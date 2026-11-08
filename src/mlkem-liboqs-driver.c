/* liboqs ML-KEM driver (implementation A).
 *
 * Line protocol on stdin, one command per line:
 *   version                     -> VERSION <liboqs version> <alg>
 *   sizes                       -> SIZES ek <n> dk <n> ct <n> ss <n>
 *   keygen                      -> PK <hex ek> SK <hex dk>   (random, via OQS_KEM_keypair)
 *   encap <hex ek>              -> CT <hex ct> SS <hex ss>
 *   decap <hex dk> <hex ct>     -> SS <hex ss> DT <nanoseconds>
 *                                | ERR <message> (length type check failed;
 *                                  the library is not called in that case)
 *
 * Length checks: the driver validates dk/ct lengths against the FIPS 203
 * parameter set BEFORE calling OQS_KEM_decaps and reports ERR without
 * calling the library, because the liboqs C API assumes caller-validated
 * fixed-size buffers (see findings.md). No command ever prints a raw
 * shared secret to a log: the harness logs only SHA-256 digests of outputs.
 *
 * Build: gcc -O2 -I<liboqs build>/include -o mlkem-liboqs-driver \
 *        mlkem-liboqs-driver.c <liboqs build>/lib/liboqs.a
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <oqs/oqs.h>

static const char *ALG = "ML-KEM-768";

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int unhex(const char *s, uint8_t *out, size_t want) {
    if (strlen(s) != want * 2) return -1;
    for (size_t i = 0; i < want; i++) {
        int hi = hexval((unsigned char)s[2*i]);
        int lo = hexval((unsigned char)s[2*i+1]);
        if (hi < 0 || lo < 0) return -1;
    }
    for (size_t i = 0; i < want; i++)
        out[i] = (uint8_t)((hexval((unsigned char)s[2*i]) << 4) |
                           hexval((unsigned char)s[2*i+1]));
    return 0;
}

static void hexout(const uint8_t *in, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", in[i]);
}

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

int main(void) {
    OQS_KEM *kem = OQS_KEM_new(ALG);
    if (!kem) { printf("ERR kem_new failed for %s\n", ALG); fflush(stdout); return 1; }

    printf("READY liboqs=%s alg=%s ek=%zu dk=%zu ct=%zu ss=%zu\n",
           OQS_version(), ALG,
           kem->length_public_key, kem->length_secret_key,
           kem->length_ciphertext, kem->length_shared_secret);
    fflush(stdout);

    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *ct = malloc(kem->length_ciphertext);
    uint8_t *ss = malloc(kem->length_shared_secret);
    uint8_t *ct2 = malloc(kem->length_ciphertext);

    while ((len = getline(&line, &cap, stdin)) > 0) {
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) line[--len] = 0;
        if (len == 0) continue;
        char cmd[32] = {0};
        sscanf(line, "%31s", cmd);

        if (!strcmp(cmd, "version")) {
            printf("VERSION liboqs=%s alg=%s\n", OQS_version(), ALG);
        } else if (!strcmp(cmd, "sizes")) {
            printf("SIZES ek %zu dk %zu ct %zu ss %zu\n",
                   kem->length_public_key, kem->length_secret_key,
                   kem->length_ciphertext, kem->length_shared_secret);
        } else if (!strcmp(cmd, "keygen")) {
            if (OQS_KEM_keypair(kem, pk, sk) != OQS_SUCCESS) {
                printf("ERR keypair failed\n");
            } else {
                printf("PK "); hexout(pk, kem->length_public_key);
                printf(" SK "); hexout(sk, kem->length_secret_key);
                printf("\n");
            }
        } else if (!strcmp(cmd, "encap")) {
            char hexpk[4096];
            if (sscanf(line, "%*s %4095s", hexpk) != 1 ||
                unhex(hexpk, pk, kem->length_public_key) != 0) {
                printf("ERR bad encapsulation key (want %zu bytes hex)\n",
                       kem->length_public_key);
            } else if (OQS_KEM_encaps(kem, ct, ss, pk) != OQS_SUCCESS) {
                printf("ERR encaps failed\n");
            } else {
                printf("CT "); hexout(ct, kem->length_ciphertext);
                printf(" SS "); hexout(ss, kem->length_shared_secret);
                printf("\n");
            }
        } else if (!strcmp(cmd, "decap")) {
            /* Split the line manually so an empty ciphertext argument is
             * still seen (as a 0-byte input) instead of a usage error. */
            char *rest = line + strlen(cmd);
            while (*rest == ' ' || *rest == '\t') rest++;
            char *sp = strchr(rest, ' ');
            char hexsk[8192] = {0}, hexct[8192] = {0};
            if (!sp) {
                printf("ERR usage: decap <hex dk> <hex ct>\n");
            } else {
                size_t nsk = (size_t)(sp - rest);
                if (nsk >= sizeof(hexsk)) nsk = sizeof(hexsk) - 1;
                memcpy(hexsk, rest, nsk);
                const char *ctarg = sp + 1;
                while (*ctarg == ' ' || *ctarg == '\t') ctarg++;
                strncpy(hexct, ctarg, sizeof(hexct) - 1);
                /* strip any trailing whitespace from hexct */
                size_t nct = strlen(hexct);
                while (nct > 0 && (hexct[nct-1] == ' ' || hexct[nct-1] == '\t'))
                    hexct[--nct] = 0;
                if (strlen(hexsk) != kem->length_secret_key * 2) {
                /* FIPS 203 Sec. 7.3 decapsulation-key type check, enforced here
                 * because OQS_KEM_decaps takes fixed-size buffers and does not
                 * itself receive (or check) a length. */
                printf("ERR decapsulation key type check failed: expected %zu bytes, got %zu\n",
                       kem->length_secret_key, strlen(hexsk) / 2);
            } else if (strlen(hexct) != kem->length_ciphertext * 2) {
                printf("ERR ciphertext type check failed: expected %zu bytes, got %zu\n",
                       kem->length_ciphertext, strlen(hexct) / 2);
            } else if (unhex(hexsk, sk, kem->length_secret_key) != 0 ||
                       unhex(hexct, ct, kem->length_ciphertext) != 0) {
                printf("ERR bad hex input\n");
            } else {
                /* Note: the FIPS 203 Sec. 7.3 hash check
                 * (H(dk[384k:768k+32]) == dk[768k+32:768k+64]) is performed by
                 * the Python harness (hashlib.sha3_256) and recorded there;
                 * the driver only enforces the two length type checks, which
                 * the liboqs C API cannot express because it takes
                 * fixed-size buffers. */
                uint64_t t0 = now_ns();
                OQS_STATUS rc = OQS_KEM_decaps(kem, ss, ct, sk);
                uint64_t t1 = now_ns();
                if (rc != OQS_SUCCESS) {
                    printf("ERR decaps returned %d\n", (int)rc);
                } else {
                    printf("SS "); hexout(ss, kem->length_shared_secret);
                    printf(" DT %llu\n", (unsigned long long)(t1 - t0));
                }
            }
            }
        } else {
            printf("ERR unknown command\n");
        }
        fflush(stdout);
    }
    free(line); free(pk); free(sk); free(ct); free(ss); free(ct2);
    OQS_KEM_free(kem);
    return 0;
}
