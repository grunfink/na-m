/* na - A tool for assymmetric encryption of files by grunfink - public domain */

#include "na.h"

#include "monocypher.h"

#include <string.h>
#include <stdlib.h>

#define VERSION "1.04"


static int random_fill(uint8_t *buf, int z)
{
    int ret = 0;
    FILE *f;

    if ((f = fopen("/dev/random", "rb")) != NULL) {
        fread(buf, z, 1, f);
        fclose(f);
    }
    else {
        ret = 2;
        fprintf(stderr, "ERROR: cannot read from random device\n");
    }

    return ret;
}


static int read_key_file(uint8_t *p, int size, char *fn)
/* reads a one-line hexadecimal text file into buffer */
{
    int ret = 0;
    FILE *f;

    if ((f = fopen(fn, "r")) != NULL) {
        int n, c;

        for (n = 0; n < size; n++) {
            fscanf(f, "%02x", &c);
            p[n] = c;
        }

        fclose(f);
    }
    else {
        ret = 2;
        fprintf(stderr, "ERROR: cannot read key file\n");
    }

    return ret;
}


static int write_key_file(uint8_t *p, int size, char *fn)
/* writes a buffer as a one-line hexadecimal text file */
{
    int ret = 0;
    FILE *f; 

    if ((f = fopen(fn, "w")) != NULL) {
        int n;

        for (n = 0; n < size; n++)
            fprintf(f, "%02x", p[n]);
        fprintf(f, "\n");

        fclose(f);
    }
    else {
        ret = 3;
        fprintf(stderr, "ERROR: cannot write key file\n");
    }

    return ret;
}


int na_generate_keys(char *pk_fn, char *sk_fn)
{
    uint8_t sk[32];     /* secret key */
    uint8_t pk[32];     /* public key */

    random_fill(sk, sizeof(sk));
    crypto_key_exchange_public_key(pk, sk);

    /* write the secret and public keys */
    return write_key_file(sk, sizeof(sk), sk_fn) +
           write_key_file(pk, sizeof(pk), pk_fn);
}


int na_rebuild_public_key(char *pk_fn, char *sk_fn)
{
    int ret = 0;
    uint8_t sk[32];     /* secret key */
    uint8_t pk[32];     /* public key */

    /* read the secret key */
    if ((ret = read_key_file(sk, sizeof(sk), sk_fn)) == 0) {
        /* recompute public key */
        crypto_key_exchange_public_key(pk, sk);

        /* write it */
        ret = write_key_file(pk, sizeof(pk), pk_fn);
    }

    return ret;
}


static void hash_key(uint8_t *salt, uint8_t *h_key, uint8_t *key, int size)
{
    uint8_t *work_area;

    work_area = (uint8_t *)malloc(100000 * 1024);

    crypto_argon2i(h_key, 32, work_area, 100000, 3, key, size, salt, 16);

    free(work_area);
}


#define BLOCK_SIZE 1024 * 1024

int na_encrypt(FILE *i, FILE *o, char *pk_fn)
{
    int ret = 0;
    uint8_t pk[32];     /* public key */
    uint8_t tmp_pk[32]; /* temporary public key */
    uint8_t tmp_sk[32]; /* temporary secret key */
    uint8_t key[32];    /* stream key */
    uint8_t cy_key[32]; /* encrypted stream key */
    uint8_t ss[32];     /* shared secret */
    uint8_t h_ss[32];   /* hashed shared secret (key to stream key) */
    uint8_t nonce[24];
    uint8_t mac[16];
    uint8_t salt[16];
    uint8_t *bl;
    int z;

    bl = (uint8_t *)malloc(BLOCK_SIZE);

    if ((ret = read_key_file(pk, sizeof(pk), pk_fn)) != 0)
        goto end;

    /* create a disposable set of assymmetric keys:
       the public one shall be inside the encrypted stream
       aside with the encrypted symmetric key */
    random_fill(tmp_sk, sizeof(tmp_sk));
    crypto_key_exchange_public_key(tmp_pk, tmp_sk);

    /* create a nonce for the encryption of the stream key */
    random_fill(nonce, sizeof(nonce));

    /* create the stream key */
    random_fill(key, sizeof(key));

    /* pick the shared secret */
    crypto_key_exchange(ss, tmp_sk, pk);

    /* create a salt to hash the shared secret */
    random_fill(salt, sizeof(salt));

    /* hash the shared secret to use it to encrypt the stream key */
    hash_key(salt, h_ss, ss, sizeof(ss));
    crypto_wipe(ss, sizeof(ss));

    /* encrypt the stream key using the hashed shared secret as key */
    crypto_lock(mac, cy_key, h_ss, nonce, key, sizeof(key));

    /** start of output **/

    /* write the signature */
    bl[0] = 'n';
    bl[1] = 'a';
    bl[2] = 0x00;
    bl[3] = 0x02;
    fwrite(bl, 4, 1, o);

    /* write the disposable pk */
    fwrite(tmp_pk, sizeof(tmp_pk), 1, o);

    /* write the nonce */
    fwrite(nonce, sizeof(nonce), 1, o);

    /* write the mac */
    fwrite(mac, sizeof(mac), 1, o);

    /* write the salt */
    fwrite(salt, sizeof(salt), 1, o);

    /* write the encrypted stream key */
    fwrite(cy_key, sizeof(cy_key), 1, o);

    /* read by blocks */
    while ((z = fread(bl, 1, BLOCK_SIZE, i)) > 0) {
        random_fill(nonce, sizeof(nonce));
        crypto_lock(mac, bl, key, nonce, bl, z);

        if (fwrite(nonce, sizeof(nonce), 1, o) != 1) {
            ret = 3;
            fprintf(stderr, "ERROR: write error (nonce)\n");
            break;
        }

        if (fwrite(mac, sizeof(mac), 1, o) != 1) {
            ret = 3;
            fprintf(stderr, "ERROR: write error (mac)\n");
            break;
        }

        if (fwrite(bl, 1, z, o) != z) {
            ret = 3;
            fprintf(stderr, "ERROR: write error (block)\n");
            break;
        }
    }
 
end:
    free(bl);

    return ret;
}


int na_decrypt(FILE *i, FILE *o, char *sk_fn)
{
    int ret = 0;
    uint8_t tmp_pk[32]; /* temporary public key */
    uint8_t sk[32];     /* secret key */
    uint8_t cy_key[32]; /* encrypted stream key */
    uint8_t key[32];    /* stream key */
    uint8_t ss[32];     /* the shared secret */
    uint8_t h_ss[32];   /* hashed shared secret (key to stream key) */
    uint8_t nonce[24];
    uint8_t mac[16];
    uint8_t salt[16];
    uint8_t *bl;
    int z;

    bl = (uint8_t *)malloc(BLOCK_SIZE);

    if ((ret = read_key_file(sk, sizeof(sk), sk_fn)) != 0)
        goto end;

    /* read 4 bytes */
    if (fread(bl, 4, 1, i) != 1) {
        ret = 2;
        fprintf(stderr, "ERROR: unexpected EOF reading signature\n");
        goto end;
    }

    /* valid signature? */
    if (bl[0] == 'n' && bl[1] == 'a' && bl[2] == 0x00) {
        if (bl[3] != 0x02) {
            ret = 4;
            fprintf(stderr, "ERROR: signature for another format (0x%02X)\n", bl[3]);
            goto end;
        }
    }
    else {
        ret = 4;
        fprintf(stderr, "ERROR: bad signature\n");
        goto end;
    }

    /* read the public key + the nonce + the mac + encrypted symmetric key */
    if (fread(tmp_pk, sizeof(tmp_pk), 1, i) != 1 ||
        fread(nonce,  sizeof(nonce),  1, i) != 1 ||
        fread(mac,    sizeof(mac),    1, i) != 1 ||
        fread(salt,   sizeof(salt),   1, i) != 1 ||
        fread(cy_key, sizeof(cy_key), 1, i) != 1) {
        ret = 2;
        fprintf(stderr, "ERROR: unexpected EOF reading header\n");
        goto end;
    }

    /* pick the shared secret */
    crypto_key_exchange(ss, sk, tmp_pk);

    /* hash the shared secret to use it to decrypt the stream key */
    hash_key(salt, h_ss, ss, sizeof(ss));
    crypto_wipe(ss, sizeof(ss));
    crypto_wipe(sk, sizeof(sk));

    /* decrypt the stream key using the hashed shared secret as key */
    if (crypto_unlock(key, h_ss, nonce, mac, cy_key, sizeof(cy_key))) {
        ret = 4;
        fprintf(stderr, "ERROR: corrupted header\n");
        goto end;
    }

    /* read by blocks */
    while (fread(nonce, sizeof(nonce), 1, i) == 1 &&
           fread(mac, sizeof(mac), 1, i) == 1 &&
           (z = fread(bl, 1, BLOCK_SIZE, i)) > 0) {

        if (crypto_unlock(bl, key, nonce, mac, bl, z)) {
            ret = 4;
            fprintf(stderr, "ERROR: corrupted stream\n");
            goto end;
        }

        if (fwrite(bl, 1, z, o) != z) {
            ret = 3;
            fprintf(stderr, "ERROR: write error\n");
            break;
        }
    }

end:
    free(bl);

    return ret;
}


int na_init(void)
{
    return 0;
}


char *na_info(void)
{
    return "monocypher (Curve25519, Argon2i, Chacha20+Poly1305) format=0x02";
}


char *na_version(void)
{
    return VERSION;
}

