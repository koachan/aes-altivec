/* AES-CTR implementation with AltiVec, based on https://eprint.iacr.org/2009/129.
 *
 * Copyright (c) 2019 Koakuma
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <altivec.h>
#include <string.h>

#include <stdio.h>

#include "aes-round.h"
#include "ecrypt-sync.h"
#include "misc.h"

/* Encrypt a single 8-block batch */
static void
aes_encrypt_sliced(ECRYPT_ctx *c, vu8 output[8], vu8 const input[8]) {
    vu8 ct[8] = {
        input[0], input[1], input[2], input[3],
        input[4], input[5], input[6], input[7]
    };

    add_round_key(ct, c->rk     );
    aes_enc(      ct, c->rk + 8 );
    aes_enc(      ct, c->rk + 16);
    aes_enc(      ct, c->rk + 24);
    aes_enc(      ct, c->rk + 32);
    aes_enc(      ct, c->rk + 40);
    aes_enc(      ct, c->rk + 48);
    aes_enc(      ct, c->rk + 56);
    aes_enc(      ct, c->rk + 64);
    aes_enc(      ct, c->rk + 72);
    aes_enc_last( ct, c->rk + 80);

    output[0] = ct[0]; output[1] = ct[1]; output[2] = ct[2]; output[3] = ct[3];
    output[4] = ct[4]; output[5] = ct[5]; output[6] = ct[6]; output[7] = ct[7];
}

static void
increment_iv(vu8 iv[8]) {
    vu32 eight = {0, 0, 0, 8};

    int i;
    for (i = 0; i < 8; i++) {
        iv[i] = (vu8) vec_add((vu32) iv[i], eight);
    }
}

static void
print_vu8(vu8 v) {
    union {
        vu8 v;
        u8  u[16];
    } uni;

    uni.v = v;
    for (int i=0; i<16; i++) {
        printf("%02x ", uni.u[i]);
    }
    printf("\n");
}

static void
test(vu8 b[8], vu8 k[8]) {
    printf("b\n");
    for (int i=0; i<8; i++) {
        print_vu8(b[i]);
    }
    printf("\n");

    slice(b, b);
    printf("b sliced\n");
    for (int i=0; i<8; i++) {
        print_vu8(b[i]);
    }
    printf("\n");

    printf("k\n");
    for (int i=0; i<8; i++) {
        print_vu8(k[i]);
    }
    printf("\n");

    slice(k, k);
    printf("k sliced\n");
    for (int i=0; i<8; i++) {
        print_vu8(k[i]);
    }
    printf("\n");

    aes_enc(b, k);
    printf("round(b) sliced\n");
    for (int i=0; i<8; i++) {
        print_vu8(b[i]);
    }
    printf("\n");

    unslice(b, b);
    printf("round(b) unsliced\n");
    for (int i=0; i<8; i++) {
        print_vu8(b[i]);
    }
    printf("\n");
}

/* static void
test_expand(u8 k[8]) {
    ECRYPT_ctx c;

    printf("k\n");
    for (int i=0; i<8; i++) {
        printf("%02x ", k[i]);
    }
    printf("\n");

    ECRYPT_keysetup(&c, k, 16, 16)
    printf("keysetup(k) sliced\n");
    for (int i=0; i<8; i++) {
        print_vu8(b[i]);
    }
    printf("\n");

    unslice(b, b);
    printf("round(b) unsliced\n");
    for (int i=0; i<8; i++) {
        print_vu8(b[i]);
    }
    printf("\n");
} */

void
ECRYPT_init(void) {
    // 00 10 20 30 40 50 60 70 80 90 a0 b0 c0 d0 e0 f0
    vu8 vb = {0x00, 0x10, 0x20, 0x30,
              0x40, 0x50, 0x60, 0x70,
              0x80, 0x90, 0xa0, 0xb0,
              0xc0, 0xd0, 0xe0, 0xf0};
    vu8 b[8] = EXPAND8(vb);

    // d6 aa 74 fd d2 af 72 fa da a6 78 f1 d6 ab 76 fe
    vu8 vk = {0xd6, 0xaa, 0x74, 0xfd,
              0xd2, 0xaf, 0x72, 0xfa,
              0xda, 0xa6, 0x78, 0xf1,
              0xd6, 0xab, 0x76, 0xfe};
    vu8 k[8] = EXPAND8(vk);

    u8  bk[16] = {0x00, 0x01, 0x02, 0x03,
                  0x04, 0x05, 0x06, 0x07,
                  0x08, 0x09, 0x0a, 0x0b,
                  0x0c, 0x0d, 0x0e, 0x0f};

    // memset(b, 0xFF, 128);

    //test(b, k);
    //test_expand(bk);
    //exit(0);

    return;
}

void
ECRYPT_keysetup(ECRYPT_ctx *c, const u8 *k, u32 keysize, u32 ivsize) {
    /* Do it traditionally, then convert to bitsliced format.
     * It's slow but at least it works. Need to improve this tho. */

    u32 rk[44];

    rk[0] = from_u8( k[0],  k[1],  k[2],  k[3]);
    rk[1] = from_u8( k[4],  k[5],  k[6],  k[7]);
    rk[2] = from_u8( k[8],  k[9], k[10], k[11]);
    rk[3] = from_u8(k[12], k[13], k[14], k[15]);

    int i;
    for (i = 4; i < 44; i+=4) {
        rk[i]     = rk[i - 4] ^ sub_word(rot_word(rk[i - 1])) ^ rcon[i / 4];
        rk[i + 1] = rk[i - 3] ^ rk[i];
        rk[i + 2] = rk[i - 2] ^ rk[i + 1];
        rk[i + 3] = rk[i - 1] ^ rk[i + 2];
    }

    vu32 vrk[11] = {
        (vu32) { rk[0],  rk[1],  rk[2],  rk[3]},
        (vu32) { rk[4],  rk[5],  rk[6],  rk[7]},
        (vu32) { rk[8],  rk[9], rk[10], rk[11]},
        (vu32) {rk[12], rk[13], rk[14], rk[15]},
        (vu32) {rk[16], rk[17], rk[18], rk[19]},
        (vu32) {rk[20], rk[21], rk[42], rk[43]},
        (vu32) {rk[24], rk[25], rk[26], rk[27]},
        (vu32) {rk[28], rk[29], rk[30], rk[31]},
        (vu32) {rk[32], rk[33], rk[34], rk[35]},
        (vu32) {rk[36], rk[37], rk[38], rk[39]},
        (vu32) {rk[40], rk[41], rk[42], rk[43]},
    };

    for (i = 0; i < 11; i++) {
        vu8 srk[8] = EXPAND8((vu8) vrk[i]);
        slice(srk, srk);
        memcpy(c->rk + (i * 8), srk, 128);
    }
}

void
ECRYPT_ivsetup(ECRYPT_ctx *c, const u8 *iv) {
    vu8 base = {iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7], iv[8], iv[9], iv[10], iv[11], iv[12], iv[13], iv[14], iv[15]};
    vu8 plus = {    0,     0,     0,     0,     0,     0,     0,     0,     0,     0,      0,      0,      0,      0,      0,      1};

    c->iv[0] = base;
    c->iv[1] = vec_add(c->iv[0], plus);
    c->iv[2] = vec_add(c->iv[1], plus);
    c->iv[3] = vec_add(c->iv[2], plus);
    c->iv[4] = vec_add(c->iv[3], plus);
    c->iv[5] = vec_add(c->iv[4], plus);
    c->iv[6] = vec_add(c->iv[5], plus);
    c->iv[7] = vec_add(c->iv[6], plus);
}

void
ECRYPT_process_bytes(int action, ECRYPT_ctx *c, const u8 *input, u8 *output, u32 len) {
    u32 blocks   = len >> 7;
    u32 residual = len & 0x7F;
    vu8 iv_sliced[8], pad_sliced[8], pad[8], tmp;
    union { vu8 v[8]; u8 u[128]; } block_last;

    if (!len) return;

    u32 i, j;
    for (i = 0; i < blocks; i++) {
        slice(iv_sliced, c->iv);
        aes_encrypt_sliced(c, pad_sliced, iv_sliced);
        unslice(pad, pad_sliced);

        for (j = 0; j < 8; j++) {
            tmp = vec_ld((128 * i) + (16 * j), input);
            tmp = vec_xor(tmp, pad[j]);
            vec_st(tmp, (128 * i) + (16 * j), output);
        }

        increment_iv(c->iv);
    }

    /* Now encrypt the last block. */
    if (!residual) return;

    slice(iv_sliced, c->iv);
    aes_encrypt_sliced(c, pad_sliced, iv_sliced);
    unslice(pad, pad_sliced);

    for (i = 0; i < 8; i++) {
        block_last.v[i] = pad[i];
    }

    u32 vec_start   = blocks * 128;
    u32 vec_count   = (len - vec_start) >> 4;
    for (i = vec_start, j = 0; j < vec_count; i += 16, j++) {
        tmp = vec_ld(i, input);
        tmp = vec_xor(tmp, block_last.v[j]);
        vec_st(tmp, i, output);
    }

    u32 bytes_start = vec_start + (vec_count << 4);
    for (i = bytes_start, j = 0; i < len; i++, j++) {
        output[i] = input[i] ^ block_last.u[j];
    }
}
