/* AES-CTR implementation with AltiVec, based on https://eprint.iacr.org/2009/129.
 *
 * Copyright (c) 2019 Koakuma <koachan@protonmail.com>
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

#ifndef AES_KEYSETUP_H
#define AES_KEYSETUP_H

/* Set this to 0 to use the bitslice-based key expansion implementation */
#define USE_LOOKUP_TABLE 1

#include <altivec.h>

#include "aes-round.h"
#include "const.h"
#include "ecrypt-sync.h"
#include "misc.h"

/* Start bitsliced implementation */
static inline u32
sub_word_bitsliced(u32 w) {
    vu32 v = vec_splats(w);
    vu8 x[8] = EXPAND8((vu8) v);
    slice(x, x);
    sub_bytes(x);
    unslice(x, x);
    return vec_extract((vu32) x[0], 0);
}

static inline void
aes_key_expand_sliced(u32 rk[44], u8 const k[16]) {
    rk[0] = U8TO32_BIG(k);
    rk[1] = U8TO32_BIG(k + 4);
    rk[2] = U8TO32_BIG(k + 8);
    rk[3] = U8TO32_BIG(k + 12);

    int i;
    for (i = 4; i < 44; i+=4) {
        rk[i]     = rk[i - 4] ^ sub_word_bitsliced(ROTL32(rk[i - 1], 8)) ^ rcon[i / 4];
        rk[i + 1] = rk[i - 3] ^ rk[i];
        rk[i + 2] = rk[i - 2] ^ rk[i + 1];
        rk[i + 3] = rk[i - 1] ^ rk[i + 2];
    }
}
/* End bitsliced implementation */

/* Start lookup-table-based implementation
 * This is still a naive implementation, could be improved more. */
static inline u32
sub_word_lookup(u32 w) {
    union {
        u32 w;
        u8  b[4];
    } in, out;

    in.w = w;
    out.b[0] = sbox[in.b[0]];
    out.b[1] = sbox[in.b[1]];
    out.b[2] = sbox[in.b[2]];
    out.b[3] = sbox[in.b[3]];
    return out.w;
}

static inline void
aes_key_expand_lookup(u32 rk[44], u8 const k[16]) {
    rk[0] = U8TO32_BIG(k);
    rk[1] = U8TO32_BIG(k + 4);
    rk[2] = U8TO32_BIG(k + 8);
    rk[3] = U8TO32_BIG(k + 12);

    int i;
    for (i = 4; i < 44; i+=4) {
        rk[i]     = rk[i - 4] ^ sub_word_lookup(ROTL32(rk[i - 1], 8)) ^ rcon[i / 4];
        rk[i + 1] = rk[i - 3] ^ rk[i];
        rk[i + 2] = rk[i - 2] ^ rk[i + 1];
        rk[i + 3] = rk[i - 1] ^ rk[i + 2];
    }
}

/* End lookup-table-based implementation */

/* This is AES-128 only for now */
static inline void
aes_key_expand(u32 rk[44], u8 const k[16]) {
#   if USE_LOOKUP_TABLE == 1
        aes_key_expand_lookup(rk, k);
#   else
        aes_key_expand_sliced(rk, k);
#   endif
}

#endif /* AES_KEYSETUP_H */
