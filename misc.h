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

#ifndef MISC_H
#define MISC_H

#include <altivec.h>

#include "aes-round.h"
#include "const.h"
#include "ecrypt-sync.h"

#define EXPAND8(x) {(x), (x), (x), (x), (x), (x), (x), (x)}

static inline void
slice(vu8 output[8], vu8 const input[8]) {
    /* Very ugly, need to find a way to turn this into a clean loop. */

	vu8 v0 = input[0], v1 = input[1], v2 = input[2], v3 = input[3],
        v4 = input[4], v5 = input[5], v6 = input[6], v7 = input[7];

	vu8 m = vec_splats((u8) 0x80);

	vu8 t0, t1, t2, t3, t4, t5, t6, t7;

    t0 = vec_and(v0, m);
    t0 = vec_or(t0, vec_sr(vec_and(v1, m), vec_splats((u8) 1)));
    t0 = vec_or(t0, vec_sr(vec_and(v2, m), vec_splats((u8) 2)));
    t0 = vec_or(t0, vec_sr(vec_and(v3, m), vec_splats((u8) 3)));
    t0 = vec_or(t0, vec_sr(vec_and(v4, m), vec_splats((u8) 4)));
    t0 = vec_or(t0, vec_sr(vec_and(v5, m), vec_splats((u8) 5)));
    t0 = vec_or(t0, vec_sr(vec_and(v6, m), vec_splats((u8) 6)));
    t0 = vec_or(t0, vec_sr(vec_and(v7, m), vec_splats((u8) 7)));
    t0 = vec_perm(t0, t0, slice_rearrange);
    m = vec_sr(m, vec_splats((u8) 1));

    t1 = vec_sl(vec_and(v0, m), vec_splats((u8) 1));
    t1 = vec_or(t1, vec_and(v1, m));
    t1 = vec_or(t1, vec_sr(vec_and(v2, m), vec_splats((u8) 1)));
    t1 = vec_or(t1, vec_sr(vec_and(v3, m), vec_splats((u8) 2)));
    t1 = vec_or(t1, vec_sr(vec_and(v4, m), vec_splats((u8) 3)));
    t1 = vec_or(t1, vec_sr(vec_and(v5, m), vec_splats((u8) 4)));
    t1 = vec_or(t1, vec_sr(vec_and(v6, m), vec_splats((u8) 5)));
    t1 = vec_or(t1, vec_sr(vec_and(v7, m), vec_splats((u8) 6)));
    t1 = vec_perm(t1, t1, slice_rearrange);
    m = vec_sr(m, vec_splats((u8) 1));

    t2 = vec_sl(vec_and(v0, m), vec_splats((u8) 2));
    t2 = vec_or(t2, vec_sl(vec_and(v1, m), vec_splats((u8) 1)));
    t2 = vec_or(t2, vec_and(v2, m));
    t2 = vec_or(t2, vec_sr(vec_and(v3, m), vec_splats((u8) 1)));
    t2 = vec_or(t2, vec_sr(vec_and(v4, m), vec_splats((u8) 2)));
    t2 = vec_or(t2, vec_sr(vec_and(v5, m), vec_splats((u8) 3)));
    t2 = vec_or(t2, vec_sr(vec_and(v6, m), vec_splats((u8) 4)));
    t2 = vec_or(t2, vec_sr(vec_and(v7, m), vec_splats((u8) 5)));
    t2 = vec_perm(t2, t2, slice_rearrange);
    m = vec_sr(m, vec_splats((u8) 1));

    t3 = vec_sl(vec_and(v0, m), vec_splats((u8) 3));
    t3 = vec_or(t3, vec_sl(vec_and(v1, m), vec_splats((u8) 2)));
    t3 = vec_or(t3, vec_sl(vec_and(v2, m), vec_splats((u8) 1)));
    t3 = vec_or(t3, vec_and(v3, m));
    t3 = vec_or(t3, vec_sr(vec_and(v4, m), vec_splats((u8) 1)));
    t3 = vec_or(t3, vec_sr(vec_and(v5, m), vec_splats((u8) 2)));
    t3 = vec_or(t3, vec_sr(vec_and(v6, m), vec_splats((u8) 3)));
    t3 = vec_or(t3, vec_sr(vec_and(v7, m), vec_splats((u8) 4)));
    t3 = vec_perm(t3, t3, slice_rearrange);
    m = vec_sr(m, vec_splats((u8) 1));

    t4 = vec_sl(vec_and(v0, m), vec_splats((u8) 4));
    t4 = vec_or(t4, vec_sl(vec_and(v1, m), vec_splats((u8) 3)));
    t4 = vec_or(t4, vec_sl(vec_and(v2, m), vec_splats((u8) 2)));
    t4 = vec_or(t4, vec_sl(vec_and(v3, m), vec_splats((u8) 1)));
    t4 = vec_or(t4, vec_and(v4, m));
    t4 = vec_or(t4, vec_sr(vec_and(v5, m), vec_splats((u8) 1)));
    t4 = vec_or(t4, vec_sr(vec_and(v6, m), vec_splats((u8) 2)));
    t4 = vec_or(t4, vec_sr(vec_and(v7, m), vec_splats((u8) 3)));
    t4 = vec_perm(t4, t4, slice_rearrange);
    m = vec_sr(m, vec_splats((u8) 1));

    t5 = vec_sl(vec_and(v0, m), vec_splats((u8) 5));
    t5 = vec_or(t5, vec_sl(vec_and(v1, m), vec_splats((u8) 4)));
    t5 = vec_or(t5, vec_sl(vec_and(v2, m), vec_splats((u8) 3)));
    t5 = vec_or(t5, vec_sl(vec_and(v3, m), vec_splats((u8) 2)));
    t5 = vec_or(t5, vec_sl(vec_and(v4, m), vec_splats((u8) 1)));
    t5 = vec_or(t5, vec_and(v5, m));
    t5 = vec_or(t5, vec_sr(vec_and(v6, m), vec_splats((u8) 1)));
    t5 = vec_or(t5, vec_sr(vec_and(v7, m), vec_splats((u8) 2)));
    t5 = vec_perm(t5, t5, slice_rearrange);
    m = vec_sr(m, vec_splats((u8) 1));

    t6 = vec_sl(vec_and(v0, m), vec_splats((u8) 6));
    t6 = vec_or(t6, vec_sl(vec_and(v1, m), vec_splats((u8) 5)));
    t6 = vec_or(t6, vec_sl(vec_and(v2, m), vec_splats((u8) 4)));
    t6 = vec_or(t6, vec_sl(vec_and(v3, m), vec_splats((u8) 3)));
    t6 = vec_or(t6, vec_sl(vec_and(v4, m), vec_splats((u8) 2)));
    t6 = vec_or(t6, vec_sl(vec_and(v5, m), vec_splats((u8) 1)));
    t6 = vec_or(t6, vec_and(v6, m));
    t6 = vec_or(t6, vec_sr(vec_and(v7, m), vec_splats((u8) 1)));
    t6 = vec_perm(t6, t6, slice_rearrange);
    m = vec_sr(m, vec_splats((u8) 1));

    t7 = vec_sl(vec_and(v0, m), vec_splats((u8) 7));
    t7 = vec_or(t7, vec_sl(vec_and(v1, m), vec_splats((u8) 6)));
    t7 = vec_or(t7, vec_sl(vec_and(v2, m), vec_splats((u8) 5)));
    t7 = vec_or(t7, vec_sl(vec_and(v3, m), vec_splats((u8) 4)));
    t7 = vec_or(t7, vec_sl(vec_and(v4, m), vec_splats((u8) 3)));
    t7 = vec_or(t7, vec_sl(vec_and(v5, m), vec_splats((u8) 2)));
    t7 = vec_or(t7, vec_sl(vec_and(v6, m), vec_splats((u8) 1)));
    t7 = vec_or(t7, vec_and(v7, m));
    t7 = vec_perm(t7, t7, slice_rearrange);

    output[0] = t0; output[1] = t1; output[2] = t2; output[3] = t3;
    output[4] = t4; output[5] = t5; output[6] = t6; output[7] = t7;
}

static inline void
unslice(vu8 output[8], vu8 const input[8]) {
    slice(output, input);
}

static inline u32
sub_word(u32 w) {
    vu32 v = vec_splats(w);
    vu8 x[8] = EXPAND8((vu8) v);
    slice(x, x);
    sub_bytes(x);
    unslice(x, x);
    return vec_extract((vu32) x[0], 0);
}

#endif /* MISC_H */
