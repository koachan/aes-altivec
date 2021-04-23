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

#ifndef AES_ROUND_H
#define AES_ROUND_H

#include <altivec.h>

#include "const.h"
#include "ecrypt-sync.h"

static inline vu8
vec_rl32(vu8 v) {
    return vec_sld(v, v, 4);
}

static inline vu8
vec_rl64(vu8 v) {
    return vec_sld(v, v, 8);
}

static inline vu8
vec_xnor(vu8 a, vu8 b) {
    vu8 c = vec_xor(a, b);
    return vec_nor(c, c);
}

/* From https://eprint.iacr.org/2009/191 */
static inline void
sub_bytes(vu8 x[8]) {
    vu8 x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3],
        x4 = x[4], x5 = x[5], x6 = x[6], x7 = x[7];
    vu8 t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14,
        t15, t16, t17, t18, t19, t20, t21, t22, t23, t24, t25, t26, t27,
        t28, t29, t30, t31, t32, t33, t34, t35, t36, t37, t38, t39, t40,
        t41, t42, t43, t44, t45, t46, t47, t48, t49, t50, t51, t52, t53,
        t54, t55, t56, t57, t58, t59, t60, t61, t62, t63, t64, t65, t66, t67;
    vu8 y1, y2, y3, y4, y5, y6, y7, y8, y9, y10, y11, y12, y13, y14, y15, y16, y17, y18, y19, y20, y21;
    vu8 z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, z10, z11, z12, z13, z14, z15, z16, z17;
    vu8 s0, s1, s2, s3, s4, s5, s6, s7;

    y14 = vec_xor(x3, x5);   y13 = vec_xor(x0, x6);   y9  = vec_xor(x0, x3);
    y8  = vec_xor(x0, x5);   t0  = vec_xor(x1, x2);   y1  = vec_xor(t0, x7);
    y4  = vec_xor(y1, x3);   y12 = vec_xor(y13, y14); y2  = vec_xor(y1, x0);
    y5  = vec_xor(y1, x6);   y3  = vec_xor(y5, y8);   t1  = vec_xor(x4, y12);
    y15 = vec_xor(t1, x5);   y20 = vec_xor(t1, x1);   y6  = vec_xor(y15, x7);
    y10 = vec_xor(y15, t0);  y11 = vec_xor(y20, y9);  y7  = vec_xor(x7, y11);
    y17 = vec_xor(y10, y11); y19 = vec_xor(y10, y8);  y16 = vec_xor(t0, y11);
    y21 = vec_xor(y13, y16); y18 = vec_xor(x0, y16);

    t2  = vec_and(y12, y15); t3  = vec_and(y3, y6);   t4  = vec_xor(t3, t2);
    t5  = vec_and(y4, x7);   t6  = vec_xor(t5, t2);   t7  = vec_and(y13, y16);
    t8  = vec_and(y5, y1);   t9  = vec_xor(t8, t7);   t10 = vec_and(y2, y7);
    t11 = vec_xor(t10, t7);  t12 = vec_and(y9, y11);  t13 = vec_and(y14, y17);
    t14 = vec_xor(t13, t12); t15 = vec_and(y8, y10);  t16 = vec_xor(t15, t12);
    t17 = vec_xor(t4, t14);  t18 = vec_xor(t6, t16);  t19 = vec_xor(t9, t14);
    t20 = vec_xor(t11, t16); t21 = vec_xor(t17, y20); t22 = vec_xor(t18, y19);
    t23 = vec_xor(t19, y21); t24 = vec_xor(t20, y18);

    t25 = vec_xor(t21, t22); t26 = vec_and(t21, t23); t27 = vec_xor(t24, t26);
    t28 = vec_and(t25, t27); t29 = vec_xor(t28, t22); t30 = vec_xor(t23, t24);
    t31 = vec_xor(t22, t26); t32 = vec_and(t31, t30); t33 = vec_xor(t32, t24);
    t34 = vec_xor(t23, t33); t35 = vec_xor(t27, t33); t36 = vec_and(t24, t35);
    t37 = vec_xor(t36, t34); t38 = vec_xor(t27, t36); t39 = vec_and(t29, t38);
    t40 = vec_xor(t25, t39);

    t41 = vec_xor(t40, t37); t42 = vec_xor(t29, t33); t43 = vec_xor(t29, t40);
    t44 = vec_xor(t33, t37); t45 = vec_xor(t42, t41); z0  = vec_and(t44, y15);
    z1  = vec_and(t37, y6);  z2  = vec_and(t33, x7);  z3  = vec_and(t43, y16);
    z4  = vec_and(t40, y1);  z5  = vec_and(t29, y7);  z6  = vec_and(t42, y11);
    z7  = vec_and(t45, y17); z8  = vec_and(t41, y10); z9  = vec_and(t44, y12);
    z10 = vec_and(t37, y3);  z11 = vec_and(t33, y4);  z12 = vec_and(t43, y13);
    z13 = vec_and(t40, y5);  z14 = vec_and(t29, y2);  z15 = vec_and(t42, y9);
    z16 = vec_and(t45, y14); z17 = vec_and(t41, y8);

    t46 = vec_xor(z15, z16); t47 = vec_xor(z10, z11);  t48 = vec_xor(z5, z13);
    t49 = vec_xor(z9, z10);  t50 = vec_xor(z2, z12);   t51 = vec_xor(z2, z5);
    t52 = vec_xor(z7, z8);   t53 = vec_xor(z0, z3);    t54 = vec_xor(z6, z7);
    t55 = vec_xor(z16, z17); t56 = vec_xor(z12, t48);  t57 = vec_xor(t50, t53);
    t58 = vec_xor(z4, t46);  t59 = vec_xor(z3, t54);   t60 = vec_xor(t46, t57);
    t61 = vec_xor(z14, t57); t62 = vec_xor(t52, t58);  t63 = vec_xor(t49, t58);
    t64 = vec_xor(z4, t59);  t65 = vec_xor(t61, t62);  t66 = vec_xor(z1, t63);
    s0  = vec_xor(t59, t63); s6  = vec_xnor(t56, t62); s7  = vec_xnor(t48, t60);
    t67 = vec_xor(t64, t65); s3  = vec_xor(t53, t66);  s4  = vec_xor(t51, t66);
    s5  = vec_xor(t47, t65); s1  = vec_xnor(t64, s3);  s2  = vec_xnor(t55, t67);

    x[0] = s0; x[1] = s1; x[2] = s2; x[3] = s3;
    x[4] = s4; x[5] = s5; x[6] = s6; x[7] = s7;
}

static inline void
shift_rows(vu8 x[8]) {
    x[0] = vec_perm(x[0], x[0], sr_const);
    x[1] = vec_perm(x[1], x[1], sr_const);
    x[2] = vec_perm(x[2], x[2], sr_const);
    x[3] = vec_perm(x[3], x[3], sr_const);
    x[4] = vec_perm(x[4], x[4], sr_const);
    x[5] = vec_perm(x[5], x[5], sr_const);
    x[6] = vec_perm(x[6], x[6], sr_const);
    x[7] = vec_perm(x[7], x[7], sr_const);
}

static inline void
mix_columns(vu8 a[8]) {
    /* The paper uses b0 to mean lsb and b7 to mean the msb, meanwhile this implementation
     * does the reverse, so we need to flip the names. */

    vu8 a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3],
        a4 = a[4], a5 = a[5], a6 = a[6], a7 = a[7];
    vu8 b0, b1, b2, b3, b4, b5, b6, b7;

    b7 = (a0 ^ vec_rl32(a0))                       ^ vec_rl32(a7) ^ vec_rl64(a7 ^ vec_rl32(a7));
    b6 = (a7 ^ vec_rl32(a7)) ^ (a0 ^ vec_rl32(a0)) ^ vec_rl32(a6) ^ vec_rl64(a6 ^ vec_rl32(a6));
    b5 = (a6 ^ vec_rl32(a6))                       ^ vec_rl32(a5) ^ vec_rl64(a5 ^ vec_rl32(a5));
    b4 = (a5 ^ vec_rl32(a5)) ^ (a0 ^ vec_rl32(a0)) ^ vec_rl32(a4) ^ vec_rl64(a4 ^ vec_rl32(a4));
    b3 = (a4 ^ vec_rl32(a4)) ^ (a0 ^ vec_rl32(a0)) ^ vec_rl32(a3) ^ vec_rl64(a3 ^ vec_rl32(a3));
    b2 = (a3 ^ vec_rl32(a3))                       ^ vec_rl32(a2) ^ vec_rl64(a2 ^ vec_rl32(a2));
    b1 = (a2 ^ vec_rl32(a2))                       ^ vec_rl32(a1) ^ vec_rl64(a1 ^ vec_rl32(a1));
    b0 = (a1 ^ vec_rl32(a1))                       ^ vec_rl32(a0) ^ vec_rl64(a0 ^ vec_rl32(a0));

    a[0] = b0; a[1] = b1; a[2] = b2; a[3] = b3;
    a[4] = b4; a[5] = b5; a[6] = b6; a[7] = b7;
}

static inline void
add_round_key(vu8 x[8], vu8 const k[8]) {
    int i;
    for (i = 0; i < 8; i++) {
        x[i] = vec_xor(x[i], k[i]);
    }
}

static inline void
aes_enc(vu8 x[8], vu8 const k[8]) {
    sub_bytes(x);
    shift_rows(x);
    mix_columns(x);
    add_round_key(x, k);
}

static inline void
aes_enc_last(vu8 x[8], vu8 const k[8]) {
    sub_bytes(x);
    shift_rows(x);
    add_round_key(x, k);
}

#endif /* AES_ROUND_H */
