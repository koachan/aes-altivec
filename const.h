#ifndef CONST_H
#define CONST_H

#include <altivec.h>

#include "ecrypt-sync.h"

/* IV setup constant */
static const vu8 one = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

/* IV increment constants, with a byte swap since
 * we need to increment it with a little-endian addition */
static const vu32 eight = {8, 0, 0, 0};
static const vu8 swap   = {3, 2, 1, 0, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

/* Byte shuffling for slice/unslice */
static const vu8 slice_rearrange = {
    0, 4,  8, 12,
    1, 5,  9, 13,
    2, 6, 10, 14,
    3, 7, 11, 15
};

/* Byte shuffling for shift_rows */
static const vu8 sr_const = {
     0,  1,  2,  3,
     5,  6,  7,  4,
    10, 11,  8,  9,
    15, 12, 13, 14,
};

static const u32 rcon[11] = {
    0xffffffff, /* undefined */
    0x01000000,
    0x02000000,
    0x04000000,
    0x08000000,
    0x10000000,
    0x20000000,
    0x40000000,
    0x80000000,
    0x1B000000,
    0x36000000,
};

#endif /* CONST_H */
