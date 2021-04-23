An AES-CTR implementation using AltiVec
---

### What is this?

This is a port of the AES-CTR part of Käsper & Schwabe's
[Faster and Timing-Attack Resistant AES-GCM](https://eprint.iacr.org/2009/129)
to PowerPC processors.

The code is written to be compatible with the
[eSTREAM testing framework](https://www.ecrypt.eu.org/stream/perf/),
just drop it into the submissions directory and run the benchmarks to try it out.

Of course, the usual disclaimer applies: This is experimental and unaudited code,
use it at your own risk.

### How fast is it?

Below is the comparison between my implementation and the benchmark
implementation included in the testing framework:

| Implementation                                  | Long Stream | 40 bytes  | 576 bytes | 1500 bytes | Imix      | Agility   | Key setup      | IV setup     |
|-------------------------------------------------|-------------|-----------|-----------|------------|-----------|-----------|----------------|--------------|
| bernstein/big-1/1                               | 24.74 cpb   | 38.74 cpb | 25.25 cpb | 25.01 cpb  | 26.09 cpb | 28.11 cpb | 233.92 cycles  | 50.06 cycles |
| aes-altivec                                     | 16.30 cpb   | 60.03 cpb | 18.69 cpb | 16.93 cpb  | 20.88 cpb | 35.78 cpb | 5152.13 cycles | 91.26 cycles |
| aes-altivec (with lookup table-based key setup) | 16.30 cpb   | 59.98 cpb | 18.68 cpb | 16.92 cpb  | 20.87 cpb | 35.81 cpb | 2033.00 cycles | 91.06 cycles |

All tests were done on a 1.4 GHz Mac mini running OpenBSD 6.8 with
the default Clang 10.0.1 compiler.

Some observations of the result:
- It's already faster than the benchmark implementation in longer (576+ bytes)
  encryption sessions.
- Encryption on 40 byte packets are slow since my implementation operates on
  128 byte blocks, so there's a lot of wasted computation.
- In bitslicing mode, key setup is much slower, this happens because
  the `sub_bytes` function only accepts bitsliced input so there's a lot
  of possibly unnecessary slicing/unslicing going on. \
  K&S proposed to solve this by using an normal key setup function
  that uses lookup tables.
- IV setup is slower since this needs to set up eight IVs at once.

### Things to do

- Optimize it more.
  - In particular, the main loop (`ECRYPT_process_bytes`), slicing process, and
    key/IV setup could probably be done in a much better way.
- Add 192 and 256 bit key variants.
