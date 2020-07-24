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

| Implementation    | Long Stream | 40 bytes  | 576 bytes | 1500 bytes | Imix      | Agility   | Key setup      | IV setup     |
|-------------------|-------------|-----------|-----------|------------|-----------|-----------|----------------|--------------|
| bernstein/big-1/1 | 21.86 cpb   | 32.90 cpb | 22.23 cpb | 22.08 cpb  | 22.90 cpb | 25.14 cpb | 200.80 cycles  | 17.10 cycles |
| aes-altivec       | 16.01 cpb   | 56.00 cpb | 18.17 cpb | 16.56 cpb  | 20.17 cpb | 35.24 cpb | 4978.17 cycles | 58.03 cycles |

All tests were done on a 1.4 Ghz Mac mini running OpenBSD 6.7 with
the default Clang 8.0.1 compiler.

Some observations of the result:
- This is already faster than the benchmark implementation in long (576+ bytes)
  encryption sessions.
- Encryption on 40 byte packets are slow since my implementation operates on
  128 byte blocks, so there's a lot of wasted things there.
- Key setup is much slower than benchmark, this happens because the `sub_bytes`
  function only accepts bitsliced input so there's a lot of possibly unnecessary
  slicing/unslicing going on. \
  K&S solves this by giving an alternate key setup function that uses normal
  lookup table-based implementation.
- IV setup is slower since this needs to set up eight IVs at once.

### Things to do

- Optimize it more.
  - In particular, the main loop (`ECRYPT_process_bytes`), slicing process, and
    key/IV setup could probably be done in a much better way.
- Add 192 and 256 bit key variants.
