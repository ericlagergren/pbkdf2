// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

#include "textflag.h"

#define K0 V16
#define K1 V17
#define K2 V18
#define K3 V19
#define K4 V20
#define K5 V21
#define K6 V22
#define K7 V23
#define K8 V24
#define K9 V25
#define K10 V26
#define K11 V27
#define K12 V28
#define K13 V29
#define K14 V30
#define K15 V31

#define HASHUPDATE(h2, h3, t0, t1) \
	SHA256H  t1.S4, h3, h2  \
	SHA256H2 t1.S4, t0, h3  \
	VMOV     h2.B16, t0.B16

#define HASH_BLOCK(h0, h1, h2, h3, m0, m1, m2, m3, t0, t1) \
	VMOV      h0.B16, h2.B16       \
	VMOV      h1.B16, h3.B16       \
	VMOV      h2.B16, t0.B16       \
	                               \
	VADD      K0.S4, m0.S4, t1.S4  \
	SHA256SU0 m1.S4, m0.S4         \
	HASHUPDATE(h2, h3, t0, t1)     \
	                               \
	VADD      K1.S4, m1.S4, t1.S4  \
	SHA256SU0 m2.S4, m1.S4         \
	SHA256SU1 m3.S4, m2.S4, m0.S4  \
	HASHUPDATE(h2, h3, t0, t1)     \
	                               \
	VADD      K2.S4, m2.S4, t1.S4  \
	SHA256SU0 m3.S4, m2.S4         \
	SHA256SU1 m0.S4, m3.S4, m1.S4  \
	HASHUPDATE(h2, h3, t0, t1)     \
	                               \
	VADD      K3.S4, m3.S4, t1.S4  \
	SHA256SU0 m0.S4, m3.S4         \
	SHA256SU1 m1.S4, m0.S4, m2.S4  \
	HASHUPDATE(h2, h3, t0, t1)     \
	                               \
	VADD      K4.S4, m0.S4, t1.S4  \
	SHA256SU0 m1.S4, m0.S4         \
	SHA256SU1 m2.S4, m1.S4, m3.S4  \
	HASHUPDATE(h2, h3, t0, t1)     \
	                               \
	VADD      K5.S4, m1.S4, t1.S4  \
	SHA256SU0 m2.S4, m1.S4         \
	SHA256SU1 m3.S4, m2.S4, m0.S4  \
	HASHUPDATE(h2, h3, t0, t1)     \
	                               \
	VADD      K6.S4, m2.S4, t1.S4  \
	SHA256SU0 m3.S4, m2.S4         \
	SHA256SU1 m0.S4, m3.S4, m1.S4  \
	HASHUPDATE(h2, h3, t0, t1)     \
	                               \
	VADD      K7.S4, m3.S4, t1.S4  \
	SHA256SU0 m0.S4, m3.S4         \
	SHA256SU1 m1.S4, m0.S4, m2.S4  \
	HASHUPDATE(h2, h3, t0, t1)     \
	                               \
	VADD      K8.S4, m0.S4, t1.S4  \
	SHA256SU0 m1.S4, m0.S4         \
	SHA256SU1 m2.S4, m1.S4, m3.S4  \
	HASHUPDATE(h2, h3, t0, t1)     \
	                               \
	VADD      K9.S4, m1.S4, t1.S4  \
	SHA256SU0 m2.S4, m1.S4         \
	SHA256SU1 m3.S4, m2.S4, m0.S4  \
	HASHUPDATE(h2, h3, t0, t1)     \
	                               \
	VADD      K10.S4, m2.S4, t1.S4 \
	SHA256SU0 m3.S4, m2.S4         \
	SHA256SU1 m0.S4, m3.S4, m1.S4  \
	HASHUPDATE(h2, h3, t0, t1)     \
	                               \
	VADD      K11.S4, m3.S4, t1.S4 \
	SHA256SU0 m0.S4, m3.S4         \
	SHA256SU1 m1.S4, m0.S4, m2.S4  \
	HASHUPDATE(h2, h3, t0, t1)     \
	                               \
	VADD      K12.S4, m0.S4, t1.S4 \
	HASHUPDATE(h2, h3, t0, t1)     \
	SHA256SU1 m2.S4, m1.S4, m3.S4  \
	                               \
	VADD      K13.S4, m1.S4, t1.S4 \
	HASHUPDATE(h2, h3, t0, t1)     \
	                               \
	VADD      K14.S4, m2.S4, t1.S4 \
	HASHUPDATE(h2, h3, t0, t1)     \
	                               \
	VADD      K15.S4, m3.S4, t1.S4 \
	HASHUPDATE(h2, h3, t0, t1)     \
	                               \
	VADD      h2.S4, h0.S4, h0.S4  \
	VADD      h3.S4, h1.S4, h1.S4

// func sha256block(h []uint32, p []byte, k []uint32)
TEXT ·sha256block(SB), NOSPLIT, $0
#define h_ptr R0
#define p_ptr R1
#define k_ptr  R2
#define plen R3

#define H0 V0
#define H1 V1
#define H2 V2
#define H3 V3

#define m1 V4
#define m2 V5
#define m3 V6
#define m4 V7

#define t0 V8
#define t1 V9

	MOVD   h_base+0(FP), h_ptr                       // Hash value first address
	MOVD   p_base+24(FP), p_ptr                      // message first address
	MOVD   k_base+48(FP), k_ptr                      // k constants first address
	MOVD   p_len+32(FP), plen                        // message length
	VLD1   (h_ptr), [H0.S4, H1.S4]                   // load h(a,b,c,d,e,f,g,h)
	VLD1.P 64(k_ptr), [K0.S4, K1.S4, K2.S4, K3.S4]
	VLD1.P 64(k_ptr), [K4.S4, K5.S4, K6.S4, K7.S4]
	VLD1.P 64(k_ptr), [K8.S4, K9.S4, K10.S4, K11.S4]
	VLD1   (k_ptr), [K12.S4, K13.S4, K14.S4, K15.S4] // load 64*4bytes K constant(K0-K63)

blockloop:

	VLD1.P 16(p_ptr), [V4.B16] // load 16bytes message
	VLD1.P 16(p_ptr), [V5.B16] // load 16bytes message
	VLD1.P 16(p_ptr), [V6.B16] // load 16bytes message
	VLD1.P 16(p_ptr), [V7.B16] // load 16bytes message

	VREV32 V4.B16, V4.B16
	VREV32 V5.B16, V5.B16
	VREV32 V6.B16, V6.B16
	VREV32 V7.B16, V7.B16

	HASH_BLOCK(H0, H1, H2, H3, m1, m2, m3, m4, t0, t1)

	SUB  $64, plen, plen // message length - 64bytes, then compare with 64bytes
	CBNZ plen, blockloop

	VST1 [H0.S4, H1.S4], (h_ptr) // store hash value H
	RET

#undef h_ptr
#undef p_ptr
#undef k_ptr
#undef plen

#undef H0
#undef H1
#undef H2
#undef H3

#undef m1
#undef m2
#undef m3
#undef m4

#undef t0
#undef t1

// func sha256inner(out *byte, sum, inner0, outer0 *[8]uint32, U *[blockSize]byte, k *[64]uint32, iter int)
TEXT ·sha256inner(SB), NOSPLIT, $0
#define sum_ptr R0
#define inner0_ptr R1
#define outer0_ptr R2
#define U_ptr R3
#define k_ptr R4
#define n R5
#define out_ptr R6
#define U_upper_ptr R7

#define H0 V0
#define H1 V1
#define H2 V2
#define H3 V3

#define U0 V4
#define U1 V5
#define U2 V6
#define U3 V7

#define t0 V8
#define t1 V9

#define U2_bak V10
#define U3_bak V11

#define sum0 V12
#define sum1 V13

	MOVD sum+8(FP), sum_ptr
	VLD1 (sum_ptr), [sum0.S4, sum1.S4]

	MOVD iter+48(FP), n
	CMP  $2, n
	BLT  done

preLoop:
	MOVD inner0+16(FP), inner0_ptr
	MOVD outer0+24(FP), outer0_ptr
	MOVD U+32(FP), U_ptr
	ADD  $32, U_ptr, U_upper_ptr

	VLD1 (U_ptr), [U0.B16, U1.B16, U2.B16, U3.B16]

	VREV32 U0.B16, U0.B16
	VREV32 U1.B16, U1.B16
	VMOV   U2.B16, U2_bak.B16
	VMOV   U3.B16, U3_bak.B16

	// Load 64*4 bytes K constant (K0-K63)
	MOVD   k+40(FP), k_ptr
	VLD1.P 64(k_ptr), [V16.S4, V17.S4, V18.S4, V19.S4]
	VLD1.P 64(k_ptr), [V20.S4, V21.S4, V22.S4, V23.S4]
	VLD1.P 64(k_ptr), [V24.S4, V25.S4, V26.S4, V27.S4]
	VLD1.P 64(k_ptr), [V28.S4, V29.S4, V30.S4, V31.S4]

	// U_n = PRF(password, U_(n-1))
loop:
	SUB $1, n

	// Inner.
	//
	//    s = H(U)
	//    U[:32] = s
	//
	VLD1 (inner0_ptr), [H0.S4, H1.S4]

	VREV32 U2_bak.B16, U2.B16
	VREV32 U3_bak.B16, U3.B16
	HASH_BLOCK(H0, H1, H2, H3, U0, U1, U2, U3, t0, t1)

	// Write hash state to U[:32].
	VMOV H0.B16, U0.B16
	VMOV H1.B16, U1.B16

	// Outer.
	//
	//    s = H(U)
	//    U[:32] = s
	//
	// Reload the top 32 bytes of U.
	VLD1   (outer0_ptr), [H0.S4, H1.S4]
	VREV32 U2_bak.B16, U2.B16
	VREV32 U3_bak.B16, U3.B16
	HASH_BLOCK(H0, H1, H2, H3, U0, U1, U2, U3, t0, t1)

	VMOV H0.B16, U0.B16
	VMOV H1.B16, U1.B16

	// sum[i] ^= oh[i]
	VEOR H0.B16, sum0.B16, sum0.B16
	VEOR H1.B16, sum1.B16, sum1.B16

	CMP $2, n
	BGE loop

postLoop:
	VREV32 U0.B16, U0.B16
	VREV32 U1.B16, U1.B16
	VST1   [U0.S4, U1.S4], (U_ptr)

	// VMOVQ $0x80000000, $0x0, U2
	// VREV32 U2_bak.B16, U2.B16
	// VMOVQ $0x0, $0x300, U3
	// VREV64 U3_bak.B16, U3.B16
	// VST1 [U2.S4, U3.S4], (U_upper_ptr)

done:
	MOVD   out+0(FP), out_ptr
	VREV32 sum0.B16, sum0.B16
	VREV32 sum1.B16, sum1.B16
	VST1   [sum0.S4, sum1.S4], (out_ptr)

	RET

DATA K<>+0(SB)/8, $0x71374491428a2f98
DATA K<>+8(SB)/8, $0xe9b5dba5b5c0fbcf
DATA K<>+16(SB)/8, $0x59f111f13956c25b
DATA K<>+24(SB)/8, $0xab1c5ed5923f82a4
DATA K<>+32(SB)/8, $0x12835b01d807aa98
DATA K<>+40(SB)/8, $0x550c7dc3243185be
DATA K<>+48(SB)/8, $0x80deb1fe72be5d74
DATA K<>+56(SB)/8, $0xc19bf1749bdc06a7
DATA K<>+64(SB)/8, $0xefbe4786e49b69c1
DATA K<>+72(SB)/8, $0x240ca1cc0fc19dc6
DATA K<>+80(SB)/8, $0x4a7484aa2de92c6f
DATA K<>+88(SB)/8, $0x76f988da5cb0a9dc
DATA K<>+96(SB)/8, $0xa831c66d983e5152
DATA K<>+104(SB)/8, $0xbf597fc7b00327c8
DATA K<>+112(SB)/8, $0xd5a79147c6e00bf3
DATA K<>+120(SB)/8, $0x1429296706ca6351
DATA K<>+128(SB)/8, $0x2e1b213827b70a85
DATA K<>+136(SB)/8, $0x53380d134d2c6dfc
DATA K<>+144(SB)/8, $0x766a0abb650a7354
DATA K<>+152(SB)/8, $0x92722c8581c2c92e
DATA K<>+160(SB)/8, $0xa81a664ba2bfe8a1
DATA K<>+168(SB)/8, $0xc76c51a3c24b8b70
DATA K<>+176(SB)/8, $0xd6990624d192e819
DATA K<>+184(SB)/8, $0x106aa070f40e3585
DATA K<>+192(SB)/8, $0x1e376c0819a4c116
DATA K<>+200(SB)/8, $0x34b0bcb52748774c
DATA K<>+208(SB)/8, $0x4ed8aa4a391c0cb3
DATA K<>+216(SB)/8, $0x682e6ff35b9cca4f
DATA K<>+224(SB)/8, $0x78a5636f748f82ee
DATA K<>+232(SB)/8, $0x8cc7020884c87814
DATA K<>+240(SB)/8, $0xa4506ceb90befffa
DATA K<>+248(SB)/8, $0xc67178f2bef9a3f7
GLOBL K<>(SB), RODATA|NOPTR, $2048
