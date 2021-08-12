/*
 * Copyright (c) 2003, 2021, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2014, 2021, Red Hat Inc. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 *
 */

#include "precompiled.hpp"
#include "asm/assembler.hpp"
#include "asm/assembler.inline.hpp"
#include "runtime/stubRoutines.hpp"
#include "macroAssembler_aarch64.hpp"

void MacroAssembler::aesecb_decrypt(Register from, Register to, Register key, Register keylen) {
  Label L_doLast;

  ld1(v0, T16B, from); // get 16 bytes of input

  ld1(v5, T16B, post(key, 16));
  rev32(v5, T16B, v5);

  ld1(v1, v2, v3, v4, T16B, post(key, 64));
  rev32(v1, T16B, v1);
  rev32(v2, T16B, v2);
  rev32(v3, T16B, v3);
  rev32(v4, T16B, v4);
  aesd(v0, v1);
  aesimc(v0, v0);
  aesd(v0, v2);
  aesimc(v0, v0);
  aesd(v0, v3);
  aesimc(v0, v0);
  aesd(v0, v4);
  aesimc(v0, v0);

  ld1(v1, v2, v3, v4, T16B, post(key, 64));
  rev32(v1, T16B, v1);
  rev32(v2, T16B, v2);
  rev32(v3, T16B, v3);
  rev32(v4, T16B, v4);
  aesd(v0, v1);
  aesimc(v0, v0);
  aesd(v0, v2);
  aesimc(v0, v0);
  aesd(v0, v3);
  aesimc(v0, v0);
  aesd(v0, v4);
  aesimc(v0, v0);

  ld1(v1, v2, T16B, post(key, 32));
  rev32(v1, T16B, v1);
  rev32(v2, T16B, v2);

  cmpw(keylen, 44);
  br(Assembler::EQ, L_doLast);

  aesd(v0, v1);
  aesimc(v0, v0);
  aesd(v0, v2);
  aesimc(v0, v0);

  ld1(v1, v2, T16B, post(key, 32));
  rev32(v1, T16B, v1);
  rev32(v2, T16B, v2);

  cmpw(keylen, 52);
  br(Assembler::EQ, L_doLast);

  aesd(v0, v1);
  aesimc(v0, v0);
  aesd(v0, v2);
  aesimc(v0, v0);

  ld1(v1, v2, T16B, post(key, 32));
  rev32(v1, T16B, v1);
  rev32(v2, T16B, v2);

  bind(L_doLast);

  aesd(v0, v1);
  aesimc(v0, v0);
  aesd(v0, v2);

  eor(v0, T16B, v0, v5);

  st1(v0, T16B, to);

  // Preserve the address of the start of the key
  sub(key, key, keylen, LSL, exact_log2(sizeof (jint)));
}

void MacroAssembler::aesecb_encrypt(Register from, Register to, Register key, Register keylen) {
  Label L_doLast;

  ld1(v0, T16B, from); // get 16 bytes of input

  ld1(v1, v2, v3, v4, T16B, post(key, 64));
  rev32(v1, T16B, v1);
  rev32(v2, T16B, v2);
  rev32(v3, T16B, v3);
  rev32(v4, T16B, v4);
  aese(v0, v1);
  aesmc(v0, v0);
  aese(v0, v2);
  aesmc(v0, v0);
  aese(v0, v3);
  aesmc(v0, v0);
  aese(v0, v4);
  aesmc(v0, v0);

  ld1(v1, v2, v3, v4, T16B, post(key, 64));
  rev32(v1, T16B, v1);
  rev32(v2, T16B, v2);
  rev32(v3, T16B, v3);
  rev32(v4, T16B, v4);
  aese(v0, v1);
  aesmc(v0, v0);
  aese(v0, v2);
  aesmc(v0, v0);
  aese(v0, v3);
  aesmc(v0, v0);
  aese(v0, v4);
  aesmc(v0, v0);

  ld1(v1, v2, T16B, post(key, 32));
  rev32(v1, T16B, v1);
  rev32(v2, T16B, v2);

  cmpw(keylen, 44);
  br(Assembler::EQ, L_doLast);

  aese(v0, v1);
  aesmc(v0, v0);
  aese(v0, v2);
  aesmc(v0, v0);

  ld1(v1, v2, T16B, post(key, 32));
  rev32(v1, T16B, v1);
  rev32(v2, T16B, v2);

  cmpw(keylen, 52);
  br(Assembler::EQ, L_doLast);

  aese(v0, v1);
  aesmc(v0, v0);
  aese(v0, v2);
  aesmc(v0, v0);

  ld1(v1, v2, T16B, post(key, 32));
  rev32(v1, T16B, v1);
  rev32(v2, T16B, v2);

  bind(L_doLast);

  aese(v0, v1);
  aesmc(v0, v0);
  aese(v0, v2);

  ld1(v1, T16B, post(key, 16));
  rev32(v1, T16B, v1);
  eor(v0, T16B, v0, v1);

  st1(v0, T16B, to);

  // Preserve the address of the start of the key
  sub(key, key, keylen, LSL, exact_log2(sizeof (jint)));
}

void MacroAssembler::ghash_multiply(FloatRegister result_lo, FloatRegister result_hi,
                    FloatRegister a, FloatRegister b, FloatRegister a1_xor_a0,
                    FloatRegister tmp1, FloatRegister tmp2, FloatRegister tmp3, FloatRegister tmp4) {
    // Karatsuba multiplication performs a 128*128 -> 256-bit
    // multiplication in three 128-bit multiplications and a few
    // additions.
    //
    // (C1:C0) = A1*B1, (D1:D0) = A0*B0, (E1:E0) = (A0+A1)(B0+B1)
    // (A1:A0)(B1:B0) = C1:(C0+C1+D1+E1):(D1+C0+D0+E0):D0
    //
    // Inputs:
    //
    // A0 in a.d[0]     (subkey)
    // A1 in a.d[1]
    // (A1+A0) in a1_xor_a0.d[0]
    //
    // B0 in b.d[0]     (state)
    // B1 in b.d[1]

    ext(tmp1, T16B, b, b, 0x08);
    pmull2(result_hi, T1Q, b, a, T2D);  // A1*B1
    eor(tmp1, T16B, tmp1, b);            // (B1+B0)
    pmull(result_lo,  T1Q, b, a, T1D);  // A0*B0
    pmull(tmp2, T1Q, tmp1, a1_xor_a0, T1D); // (A1+A0)(B1+B0)

    ext(tmp4, T16B, result_lo, result_hi, 0x08);
    eor(tmp3, T16B, result_hi, result_lo); // A1*B1+A0*B0
    eor(tmp2, T16B, tmp2, tmp4);
    eor(tmp2, T16B, tmp2, tmp3);

    // Register pair <result_hi:result_lo> holds the result of carry-less multiplication
    ins(result_hi, D, tmp2, 0, 1);
    ins(result_lo, D, tmp2, 1, 0);
  }

void MacroAssembler::ghash_reduce(FloatRegister result, FloatRegister lo, FloatRegister hi,
                  FloatRegister p, FloatRegister z, FloatRegister t1) {
  const FloatRegister t0 = result;

  // The GCM field polynomial f is z^128 + p(z), where p =
  // z^7+z^2+z+1.
  //
  //    z^128 === -p(z)  (mod (z^128 + p(z)))
  //
  // so, given that the product we're reducing is
  //    a == lo + hi * z^128
  // substituting,
  //      === lo - hi * p(z)  (mod (z^128 + p(z)))
  //
  // we reduce by multiplying hi by p(z) and subtracting the result
  // from (i.e. XORing it with) lo.  Because p has no nonzero high
  // bits we can do this with two 64-bit multiplications, lo*p and
  // hi*p.

  pmull2(t0, T1Q, hi, p, T2D);
  ext(t1, T16B, t0, z, 8);
  eor(hi, T16B, hi, t1);
  ext(t1, T16B, z, t0, 8);
  eor(lo, T16B, lo, t1);
  pmull(t0, T1Q, hi, p, T1D);
  eor(result, T16B, lo, t0);
}

