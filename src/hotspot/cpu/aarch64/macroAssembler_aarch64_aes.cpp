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

// Load expanded key into v17..v31
void MacroAssembler::aesenc_loadkeys(Register key, Register keylen) {
  Label L_loadkeys_44, L_loadkeys_52;
  cmpw(keylen, 52);
  br(Assembler::LO, L_loadkeys_44);
  br(Assembler::EQ, L_loadkeys_52);

  ld1(v17, v18,  T16B,  post(key, 32));
  rev32(v17,  T16B, v17);
  rev32(v18,  T16B, v18);
  bind(L_loadkeys_52);
  ld1(v19, v20,  T16B,  post(key, 32));
  rev32(v19,  T16B, v19);
  rev32(v20,  T16B, v20);
  bind(L_loadkeys_44);
  ld1(v21, v22, v23, v24,  T16B,  post(key, 64));
  rev32(v21,  T16B, v21);
  rev32(v22,  T16B, v22);
  rev32(v23,  T16B, v23);
  rev32(v24,  T16B, v24);
  ld1(v25, v26, v27, v28,  T16B,  post(key, 64));
  rev32(v25,  T16B, v25);
  rev32(v26,  T16B, v26);
  rev32(v27,  T16B, v27);
  rev32(v28,  T16B, v28);
  ld1(v29, v30, v31,  T16B, post(key, 48));
  rev32(v29,  T16B, v29);
  rev32(v30,  T16B, v30);
  rev32(v31,  T16B, v31);

  // Preserve the address of the start of the key
  sub(key, key, keylen, LSL, exact_log2(sizeof (jint)));
}

#if 0
// Clobbers v1, v2, v3, v4
// Uses expanded key in v17..v31
// Returns encrypted value in v0.
// If to != noreg, store value at to
// Preserves from, to, key, keylen
void MacroAssembler::aesecb_encrypt(Register from, Register to, Register keylen) {
  Label L_rounds_44, L_rounds_52;
  Label L_doLast;
  // BIND(L_aes_loop);
  // ld1(v0,  T16B,  post(from, 16));
  if (from != noreg) {
    ld1(v0, T16B, from); // get 16 bytes of input
  }

  cmpw(keylen, 52);
  br(Assembler::LO, L_rounds_44);
  br(Assembler::EQ, L_rounds_52);

  aese(v0, v17);  aesmc(v0, v0);
  aese(v0, v18);  aesmc(v0, v0);
  bind(L_rounds_52);
  aese(v0, v19);  aesmc(v0, v0);
  aese(v0, v20);  aesmc(v0, v0);
  bind(L_rounds_44);
  aese(v0, v21);  aesmc(v0, v0);
  aese(v0, v22);  aesmc(v0, v0);
  aese(v0, v23);  aesmc(v0, v0);
  aese(v0, v24);  aesmc(v0, v0);
  aese(v0, v25);  aesmc(v0, v0);
  aese(v0, v26);  aesmc(v0, v0);
  aese(v0, v27);  aesmc(v0, v0);
  aese(v0, v28);  aesmc(v0, v0);
  aese(v0, v29);  aesmc(v0, v0);
  aese(v0, v30);
  eor(v0, T16B, v0, v31);

  if (to != noreg) {
    st1(v0, T16B, to);
  }
}
#endif

#include <functional>
static void forAll(FloatRegSet floatRegs,
                   std::function<void (FloatRegister)> f1) {
  for (RegSetIterator<FloatRegister> i = floatRegs.begin();  *i != fnoreg; ++i) {
    f1(*i);
  }
}

static void forAll(FloatRegSet floatRegs,
                   std::function<void (FloatRegister)> f1,
                   std::function<void (FloatRegister)> f2) {
  for (RegSetIterator<FloatRegister> i = floatRegs.begin();  *i != fnoreg; ++i) {
    f1(*i);
  }
  for (RegSetIterator<FloatRegister> i = floatRegs.begin();  *i != fnoreg; ++i) {
    f2(*i);
  }
}

// NeoverseTM N1Software Optimization Guide:
// Adjacent AESE/AESMC instruction pairs and adjacent AESD/AESIMC
// instruction pairs will exhibit the performance characteristics
// described in Section 4.6.
void MacroAssembler::aes_round(FloatRegister input, FloatRegister subkey) {
  aese(input, subkey); aesmc(input, input);
}

// Uses expanded key in v17..v31
// Returns encrypted values in inputs.
// If to != noreg, store value at to; likewise from
// Preserves key, keylen
// Increments from, to
void MacroAssembler::aesecb_encrypt(Register from, Register to, Register keylen,
                                    FloatRegSet inputs) {
  Label L_rounds_44, L_rounds_52;
  if (from != noreg) {
    forAll(inputs,
           [&](FloatRegister reg) { ld1(reg, T16B, post(from, 16)); });// get 16 bytes of input
  }

  cmpw(keylen, 52);
  br(Assembler::LO, L_rounds_44);
  br(Assembler::EQ, L_rounds_52);

  for (RegSetIterator<FloatRegister> subkeys = FloatRegSet::range(v17, v18);
       *subkeys != fnoreg; ++subkeys) {
    forAll(inputs, [&](FloatRegister reg) { aes_round( reg, *subkeys); });
    // forAll(inputs, [&](FloatRegister reg) { aese(reg, *subkeys); });
    // forAll(inputs, [&](FloatRegister reg) { aesmc(reg, reg); });
  }
  bind(L_rounds_52);
  for (RegSetIterator<FloatRegister> subkeys = FloatRegSet::range(v19, v20);
       *subkeys != fnoreg; ++subkeys) {
    forAll(inputs, [&](FloatRegister reg) { aes_round( reg, *subkeys); });
    // forAll(inputs, [&](FloatRegister reg) { aese(reg, *subkeys); });
    // forAll(inputs, [&](FloatRegister reg) { aesmc(reg, reg); });
  }
  bind(L_rounds_44);
  for (RegSetIterator<FloatRegister> subkeys = FloatRegSet::range(v21, v29);
       *subkeys != fnoreg; ++subkeys) {
    forAll(inputs, [&](FloatRegister reg) { aes_round( reg, *subkeys); });
    // forAll(inputs, [&](FloatRegister reg) { aese(reg, *subkeys); });
    // forAll(inputs, [&](FloatRegister reg) { aesmc(reg, reg); });
  }
  // forAll(inputs, [&](FloatRegister reg) { aese(reg, v30); eor(reg, T16B, reg, v31); });
  forAll(inputs, [&](FloatRegister reg) { aese(reg, v30); });
  forAll(inputs, [&](FloatRegister reg) { eor(reg, T16B, reg, v31); });

  if (to != noreg) {
    forAll(inputs,
           [&](FloatRegister reg) { st1(v0, T16B, post(to, 16)); });
  }
}

void MacroAssembler::ghash_multiply(FloatRegister result_lo, FloatRegister result_hi,
                                    FloatRegister a, FloatRegister b, FloatRegister a1_xor_a0,
                                    FloatRegister tmp1, FloatRegister tmp2, FloatRegister tmp3) {
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
  eor(tmp1, T16B, tmp1, b);           // (B1+B0)
  pmull(result_lo,  T1Q, b, a, T1D);  // A0*B0
  pmull(tmp2, T1Q, tmp1, a1_xor_a0, T1D); // (A1+A0)(B1+B0)

  ext(tmp1, T16B, result_lo, result_hi, 0x08);
  eor(tmp3, T16B, result_hi, result_lo); // A1*B1+A0*B0
  eor(tmp2, T16B, tmp2, tmp1);
  eor(tmp2, T16B, tmp2, tmp3);

  // Register pair <result_hi:result_lo> holds the result of carry-less multiplication
  ins(result_hi, D, tmp2, 0, 1);
  ins(result_lo, D, tmp2, 1, 0);
}

void MacroAssembler::ghash_reduce(FloatRegister result, FloatRegister lo, FloatRegister hi,
                  FloatRegister p, FloatRegister vzr, FloatRegister t1) {
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
  ext(t1, T16B, t0, vzr, 8);
  eor(hi, T16B, hi, t1);
  ext(t1, T16B, vzr, t0, 8);
  eor(lo, T16B, lo, t1);
  pmull(t0, T1Q, hi, p, T1D);
  eor(result, T16B, lo, t0);
}



void iter(std::function<void (FloatRegister, FloatRegister, FloatRegister, FloatRegister,
                              FloatRegister, FloatRegister, FloatRegister)> f1,
          FloatRegister result_lo, FloatRegister result_hi,
          FloatRegister a, FloatRegister b, FloatRegister a1_xor_a0,
          FloatRegister tmp1, FloatRegister tmp2) {
  int ofs = 0;
  f1(result_lo + ofs, result_hi + ofs, a + ofs, b + ofs,
     a1_xor_a0 + ofs, tmp1 + ofs, tmp2 + ofs);
}

void MacroAssembler::ghash_multiply_wide(int unroll, int register_offset,
                    FloatRegister result_lo, FloatRegister result_hi,
                    FloatRegister a, FloatRegister b, FloatRegister a1_xor_a0,
                    FloatRegister tmp1, FloatRegister tmp2, FloatRegister tmp3) {
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
  eor(tmp1, T16B, tmp1, b);           // (B1+B0)
  pmull(result_lo,  T1Q, b, a, T1D);  // A0*B0
  pmull(tmp2, T1Q, tmp1, a1_xor_a0, T1D); // (A1+A0)(B1+B0)

  ext(tmp1, T16B, result_lo, result_hi, 0x08);
  eor(tmp3, T16B, result_hi, result_lo); // A1*B1+A0*B0
  eor(tmp2, T16B, tmp2, tmp1);
  eor(tmp2, T16B, tmp2, tmp3);

  // Register pair <result_hi:result_lo> holds the result of carry-less multiplication
  ins(result_hi, D, tmp2, 0, 1);
  ins(result_lo, D, tmp2, 1, 0);
}

void MacroAssembler::ghash_modmul_wide (FloatRegister result,
                                        FloatRegister result_lo, FloatRegister result_hi, FloatRegister b,
                                        FloatRegister a, FloatRegister vzr, FloatRegister a1_xor_a0, FloatRegister p,
                                        FloatRegister t1, FloatRegister t2, FloatRegister t3) {
  // Multiply state in v2 by H
  ghash_multiply(/*result_lo*/result_lo, /*result_hi*/result_hi,
                    /*a*/a, /*b*/b, /*a1_xor_a0*/a1_xor_a0,
                    /*temps*/t1, t2, /*reuse b*/b);
  // Reduce v4:v5 by the field polynomial
  ghash_reduce(/*result*/result, /*lo*/result_lo, /*hi*/result_hi, /*p*/p, vzr, /*temp*/t2);
}

void MacroAssembler::ghash_processBlocks_wide(address field_polynomial, Register state, Register subkeyH,
                                              Register data, Register blocks, int unrolls) {
  int unroll_step = 7;

  assert(unrolls <= 4, "out of registers");

  FloatRegister a1_xor_a0 = v28;
  FloatRegister Hprime = v29;
  FloatRegister vzr = v30;
  FloatRegister p = v31;
  eor(vzr, T16B, vzr, vzr); // zero register

  ldrq(p, field_polynomial);    // The field polynomial

  ldrq(v0, Address(state));
  ldrq(Hprime, Address(subkeyH));

  rev64(v0, T16B, v0);          // Bit-reverse words in state and subkeyH
  rbit(v0, T16B, v0);
  rev64(Hprime, T16B, Hprime);
  rbit(Hprime, T16B, Hprime);

  // Square H -> Hprime

  orr(v6, T16B, Hprime, Hprime);  // Start with H in v6 and Hprime
  for (int i = 1; i < unrolls; i++) {
    ext(a1_xor_a0, T16B, Hprime, Hprime, 0x08); // long-swap subkeyH into a1_xor_a0
    eor(a1_xor_a0, T16B, a1_xor_a0, Hprime);        // xor subkeyH into subkeyL (Karatsuba: (A1+A0))
    ghash_modmul_wide(/*result*/v6, /*result_lo*/v5, /*result_hi*/v4, /*b*/v6,
                      Hprime, vzr, a1_xor_a0, p,
                      /*temps*/v1, v3, v2);
    rev64(v1, T16B, v6);
    rbit(v1, T16B, v1);
    strq(v1, Address(subkeyH, 16 * i));
  }

  orr(Hprime, T16B, v6, v6);

  // Hprime contains (H**unrolls)
  // v0 and ofs + (v0) contain the initial state
  for (int ofs = unroll_step; ofs < unrolls * unroll_step; ofs += unroll_step) {
    eor(ofs + (v0), T16B, ofs + (v0), ofs + (v0)); // zero odd state register
  }

  {
    Label L_ghash_loop;
    bind(L_ghash_loop);

    ext(a1_xor_a0, T16B, Hprime, Hprime, 0x08); // long-swap subkeyH into a1_xor_a0
    eor(a1_xor_a0, T16B, a1_xor_a0, Hprime);       // xor subkeyH into subkeyL (Karatsuba: (A1+A0))

    for (int ofs = 0; ofs < unrolls * unroll_step; ofs += unroll_step) {
      ld1(ofs + (v2), T16B, post(data, 0x10));
      rbit(ofs + (v2), T16B, ofs + (v2));
      eor(ofs + (v2), T16B, ofs + (v0), ofs + (v2));   // bit-swapped data ^ bit-swapped state
      ghash_modmul_wide(/*result*/v0+ofs, /*result_lo*/v5+ofs, /*result_hi*/v4+ofs, /*b*/v2+ofs,
                        Hprime, vzr, a1_xor_a0, p,
                        /*temps*/v1+ofs, v3+ofs, /* reuse b*/v2+ofs);
      nop();
    }

    sub(blocks, blocks, unrolls);
    cmp(blocks, (unsigned char)unrolls);
    br(GT, L_ghash_loop);
  }

  // Final go-around
  for (int i = 0; i < unrolls; i++) {
    int ofs = unroll_step * i;
    ld1(v2+ofs, T16B, post(data, 0x10));
    rbit(ofs + (v2), T16B, ofs + (v2));
    eor(ofs + (v2), T16B, ofs + (v0), ofs + (v2));   // bit-swapped data ^ bit-swapped state

    ldrq(Hprime, Address(subkeyH, 16 * (unrolls - i - 1)));
    rev64(Hprime, T16B, Hprime);
    rbit(Hprime, T16B, Hprime);
    ext(a1_xor_a0, T16B, Hprime, Hprime, 0x08); // long-swap subkeyH into a1_xor_a0
    eor(a1_xor_a0, T16B, a1_xor_a0, Hprime);       // xor subkeyH into subkeyL (Karatsuba: (A1+A0))
    ghash_modmul_wide(/*result*/v0+ofs, /*result_lo*/v5+ofs, /*result_hi*/v4+ofs, /*b*/v2+ofs,
                      Hprime, vzr, a1_xor_a0, p,
                      /*temps*/v1+ofs, v3+ofs, /* reuse b*/v2+ofs);
    nop();
  }

  for (int i = 0; i < unrolls - 1; i++) {
    int ofs = unroll_step * i;
    eor(v0, T16B, v0, v0 + unroll_step + ofs);
  }
  rev64(v0, T16B, v0);
  rbit(v0, T16B, v0);
  nop();
  st1(v0, T16B, state);
}
