/*
 * Copyright (c) 2002, 2020, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2014, Red Hat Inc. All rights reserved.
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
#include "asm/macroAssembler.inline.hpp"
#include "asm/register.hpp"
#include "register_aarch64.hpp"
# include "interp_masm_aarch64.hpp"

namespace RegisterDeclarations {
  RegisterImpl the_regs[RegisterImpl::number_of_registers + 3];  // 32 physical regs + SP + ZR + noreg
};
namespace FloatRegisterDeclarations {
  FloatRegisterImpl the_regs[FloatRegisterImpl::number_of_registers + 1];   // 32 physical regs + fnoreg
};
namespace PRegisterDeclarations {
  PRegisterImpl the_regs[PRegisterImpl::number_of_registers + 1];   // 16 physical registers + noreg
};

#define AARCH64_REGISTER_DEFINITION(type, name) \
constexpr type name = (type##Declarations::first_reg_addr + name##_##type##EnumValue)

AARCH64_REGISTER_DEFINITION(Register, noreg);

AARCH64_REGISTER_DEFINITION(Register, r0);
AARCH64_REGISTER_DEFINITION(Register, r1);
AARCH64_REGISTER_DEFINITION(Register, r2);
AARCH64_REGISTER_DEFINITION(Register, r3);
AARCH64_REGISTER_DEFINITION(Register, r4);
AARCH64_REGISTER_DEFINITION(Register, r5);
AARCH64_REGISTER_DEFINITION(Register, r6);
AARCH64_REGISTER_DEFINITION(Register, r7);
AARCH64_REGISTER_DEFINITION(Register, r8);
AARCH64_REGISTER_DEFINITION(Register, r9);
AARCH64_REGISTER_DEFINITION(Register, r10);
AARCH64_REGISTER_DEFINITION(Register, r11);
AARCH64_REGISTER_DEFINITION(Register, r12);
AARCH64_REGISTER_DEFINITION(Register, r13);
AARCH64_REGISTER_DEFINITION(Register, r14);
AARCH64_REGISTER_DEFINITION(Register, r15);
AARCH64_REGISTER_DEFINITION(Register, r16);
AARCH64_REGISTER_DEFINITION(Register, r17);
AARCH64_REGISTER_DEFINITION(Register, r18_tls); // see comment in register_aarch64.hpp
AARCH64_REGISTER_DEFINITION(Register, r19);
AARCH64_REGISTER_DEFINITION(Register, r20);
AARCH64_REGISTER_DEFINITION(Register, r21);
AARCH64_REGISTER_DEFINITION(Register, r22);
AARCH64_REGISTER_DEFINITION(Register, r23);
AARCH64_REGISTER_DEFINITION(Register, r24);
AARCH64_REGISTER_DEFINITION(Register, r25);
AARCH64_REGISTER_DEFINITION(Register, r26);
AARCH64_REGISTER_DEFINITION(Register, r27);
AARCH64_REGISTER_DEFINITION(Register, r28);
AARCH64_REGISTER_DEFINITION(Register, r29);
AARCH64_REGISTER_DEFINITION(Register, r30);
AARCH64_REGISTER_DEFINITION(Register, sp);

AARCH64_REGISTER_DEFINITION(FloatRegister, fnoreg);

AARCH64_REGISTER_DEFINITION(FloatRegister, v0);
AARCH64_REGISTER_DEFINITION(FloatRegister, v1);
AARCH64_REGISTER_DEFINITION(FloatRegister, v2);
AARCH64_REGISTER_DEFINITION(FloatRegister, v3);
AARCH64_REGISTER_DEFINITION(FloatRegister, v4);
AARCH64_REGISTER_DEFINITION(FloatRegister, v5);
AARCH64_REGISTER_DEFINITION(FloatRegister, v6);
AARCH64_REGISTER_DEFINITION(FloatRegister, v7);
AARCH64_REGISTER_DEFINITION(FloatRegister, v8);
AARCH64_REGISTER_DEFINITION(FloatRegister, v9);
AARCH64_REGISTER_DEFINITION(FloatRegister, v10);
AARCH64_REGISTER_DEFINITION(FloatRegister, v11);
AARCH64_REGISTER_DEFINITION(FloatRegister, v12);
AARCH64_REGISTER_DEFINITION(FloatRegister, v13);
AARCH64_REGISTER_DEFINITION(FloatRegister, v14);
AARCH64_REGISTER_DEFINITION(FloatRegister, v15);
AARCH64_REGISTER_DEFINITION(FloatRegister, v16);
AARCH64_REGISTER_DEFINITION(FloatRegister, v17);
AARCH64_REGISTER_DEFINITION(FloatRegister, v18);
AARCH64_REGISTER_DEFINITION(FloatRegister, v19);
AARCH64_REGISTER_DEFINITION(FloatRegister, v20);
AARCH64_REGISTER_DEFINITION(FloatRegister, v21);
AARCH64_REGISTER_DEFINITION(FloatRegister, v22);
AARCH64_REGISTER_DEFINITION(FloatRegister, v23);
AARCH64_REGISTER_DEFINITION(FloatRegister, v24);
AARCH64_REGISTER_DEFINITION(FloatRegister, v25);
AARCH64_REGISTER_DEFINITION(FloatRegister, v26);
AARCH64_REGISTER_DEFINITION(FloatRegister, v27);
AARCH64_REGISTER_DEFINITION(FloatRegister, v28);
AARCH64_REGISTER_DEFINITION(FloatRegister, v29);
AARCH64_REGISTER_DEFINITION(FloatRegister, v30);
AARCH64_REGISTER_DEFINITION(FloatRegister, v31);

AARCH64_REGISTER_DEFINITION(Register, zr);

AARCH64_REGISTER_DEFINITION(Register, c_rarg0);
AARCH64_REGISTER_DEFINITION(Register, c_rarg1);
AARCH64_REGISTER_DEFINITION(Register, c_rarg2);
AARCH64_REGISTER_DEFINITION(Register, c_rarg3);
AARCH64_REGISTER_DEFINITION(Register, c_rarg4);
AARCH64_REGISTER_DEFINITION(Register, c_rarg5);
AARCH64_REGISTER_DEFINITION(Register, c_rarg6);
AARCH64_REGISTER_DEFINITION(Register, c_rarg7);

AARCH64_REGISTER_DEFINITION(FloatRegister, c_farg0);
AARCH64_REGISTER_DEFINITION(FloatRegister, c_farg1);
AARCH64_REGISTER_DEFINITION(FloatRegister, c_farg2);
AARCH64_REGISTER_DEFINITION(FloatRegister, c_farg3);
AARCH64_REGISTER_DEFINITION(FloatRegister, c_farg4);
AARCH64_REGISTER_DEFINITION(FloatRegister, c_farg5);
AARCH64_REGISTER_DEFINITION(FloatRegister, c_farg6);
AARCH64_REGISTER_DEFINITION(FloatRegister, c_farg7);

AARCH64_REGISTER_DEFINITION(Register, j_rarg0);
AARCH64_REGISTER_DEFINITION(Register, j_rarg1);
AARCH64_REGISTER_DEFINITION(Register, j_rarg2);
AARCH64_REGISTER_DEFINITION(Register, j_rarg3);
AARCH64_REGISTER_DEFINITION(Register, j_rarg4);
AARCH64_REGISTER_DEFINITION(Register, j_rarg5);
AARCH64_REGISTER_DEFINITION(Register, j_rarg6);
AARCH64_REGISTER_DEFINITION(Register, j_rarg7);

AARCH64_REGISTER_DEFINITION(FloatRegister, j_farg0);
AARCH64_REGISTER_DEFINITION(FloatRegister, j_farg1);
AARCH64_REGISTER_DEFINITION(FloatRegister, j_farg2);
AARCH64_REGISTER_DEFINITION(FloatRegister, j_farg3);
AARCH64_REGISTER_DEFINITION(FloatRegister, j_farg4);
AARCH64_REGISTER_DEFINITION(FloatRegister, j_farg5);
AARCH64_REGISTER_DEFINITION(FloatRegister, j_farg6);
AARCH64_REGISTER_DEFINITION(FloatRegister, j_farg7);

AARCH64_REGISTER_DEFINITION(Register, rscratch1);
AARCH64_REGISTER_DEFINITION(Register, rscratch2);
AARCH64_REGISTER_DEFINITION(Register, esp);
AARCH64_REGISTER_DEFINITION(Register, rdispatch);
AARCH64_REGISTER_DEFINITION(Register, rcpool);
AARCH64_REGISTER_DEFINITION(Register, rmonitors);
AARCH64_REGISTER_DEFINITION(Register, rlocals);
AARCH64_REGISTER_DEFINITION(Register, rmethod);
AARCH64_REGISTER_DEFINITION(Register, rbcp);

AARCH64_REGISTER_DEFINITION(Register, lr);
AARCH64_REGISTER_DEFINITION(Register, rfp);
AARCH64_REGISTER_DEFINITION(Register, rthread);
AARCH64_REGISTER_DEFINITION(Register, rheapbase);

AARCH64_REGISTER_DEFINITION(Register, r31_sp);

AARCH64_REGISTER_DEFINITION(FloatRegister, z0);
AARCH64_REGISTER_DEFINITION(FloatRegister, z1);
AARCH64_REGISTER_DEFINITION(FloatRegister, z2);
AARCH64_REGISTER_DEFINITION(FloatRegister, z3);
AARCH64_REGISTER_DEFINITION(FloatRegister, z4);
AARCH64_REGISTER_DEFINITION(FloatRegister, z5);
AARCH64_REGISTER_DEFINITION(FloatRegister, z6);
AARCH64_REGISTER_DEFINITION(FloatRegister, z7);
AARCH64_REGISTER_DEFINITION(FloatRegister, z8);
AARCH64_REGISTER_DEFINITION(FloatRegister, z9);
AARCH64_REGISTER_DEFINITION(FloatRegister, z10);
AARCH64_REGISTER_DEFINITION(FloatRegister, z11);
AARCH64_REGISTER_DEFINITION(FloatRegister, z12);
AARCH64_REGISTER_DEFINITION(FloatRegister, z13);
AARCH64_REGISTER_DEFINITION(FloatRegister, z14);
AARCH64_REGISTER_DEFINITION(FloatRegister, z15);
AARCH64_REGISTER_DEFINITION(FloatRegister, z16);
AARCH64_REGISTER_DEFINITION(FloatRegister, z17);
AARCH64_REGISTER_DEFINITION(FloatRegister, z18);
AARCH64_REGISTER_DEFINITION(FloatRegister, z19);
AARCH64_REGISTER_DEFINITION(FloatRegister, z20);
AARCH64_REGISTER_DEFINITION(FloatRegister, z21);
AARCH64_REGISTER_DEFINITION(FloatRegister, z22);
AARCH64_REGISTER_DEFINITION(FloatRegister, z23);
AARCH64_REGISTER_DEFINITION(FloatRegister, z24);
AARCH64_REGISTER_DEFINITION(FloatRegister, z25);
AARCH64_REGISTER_DEFINITION(FloatRegister, z26);
AARCH64_REGISTER_DEFINITION(FloatRegister, z27);
AARCH64_REGISTER_DEFINITION(FloatRegister, z28);
AARCH64_REGISTER_DEFINITION(FloatRegister, z29);
AARCH64_REGISTER_DEFINITION(FloatRegister, z30);
AARCH64_REGISTER_DEFINITION(FloatRegister, z31);

AARCH64_REGISTER_DEFINITION(PRegister, p0);
AARCH64_REGISTER_DEFINITION(PRegister, p1);
AARCH64_REGISTER_DEFINITION(PRegister, p2);
AARCH64_REGISTER_DEFINITION(PRegister, p3);
AARCH64_REGISTER_DEFINITION(PRegister, p4);
AARCH64_REGISTER_DEFINITION(PRegister, p5);
AARCH64_REGISTER_DEFINITION(PRegister, p6);
AARCH64_REGISTER_DEFINITION(PRegister, p7);
AARCH64_REGISTER_DEFINITION(PRegister, p8);
AARCH64_REGISTER_DEFINITION(PRegister, p9);
AARCH64_REGISTER_DEFINITION(PRegister, p10);
AARCH64_REGISTER_DEFINITION(PRegister, p11);
AARCH64_REGISTER_DEFINITION(PRegister, p12);
AARCH64_REGISTER_DEFINITION(PRegister, p13);
AARCH64_REGISTER_DEFINITION(PRegister, p14);
AARCH64_REGISTER_DEFINITION(PRegister, p15);

AARCH64_REGISTER_DEFINITION(PRegister, ptrue);
