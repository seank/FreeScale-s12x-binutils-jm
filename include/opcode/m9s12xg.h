/* m68hcs12xgate.h -- Header file for Motorola 68HCS12XGATE & 68HC12 opcode table
   Copyright 1999, 2000, 2002, 2003 Free Software Foundation, Inc.
   Written by Stephane Carrez (stcarrez@nerim.fr)

This file is part of GDB, GAS, and the GNU binutils.

GDB, GAS, and the GNU binutils are free software; you can redistribute
them and/or modify them under the terms of the GNU General Public
License as published by the Free Software Foundation; either version
1, or (at your option) any later version.

GDB, GAS, and the GNU binutils are distributed in the hope that they
will be useful, but WITHOUT ANY WARRANTY; without even the implied
warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
the GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this file; see the file COPYING.  If not, write to the Free
Software Foundation, 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.  */

#ifndef _OPCODE_M9S12XG_H
#define _OPCODE_M9S12XG_H

/* Flags for the definition of the 68HCS12XGATE & 68HC12 CCR.  */
#define M6811_S_BIT     0x80	/* Stop disable */
#define M6811_X_BIT     0x40	/* X-interrupt mask */
#define M6811_H_BIT     0x20	/* Half carry flag */
#define M6811_I_BIT     0x10	/* I-interrupt mask */
#define M6811_N_BIT     0x08	/* Negative */
#define M6811_Z_BIT     0x04	/* Zero */
#define M6811_V_BIT     0x02	/* Overflow */
#define M6811_C_BIT     0x01	/* Carry */

/* Removed register definitions
*/


/* Some insns used by gas to turn relative branches into absolute ones.  */
#define M6811_BRA	0x20
#define M6811_JMP	0x7e
#define M6811_BSR	0x8d
#define M6811_JSR	0xbd
#define M6812_JMP       0x06
#define M6812_BSR       0x07
#define M6812_JSR       0x16

/* Instruction code pages. Code page 1 is the default.  */
/*#define	M6811_OPCODE_PAGE1	0x00*/
#define	M6811_OPCODE_PAGE2	0x18
#define	M6811_OPCODE_PAGE3	0x1A
#define	M6811_OPCODE_PAGE4	0xCD


/* 68HCS12XGATE operands formats as stored in the m6811_opcode table.  These
   flags do not correspond to anything in the 68HCS12XGATE or 68HC12.
   They are only used by GAS to recognize operands.  */

#define M68XG_OP_NONE           0x0001
#define M68XG_OP_IMM3           0x0002
#define M68XG_OP_R              0x0004
#define M68XG_OP_R_R            0x0008
#define M68XG_OP_R_IMM4         0x0010
#define M68XG_OP_R_R_R          0x0020
#define M68XG_OP_REL9           0x0040
#define M68XG_OP_REL10          0x0080
#define M68XG_OP_R_R_OFFS5      0x0100
#define M68XG_OP_RD_RB_RI       0x0200
#define M68XG_OP_RD_RB_RIp      0x0400
#define M68XG_OP_RD_RB_mRI      0x0800
#define M68XG_OP_R_IMM8         0x1000
#define M68XG_OP_R_IMM16        0x2000
#define M68XG_OP_REG            0x10000   /* Register operand 1                 */
#define M68XG_OP_REG_2          0x20000   /* Register operand 2                 */
#define M68XG_MAX_OPERANDS      3     /* Max operands of triadic r1, r2, r3 */


// probably want to scrub all of these
#define M6811_OP_BRANCH       0x00008000 /* Branch, jsr, call */
#define M6811_OP_BITMASK      0x00010000 /* Bitmask:             #<val-8>    */

/* Markers to identify some instructions.  */
#define M6812_OP_EXG_MARKER   0x01000000 /* exg r1,r2 */
#define M6812_OP_TFR_MARKER   0x02000000 /* tfr r1,r2 */
#define M6812_OP_SEX_MARKER   0x04000000 /* sex r1,r2 */

#define M68XG_OP_B_MARKER    0x04000000 /* bXX rel9 */
#define M68XG_OP_BRA_MARKER  0x02000000 /* bra rel10 */

#define M6812_OP_TRAP_ID      0x80000000 /* trap #N */

#define M6811_OP_HIGH_ADDR    0x01000000 /* Used internally by gas.  */
#define M6811_OP_LOW_ADDR     0x02000000

#define M68HC12_BANK_VIRT 0x010000
#define M68HC12_BANK_MASK 0x00003fff
#define M68HC12_BANK_BASE 0x00008000
#define M68HC12_BANK_SHIFT 14
#define M68HC12_BANK_PAGE_MASK 0x0ff


/* CPU identification.  */
#define cpu6811 0x01
#define cpu6812 0x02
#define cpu6812s 0x04
#define cpu9s12xe 0x08
#define cpu9s12xgate 0x10

/* The opcode table is an array of struct m68hcs12xgate_opcode.  */
struct m68hcs12xgate_opcode {
  const char*    name;     /* Op-code name */
  long           format;
  unsigned int   opcode; // base opcode with zero in register place
  unsigned int   opcode_mask; // mask with zero in register place
};

/* The opcode table.  The table contains all the opcodes (all pages).
   You can't rely on the order.  */
extern const struct m68hcs12xgate_opcode m68hcs12xgate_opcodes[];
extern const int m68hcs12xgate_num_opcodes;

#endif /* _OPCODE_M9S12XG_H */
