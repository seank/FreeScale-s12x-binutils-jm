/* Motorola 68HCS12XGATE-specific support for 32-bit ELF
   Copyright 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007
   Free Software Foundation, Inc.

James Murray 2008.
Status: search and replace hc11 -> hcs12xgate


   Contributed by Stephane Carrez (stcarrez@nerim.fr)
   (Heavily copied from the D10V port by Martin Hunt (hunt@cygnus.com))

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#include "sysdep.h"
#include "bfd.h"
#include "bfdlink.h"
#include "libbfd.h"
#include "elf-bfd.h"
#include "elf32-m9s12xg.h"
#include "elf/m9s12xg.h"
#include "opcode/m9s12xg.h"
#include "elf/reloc-macros.h"

// this seems bogus
#define m9s12xg_stub_hash_lookup(table, string, create, copy) \
  ((struct elf32_m9s12xg_stub_hash_entry *) \
   bfd_hash_lookup ((table), (string), (create), (copy)))

static struct bfd_hash_entry *stub_hash_newfunc
  (struct bfd_hash_entry *, struct bfd_hash_table *, const char *);

struct m9s12xg_scan_param
{
   struct m9s12xg_page_info* pinfo;
   bfd_boolean use_memory_banks;
};

static struct elf32_m9s12xg_stub_hash_entry* m9s12xg_add_stub
  (const char *stub_name,
   asection *section,
   struct m9s12xg_elf_link_hash_table *htab);

static bfd_boolean m9s12xg_elf_export_one_stub
  (struct bfd_hash_entry *gen_entry, void *in_arg);

static void scan_sections_for_abi (bfd*, asection*, PTR);

static void m9s12xg_elf_set_symbol (bfd* abfd, struct bfd_link_info *info,
                                    const char* name, bfd_vma value,
                                    asection* sec);

/* Relocation functions.  */
static reloc_howto_type *bfd_elf32_bfd_reloc_type_lookup
  (bfd *, bfd_reloc_code_real_type);
static void m9s12xg_info_to_howto_rel
  (bfd *, arelent *, Elf_Internal_Rela *);

/* Trampoline generation.  */
static bfd_boolean m9s12xg_elf_size_one_stub
  (struct bfd_hash_entry *gen_entry, void *in_arg);
static bfd_boolean m9s12xg_elf_build_one_stub
  (struct bfd_hash_entry *gen_entry, void *in_arg);
static struct bfd_link_hash_table* m9s12xg_elf_bfd_link_hash_table_create
  (bfd* abfd);

/* Linker relaxation.  */
static bfd_boolean m9s12xg_elf_relax_section
  (bfd *, asection *, struct bfd_link_info *, bfd_boolean *);
static void m9s12xg_elf_relax_delete_bytes
  (bfd *, asection *, bfd_vma, int);
static void m9s12xg_relax_group
  (bfd *, asection *, bfd_byte *, unsigned, unsigned long, unsigned long);
static int compare_reloc (const void *, const void *);

/* Use REL instead of RELA to save space */
#define USE_REL	1

/* The xgate core addresses 64Kb and does not use banking.
   Lots of old code remains in this file from hc12 that ought to
   be deleted.
   We must handle 8 and 16-bit relocations.  The 32-bit relocation
   are used for debugging sections (DWARF2) to represent a virtual
   address.
   The 3-bit and 16-bit PC rel relocation is only used by 68HC12.  */
static reloc_howto_type elf_m9s12xg_howto_table[] = {
  /* This reloc does nothing.  */
  HOWTO (R_M68HC11_NONE,	/* type */
	 0,			/* rightshift */
	 2,			/* size (0 = byte, 1 = short, 2 = long) */
	 32,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_M68HC11_NONE",	/* name */
	 FALSE,			/* partial_inplace */
	 0,			/* src_mask */
	 0,			/* dst_mask */
	 FALSE),		/* pcrel_offset */

  /* A 8 bit absolute relocation */
  HOWTO (R_M68HC11_8,		/* type */
	 0,			/* rightshift */
	 0,			/* size (0 = byte, 1 = short, 2 = long) */
	 8,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_M68HC11_8",		/* name */
	 FALSE,			/* partial_inplace */
	 0x00ff,		/* src_mask */
	 0x00ff,		/* dst_mask */
	 FALSE),		/* pcrel_offset */

  /* A 8 bit absolute relocation (upper address) */
  HOWTO (R_M68HC11_HI8,		/* type */
	 0,			/* rightshift */
	 1,			/* size (0 = byte, 1 = short, 2 = long) */
	 16,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_M68HC11_HI8",	/* name */
	 FALSE,			/* partial_inplace */
	 0xffff,		/* src_mask */
	 0xffff,		/* dst_mask */
	 FALSE),		/* pcrel_offset */

  /* A 8 bit absolute relocation (lower address) */
  HOWTO (R_M68HC11_LO8,		/* type */
	 0,			/* rightshift */
	 0,			/* size (0 = byte, 1 = short, 2 = long) */
	 8,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_M68HC11_LO8",	/* name */
	 FALSE,			/* partial_inplace */
	 0x00ff,		/* src_mask */
	 0x00ff,		/* dst_mask */
	 FALSE),		/* pcrel_offset */

  /* A 8 bit PC-rel relocation */
  HOWTO (R_M68HC11_PCREL_8,	/* type */
	 0,			/* rightshift */
	 0,			/* size (0 = byte, 1 = short, 2 = long) */
	 8,			/* bitsize */
	 TRUE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_M68HC11_PCREL_8",	/* name */
	 FALSE,			/* partial_inplace */
	 0x00ff,		/* src_mask */
	 0x00ff,		/* dst_mask */
	 TRUE),                 /* pcrel_offset */

  /* A 16 bit absolute relocation */
  HOWTO (R_M68HC11_16,		/* type */
	 0,			/* rightshift */
	 1,			/* size (0 = byte, 1 = short, 2 = long) */
	 16,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont /*bitfield */ ,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_M68HC11_16",	/* name */
	 FALSE,			/* partial_inplace */
	 0xffff,		/* src_mask */
	 0xffff,		/* dst_mask */
	 FALSE),		/* pcrel_offset */

  /* A 32 bit absolute relocation.  This one is never used for the
     code relocation.  It's used by gas for -gstabs generation.  */
  HOWTO (R_M68HC11_32,		/* type */
	 0,			/* rightshift */
	 2,			/* size (0 = byte, 1 = short, 2 = long) */
	 32,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_M68HC11_32",	/* name */
	 FALSE,			/* partial_inplace */
	 0xffffffff,		/* src_mask */
	 0xffffffff,		/* dst_mask */
	 FALSE),		/* pcrel_offset */

  /* A 3 bit absolute relocation */
  HOWTO (R_M68HC11_3B,		/* type */
	 0,			/* rightshift */
	 0,			/* size (0 = byte, 1 = short, 2 = long) */
	 3,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_M68HC11_4B",	/* name */
	 FALSE,			/* partial_inplace */
	 0x007,			/* src_mask */
	 0x007,			/* dst_mask */
	 FALSE),		/* pcrel_offset */

  /* A 16 bit PC-rel relocation */
  HOWTO (R_M68HC11_PCREL_16,	/* type */
	 0,			/* rightshift */
	 1,			/* size (0 = byte, 1 = short, 2 = long) */
	 16,			/* bitsize */
	 TRUE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_M68HC11_PCREL_16",	/* name */
	 FALSE,			/* partial_inplace */
	 0xffff,		/* src_mask */
	 0xffff,		/* dst_mask */
	 TRUE),                 /* pcrel_offset */

  /* GNU extension to record C++ vtable hierarchy */
  HOWTO (R_M68HC11_GNU_VTINHERIT,	/* type */
	 0,			/* rightshift */
	 1,			/* size (0 = byte, 1 = short, 2 = long) */
	 0,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 NULL,			/* special_function */
	 "R_M68HC11_GNU_VTINHERIT",	/* name */
	 FALSE,			/* partial_inplace */
	 0,			/* src_mask */
	 0,			/* dst_mask */
	 FALSE),		/* pcrel_offset */

  /* GNU extension to record C++ vtable member usage */
  HOWTO (R_M68HC11_GNU_VTENTRY,	/* type */
	 0,			/* rightshift */
	 1,			/* size (0 = byte, 1 = short, 2 = long) */
	 0,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 _bfd_elf_rel_vtable_reloc_fn,	/* special_function */
	 "R_M68HC11_GNU_VTENTRY",	/* name */
	 FALSE,			/* partial_inplace */
	 0,			/* src_mask */
	 0,			/* dst_mask */
	 FALSE),		/* pcrel_offset */

  /* A 24 bit relocation */
  HOWTO (R_M68HC11_24,	        /* type */
	 0,			/* rightshift */
	 1,			/* size (0 = byte, 1 = short, 2 = long) */
	 24,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_M68HC11_24",	/* name */
	 FALSE,			/* partial_inplace */
	 0xffffff,		/* src_mask */
	 0xffffff,		/* dst_mask */
	 FALSE),		/* pcrel_offset */

  /* A 16-bit low relocation */
  HOWTO (R_M68HC11_LO16,        /* type */
	 0,			/* rightshift */
	 1,			/* size (0 = byte, 1 = short, 2 = long) */
	 16,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_M68HC11_LO16",	/* name */
	 FALSE,			/* partial_inplace */
	 0xffff,		/* src_mask */
	 0xffff,		/* dst_mask */
	 FALSE),		/* pcrel_offset */

  /* A page relocation */
  HOWTO (R_M68HC11_PAGE,        /* type */
	 0,			/* rightshift */
	 0,			/* size (0 = byte, 1 = short, 2 = long) */
	 8,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_bitfield,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_M68HC11_PAGE",	/* name */
	 FALSE,			/* partial_inplace */
	 0x00ff,		/* src_mask */
	 0x00ff,		/* dst_mask */
	 FALSE),		/* pcrel_offset */

  /* A 8 bit absolute relocation (upper address) */
  HOWTO (R_M68HC11_HI8_16,		/* type */
	 0,			/* rightshift */
	 1,			/* size (0 = byte, 1 = short, 2 = long) */
	 16,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_M68HC11_HI8_16",	/* name */
	 FALSE,			/* partial_inplace */
	 0xffff,		/* src_mask */
	 0xffff,		/* dst_mask */
	 FALSE),		/* pcrel_offset */

  EMPTY_HOWTO (15),
  EMPTY_HOWTO (16),
  EMPTY_HOWTO (17),
  EMPTY_HOWTO (18),
  EMPTY_HOWTO (19),

  /* Mark beginning of a jump instruction (any form).  */
  HOWTO (R_M68HC11_RL_JUMP,	/* type */
	 0,			/* rightshift */
	 1,			/* size (0 = byte, 1 = short, 2 = long) */
	 0,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 m9s12xg_elf_ignore_reloc,	/* special_function */
	 "R_M68HC11_RL_JUMP",	/* name */
	 TRUE,			/* partial_inplace */
	 0,			/* src_mask */
	 0,			/* dst_mask */
	 TRUE),                 /* pcrel_offset */

  /* Mark beginning of Gcc relaxation group instruction.  */
  HOWTO (R_M68HC11_RL_GROUP,	/* type */
	 0,			/* rightshift */
	 1,			/* size (0 = byte, 1 = short, 2 = long) */
	 0,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 m9s12xg_elf_ignore_reloc,	/* special_function */
	 "R_M68HC11_RL_GROUP",	/* name */
	 TRUE,			/* partial_inplace */
	 0,			/* src_mask */
	 0,			/* dst_mask */
	 TRUE),                 /* pcrel_offset */
};

/* Map BFD reloc types to m9s12xg ELF reloc types.  */


struct m9s12xg_reloc_map
{
  bfd_reloc_code_real_type bfd_reloc_val;
  unsigned char elf_reloc_val;
};

static const struct m9s12xg_reloc_map m9s12xg_reloc_map[] = {
  {BFD_RELOC_NONE, R_M68HC11_NONE,},
  {BFD_RELOC_8, R_M68HC11_8},
  {BFD_RELOC_M68HC11_HI8, R_M68HC11_HI8},
  {BFD_RELOC_M68HC11_LO8, R_M68HC11_LO8},
  {BFD_RELOC_8_PCREL, R_M68HC11_PCREL_8},
  {BFD_RELOC_16_PCREL, R_M68HC11_PCREL_16},
  {BFD_RELOC_16, R_M68HC11_16},
  {BFD_RELOC_32, R_M68HC11_32},
  {BFD_RELOC_M68HC11_3B, R_M68HC11_3B},

  {BFD_RELOC_VTABLE_INHERIT, R_M68HC11_GNU_VTINHERIT},
  {BFD_RELOC_VTABLE_ENTRY, R_M68HC11_GNU_VTENTRY},

  {BFD_RELOC_M68HC11_LO16, R_M68HC11_LO16},
  {BFD_RELOC_M68HC11_PAGE, R_M68HC11_PAGE},
  {BFD_RELOC_M68HC11_24, R_M68HC11_24},

  {BFD_RELOC_M68HC11_RL_JUMP, R_M68HC11_RL_JUMP},
  {BFD_RELOC_M68HC11_RL_GROUP, R_M68HC11_RL_GROUP},
  {BFD_RELOC_M68HC11_HI8_16, R_M68HC11_HI8_16}
};

static reloc_howto_type *
bfd_elf32_bfd_reloc_type_lookup (bfd *abfd ATTRIBUTE_UNUSED,
                                 bfd_reloc_code_real_type code)
{
  unsigned int i;

  for (i = 0;
       i < sizeof (m9s12xg_reloc_map) / sizeof (struct m9s12xg_reloc_map);
       i++)
    {
      if (m9s12xg_reloc_map[i].bfd_reloc_val == code)
	return &elf_m9s12xg_howto_table[m9s12xg_reloc_map[i].elf_reloc_val];
    }

  return NULL;
}

static reloc_howto_type *
bfd_elf32_bfd_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED,
				 const char *r_name)
{
  unsigned int i;

  for (i = 0;
       i < (sizeof (elf_m9s12xg_howto_table)
	    / sizeof (elf_m9s12xg_howto_table[0]));
       i++)
    if (elf_m9s12xg_howto_table[i].name != NULL
	&& strcasecmp (elf_m9s12xg_howto_table[i].name, r_name) == 0)
      return &elf_m9s12xg_howto_table[i];

  return NULL;
}

/* Set the howto pointer for an m9s12xg ELF reloc.  */

static void
m9s12xg_info_to_howto_rel (bfd *abfd ATTRIBUTE_UNUSED,
                           arelent *cache_ptr, Elf_Internal_Rela *dst)
{
  unsigned int r_type;

  r_type = ELF32_R_TYPE (dst->r_info);
  BFD_ASSERT (r_type < (unsigned int) R_M68HC11_max);
  cache_ptr->howto = &elf_m9s12xg_howto_table[r_type];
}


/* Far trampoline generation.  */

/* Build a 68HCS12XGATE trampoline stub.  */
static bfd_boolean
m9s12xg_elf_build_one_stub (struct bfd_hash_entry *gen_entry, void *in_arg)
{
  struct elf32_m9s12xg_stub_hash_entry *stub_entry;
  struct bfd_link_info *info;
  struct m9s12xg_elf_link_hash_table *htab;
  asection *stub_sec;
  bfd *stub_bfd;
  bfd_byte *loc;
  bfd_vma sym_value, phys_page, phys_addr;

  /* Massage our args to the form they really have.  */
  stub_entry = (struct elf32_m9s12xg_stub_hash_entry *) gen_entry;
  info = (struct bfd_link_info *) in_arg;

  htab = m9s12xg_elf_hash_table (info);

  stub_sec = stub_entry->stub_sec;

  /* Make a note of the offset within the stubs for this entry.  */
  stub_entry->stub_offset = stub_sec->size;
  stub_sec->size += 10;
  loc = stub_sec->contents + stub_entry->stub_offset;

  stub_bfd = stub_sec->owner;

  /* Create the trampoline call stub:

     pshb
     ldab #%page(symbol)
     ldy #%addr(symbol)
     jmp __trampoline

  */
  sym_value = (stub_entry->target_value
               + stub_entry->target_section->output_offset
               + stub_entry->target_section->output_section->vma);
  phys_addr = m9s12xg_phys_addr (&htab->pinfo, sym_value);
  phys_page = m9s12xg_phys_page (&htab->pinfo, sym_value);

  /* pshb; ldab #%page(sym) */
  bfd_put_8 (stub_bfd, 0x37, loc);
  bfd_put_8 (stub_bfd, 0xC6, loc + 1);
  bfd_put_8 (stub_bfd, phys_page, loc + 2);
  loc += 3;

  /* ldy #%addr(sym)  */
  bfd_put_8 (stub_bfd, 0x18, loc);
  bfd_put_8 (stub_bfd, 0xCE, loc + 1);
  bfd_put_16 (stub_bfd, phys_addr, loc + 2);
  loc += 4;

  /* jmp __trampoline  */
  bfd_put_8 (stub_bfd, 0x7E, loc);
  bfd_put_16 (stub_bfd, htab->pinfo.trampoline_addr, loc + 1);

  return TRUE;
}

/* As above, but don't actually build the stub.  Just bump offset so
   we know stub section sizes.  */

static bfd_boolean
m9s12xg_elf_size_one_stub (struct bfd_hash_entry *gen_entry,
                           void *in_arg ATTRIBUTE_UNUSED)
{
  struct elf32_m9s12xg_stub_hash_entry *stub_entry;

  /* Massage our args to the form they really have.  */
  stub_entry = (struct elf32_m9s12xg_stub_hash_entry *) gen_entry;

  stub_entry->stub_sec->size += 10;
  return TRUE;
}

/* Create a 68HCS12XGATE ELF linker hash table.  */

static struct bfd_link_hash_table *
m9s12xg_elf_bfd_link_hash_table_create (bfd *abfd)
{
  struct m9s12xg_elf_link_hash_table *ret;

  ret = m9s12xg_elf_hash_table_create (abfd);
  if (ret == (struct m9s12xg_elf_link_hash_table *) NULL)
    return NULL;

  ret->size_one_stub = m9s12xg_elf_size_one_stub;
  ret->build_one_stub = m9s12xg_elf_build_one_stub;

  return &ret->root.root;
}


/* 68HCS12XGATE Linker Relaxation.  */
/* this probably doesn't make any sense at all with XGATE, but don't even know what it means ! */
struct m9s12xg_direct_relax
{
  const char *name;
  unsigned char code;
  unsigned char direct_code;
} m9s12xg_direct_relax_table[] = {
  { "adca", 0xB9, 0x99 },
  { "adcb", 0xF9, 0xD9 },
  { "adda", 0xBB, 0x9B },
  { "addb", 0xFB, 0xDB },
  { "addd", 0xF3, 0xD3 },
  { "anda", 0xB4, 0x94 },
  { "andb", 0xF4, 0xD4 },
  { "cmpa", 0xB1, 0x91 },
  { "cmpb", 0xF1, 0xD1 },
  { "cpd",  0xB3, 0x93 },
  { "cpxy", 0xBC, 0x9C },
/* { "cpy",  0xBC, 0x9C }, */
  { "eora", 0xB8, 0x98 },
  { "eorb", 0xF8, 0xD8 },
  { "jsr",  0xBD, 0x9D },
  { "ldaa", 0xB6, 0x96 },
  { "ldab", 0xF6, 0xD6 },
  { "ldd",  0xFC, 0xDC },
  { "lds",  0xBE, 0x9E },
  { "ldxy", 0xFE, 0xDE },
  /*  { "ldy",  0xFE, 0xDE },*/
  { "oraa", 0xBA, 0x9A },
  { "orab", 0xFA, 0xDA },
  { "sbca", 0xB2, 0x92 },
  { "sbcb", 0xF2, 0xD2 },
  { "staa", 0xB7, 0x97 },
  { "stab", 0xF7, 0xD7 },
  { "std",  0xFD, 0xDD },
  { "sts",  0xBF, 0x9F },
  { "stxy", 0xFF, 0xDF },
  /*  { "sty",  0xFF, 0xDF },*/
  { "suba", 0xB0, 0x90 },
  { "subb", 0xF0, 0xD0 },
  { "subd", 0xB3, 0x93 },
  { 0, 0, 0 }
};

static struct m9s12xg_direct_relax *
find_relaxable_insn (unsigned char code)
{
  int i;

  for (i = 0; m9s12xg_direct_relax_table[i].name; i++)
    if (m9s12xg_direct_relax_table[i].code == code)
      return &m9s12xg_direct_relax_table[i];

  return 0;
}

static int
compare_reloc (const void *e1, const void *e2)
{
  const Elf_Internal_Rela *i1 = (const Elf_Internal_Rela *) e1;
  const Elf_Internal_Rela *i2 = (const Elf_Internal_Rela *) e2;

  if (i1->r_offset == i2->r_offset)
    return 0;
  else
    return i1->r_offset < i2->r_offset ? -1 : 1;
}

#define M6811_OP_LDX_IMMEDIATE (0xCE)

static void
m9s12xg_relax_group (bfd *abfd, asection *sec, bfd_byte *contents,
                     unsigned value, unsigned long offset,
                     unsigned long end_group)
{
  unsigned char code;
  unsigned long start_offset;
  unsigned long ldx_offset = offset;
  unsigned long ldx_size;
  int can_delete_ldx;
  int relax_ldy = 0;

  /* First instruction of the relax group must be a
     LDX #value or LDY #value.  If this is not the case,
     ignore the relax group.  */
  code = bfd_get_8 (abfd, contents + offset);
  if (code == 0x18)
    {
      relax_ldy++;
      offset++;
      code = bfd_get_8 (abfd, contents + offset);
    }
  ldx_size = offset - ldx_offset + 3;
  offset += 3;
  if (code != M6811_OP_LDX_IMMEDIATE || offset >= end_group)
    return;


  /* We can remove the LDX/LDY only when all bset/brclr instructions
     of the relax group have been converted to use direct addressing
     mode.  */
  can_delete_ldx = 1;
  while (offset < end_group)
    {
      unsigned isize;
      unsigned new_value;
      int bset_use_y;

      bset_use_y = 0;
      start_offset = offset;
      code = bfd_get_8 (abfd, contents + offset);
      if (code == 0x18)
        {
          bset_use_y++;
          offset++;
          code = bfd_get_8 (abfd, contents + offset);
        }

      /* Check the instruction and translate to use direct addressing mode.  */
      switch (code)
        {
          /* bset */
        case 0x1C:
          code = 0x14;
          isize = 3;
          break;

          /* brclr */
        case 0x1F:
          code = 0x13;
          isize = 4;
          break;

          /* brset */
        case 0x1E:
          code = 0x12;
          isize = 4;
          break;

          /* bclr */
        case 0x1D:
          code = 0x15;
          isize = 3;
          break;

          /* This instruction is not recognized and we are not
             at end of the relax group.  Ignore and don't remove
             the first LDX (we don't know what it is used for...).  */
        default:
          return;
        }
      new_value = (unsigned) bfd_get_8 (abfd, contents + offset + 1);
      new_value += value;
      if ((new_value & 0xff00) == 0 && bset_use_y == relax_ldy)
        {
          bfd_put_8 (abfd, code, contents + offset);
          bfd_put_8 (abfd, new_value, contents + offset + 1);
          if (start_offset != offset)
            {
              m9s12xg_elf_relax_delete_bytes (abfd, sec, start_offset,
                                              offset - start_offset);
              end_group--;
            }
        }
      else
        {
          can_delete_ldx = 0;
        }
      offset = start_offset + isize;
    }
  if (can_delete_ldx)
    {
      /* Remove the move instruction (3 or 4 bytes win).  */
      m9s12xg_elf_relax_delete_bytes (abfd, sec, ldx_offset, ldx_size);
    }
}

/* This function handles relaxing for the 68HCS12XGATE.
   Not reviewed for XGATE at all, may need removing totally

	and somewhat more difficult to support.  */

static bfd_boolean
m9s12xg_elf_relax_section (bfd *abfd, asection *sec,
                           struct bfd_link_info *link_info, bfd_boolean *again)
{
  Elf_Internal_Shdr *symtab_hdr;
  Elf_Internal_Shdr *shndx_hdr;
  Elf_Internal_Rela *internal_relocs;
  Elf_Internal_Rela *free_relocs = NULL;
  Elf_Internal_Rela *irel, *irelend;
  bfd_byte *contents = NULL;
  bfd_byte *free_contents = NULL;
  Elf32_External_Sym *free_extsyms = NULL;
  Elf_Internal_Rela *prev_insn_branch = NULL;
  Elf_Internal_Rela *prev_insn_group = NULL;
  unsigned insn_group_value = 0;
  Elf_Internal_Sym *isymbuf = NULL;

  /* Assume nothing changes.  */
  *again = FALSE;

  /* We don't have to do anything for a relocatable link, if
     this section does not have relocs, or if this is not a
     code section.  */
  if (link_info->relocatable
      || (sec->flags & SEC_RELOC) == 0
      || sec->reloc_count == 0
      || (sec->flags & SEC_CODE) == 0)
    return TRUE;

  symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
  shndx_hdr = &elf_tdata (abfd)->symtab_shndx_hdr;

  /* Get a copy of the native relocations.  */
  internal_relocs = (_bfd_elf_link_read_relocs
		     (abfd, sec, (PTR) NULL, (Elf_Internal_Rela *) NULL,
		      link_info->keep_memory));
  if (internal_relocs == NULL)
    goto error_return;
  if (! link_info->keep_memory)
    free_relocs = internal_relocs;

  /* Checking for branch relaxation relies on the relocations to
     be sorted on 'r_offset'.  This is not guaranteed so we must sort.  */
  qsort (internal_relocs, sec->reloc_count, sizeof (Elf_Internal_Rela),
         compare_reloc);

  /* Walk through them looking for relaxing opportunities.  */
  irelend = internal_relocs + sec->reloc_count;
  for (irel = internal_relocs; irel < irelend; irel++)
    {
      bfd_vma symval;
      bfd_vma value;
      Elf_Internal_Sym *isym;
      asection *sym_sec;
      int is_far = 0;

      /* If this isn't something that can be relaxed, then ignore
	 this reloc.  */
      if (ELF32_R_TYPE (irel->r_info) != (int) R_M68HC11_16
          && ELF32_R_TYPE (irel->r_info) != (int) R_M68HC11_RL_JUMP
          && ELF32_R_TYPE (irel->r_info) != (int) R_M68HC11_RL_GROUP)
        {
          prev_insn_branch = 0;
          prev_insn_group = 0;
          continue;
        }

      /* Get the section contents if we haven't done so already.  */
      if (contents == NULL)
	{
	  /* Get cached copy if it exists.  */
	  if (elf_section_data (sec)->this_hdr.contents != NULL)
	    contents = elf_section_data (sec)->this_hdr.contents;
	  else
	    {
	      /* Go get them off disk.  */
	      if (!bfd_malloc_and_get_section (abfd, sec, &contents))
		goto error_return;
	    }
	}

      /* Try to eliminate an unconditional 8 bit pc-relative branch
	 which immediately follows a conditional 8 bit pc-relative
	 branch around the unconditional branch.

	    original:		new:
	    bCC lab1		bCC' lab2
	    bra lab2
	   lab1:	       lab1:

	 This happens when the bCC can't reach lab2 at assembly time,
	 but due to other relaxations it can reach at link time.  */
      if (ELF32_R_TYPE (irel->r_info) == (int) R_M68HC11_RL_JUMP)
	{
	  Elf_Internal_Rela *nrel;
	  unsigned char code;
          unsigned char roffset;

          prev_insn_branch = 0;
          prev_insn_group = 0;

	  /* Do nothing if this reloc is the last byte in the section.  */
	  if (irel->r_offset + 2 >= sec->size)
	    continue;

	  /* See if the next instruction is an unconditional pc-relative
	     branch, more often than not this test will fail, so we
	     test it first to speed things up.  */
	  code = bfd_get_8 (abfd, contents + irel->r_offset + 2);
	  if (code != 0x7e)
	    continue;

	  /* Also make sure the next relocation applies to the next
	     instruction and that it's a pc-relative 8 bit branch.  */
	  nrel = irel + 1;
	  if (nrel == irelend
	      || irel->r_offset + 3 != nrel->r_offset
	      || ELF32_R_TYPE (nrel->r_info) != (int) R_M68HC11_16)
	    continue;

	  /* Make sure our destination immediately follows the
	     unconditional branch.  */
          roffset = bfd_get_8 (abfd, contents + irel->r_offset + 1);
          if (roffset != 3)
            continue;

          prev_insn_branch = irel;
          prev_insn_group = 0;
          continue;
        }

      /* Read this BFD's symbols if we haven't done so already.  */
      if (isymbuf == NULL && symtab_hdr->sh_info != 0)
	{
	  isymbuf = (Elf_Internal_Sym *) symtab_hdr->contents;
	  if (isymbuf == NULL)
	    isymbuf = bfd_elf_get_elf_syms (abfd, symtab_hdr,
					    symtab_hdr->sh_info, 0,
					    NULL, NULL, NULL);
	  if (isymbuf == NULL)
	    goto error_return;
	}

      /* Get the value of the symbol referred to by the reloc.  */
      if (ELF32_R_SYM (irel->r_info) < symtab_hdr->sh_info)
	{
	  /* A local symbol.  */
	  isym = isymbuf + ELF32_R_SYM (irel->r_info);
          is_far = isym->st_other & STO_M68HC12_FAR;
          sym_sec = bfd_section_from_elf_index (abfd, isym->st_shndx);
	  symval = (isym->st_value
		    + sym_sec->output_section->vma
		    + sym_sec->output_offset);
	}
      else
	{
	  unsigned long indx;
	  struct elf_link_hash_entry *h;

	  /* An external symbol.  */
	  indx = ELF32_R_SYM (irel->r_info) - symtab_hdr->sh_info;
	  h = elf_sym_hashes (abfd)[indx];
	  BFD_ASSERT (h != NULL);
	  if (h->root.type != bfd_link_hash_defined
	      && h->root.type != bfd_link_hash_defweak)
	    {
	      /* This appears to be a reference to an undefined
                 symbol.  Just ignore it--it will be caught by the
                 regular reloc processing.  */
              prev_insn_branch = 0;
              prev_insn_group = 0;
	      continue;
	    }

          is_far = h->other & STO_M68HC12_FAR;
          isym = 0;
          sym_sec = h->root.u.def.section;
	  symval = (h->root.u.def.value
		    + sym_sec->output_section->vma
		    + sym_sec->output_offset);
	}

      if (ELF32_R_TYPE (irel->r_info) == (int) R_M68HC11_RL_GROUP)
	{
          prev_insn_branch = 0;
          prev_insn_group = 0;

	  /* Do nothing if this reloc is the last byte in the section.  */
	  if (irel->r_offset == sec->size)
	    continue;

          prev_insn_group = irel;
          insn_group_value = isym->st_value;
          continue;
        }

      /* When we relax some bytes, the size of our section changes.
         This affects the layout of next input sections that go in our
         output section.  When the symbol is part of another section that
         will go in the same output section as the current one, it's
         final address may now be incorrect (too far).  We must let the
         linker re-compute all section offsets before processing this
         reloc.  Code example:

                                Initial             Final
         .sect .text            section size = 6    section size = 4
         jmp foo
         jmp bar
         .sect .text.foo_bar    output_offset = 6   output_offset = 4
         foo: rts
         bar: rts

         If we process the reloc now, the jmp bar is replaced by a
         relative branch to the initial bar address (output_offset 6).  */
      if (*again && sym_sec != sec
          && sym_sec->output_section == sec->output_section)
        {
          prev_insn_group = 0;
          prev_insn_branch = 0;
          continue;
        }

      value = symval;
      /* Try to turn a far branch to a near branch.  */
      if (ELF32_R_TYPE (irel->r_info) == (int) R_M68HC11_16
          && prev_insn_branch)
        {
          bfd_vma offset;
          unsigned char code;

          offset = value - (prev_insn_branch->r_offset
                            + sec->output_section->vma
                            + sec->output_offset + 2);

          /* If the offset is still out of -128..+127 range,
             leave that far branch unchanged.  */
          if ((offset & 0xff80) != 0 && (offset & 0xff80) != 0xff80)
            {
              prev_insn_branch = 0;
              continue;
            }

          /* Shrink the branch.  */
          code = bfd_get_8 (abfd, contents + prev_insn_branch->r_offset);
          if (code == 0x7e)
            {
              code = 0x20;
              bfd_put_8 (abfd, code, contents + prev_insn_branch->r_offset);
              bfd_put_8 (abfd, 0xff,
                         contents + prev_insn_branch->r_offset + 1);
              irel->r_offset = prev_insn_branch->r_offset + 1;
              irel->r_info = ELF32_R_INFO (ELF32_R_SYM (irel->r_info),
                                           R_M68XG_PCREL_9);
              m9s12xg_elf_relax_delete_bytes (abfd, sec,
                                              irel->r_offset + 1, 1);
            }
          else
            {
              code ^= 0x1;
              bfd_put_8 (abfd, code, contents + prev_insn_branch->r_offset);
              bfd_put_8 (abfd, 0xff,
                         contents + prev_insn_branch->r_offset + 1);
              irel->r_offset = prev_insn_branch->r_offset + 1;
              irel->r_info = ELF32_R_INFO (ELF32_R_SYM (irel->r_info),
                                           R_M68XG_PCREL_9);
              m9s12xg_elf_relax_delete_bytes (abfd, sec,
                                              irel->r_offset + 1, 3);
            }
          prev_insn_branch = 0;
          *again = TRUE;
        }

      /* Try to turn a 16 bit address into a 8 bit page0 address.  */
      else if (ELF32_R_TYPE (irel->r_info) == (int) R_M68HC11_16
               && (value & 0xff00) == 0)
	{
          unsigned char code;
          unsigned short offset;
          struct m9s12xg_direct_relax *rinfo;

          prev_insn_branch = 0;
          offset = bfd_get_16 (abfd, contents + irel->r_offset);
          offset += value;
          if ((offset & 0xff00) != 0)
            {
              prev_insn_group = 0;
              continue;
            }

          if (prev_insn_group)
            {
              unsigned long old_sec_size = sec->size;

              /* Note that we've changed the relocation contents, etc.  */
              elf_section_data (sec)->relocs = internal_relocs;
              free_relocs = NULL;

              elf_section_data (sec)->this_hdr.contents = contents;
              free_contents = NULL;

              symtab_hdr->contents = (bfd_byte *) isymbuf;
              free_extsyms = NULL;

              m9s12xg_relax_group (abfd, sec, contents, offset,
                                   prev_insn_group->r_offset,
                                   insn_group_value);
              irel = prev_insn_group;
              prev_insn_group = 0;
              irel->r_info = ELF32_R_INFO (ELF32_R_SYM (irel->r_info),
                                           R_M68HC11_NONE);
              if (sec->size != old_sec_size)
                *again = TRUE;
              continue;
            }

          /* Get the opcode.  */
          code = bfd_get_8 (abfd, contents + irel->r_offset - 1);
          rinfo = find_relaxable_insn (code);
          if (rinfo == 0)
            {
              prev_insn_group = 0;
              continue;
            }

          /* Note that we've changed the relocation contents, etc.  */
          elf_section_data (sec)->relocs = internal_relocs;
          free_relocs = NULL;

          elf_section_data (sec)->this_hdr.contents = contents;
          free_contents = NULL;

          symtab_hdr->contents = (bfd_byte *) isymbuf;
          free_extsyms = NULL;

          /* Fix the opcode.  */
          /* printf ("A relaxable case : 0x%02x (%s)\n",
             code, rinfo->name); */
          bfd_put_8 (abfd, rinfo->direct_code,
                     contents + irel->r_offset - 1);

          /* Delete one byte of data (upper byte of address).  */
          m9s12xg_elf_relax_delete_bytes (abfd, sec, irel->r_offset, 1);

          /* Fix the relocation's type.  */
          irel->r_info = ELF32_R_INFO (ELF32_R_SYM (irel->r_info),
                                       R_M68HC11_8);

          /* That will change things, so, we should relax again.  */
          *again = TRUE;
        }
      else if (ELF32_R_TYPE (irel->r_info) == R_M68HC11_16 && !is_far)
        {
          unsigned char code;
          bfd_vma offset;

          prev_insn_branch = 0;
          code = bfd_get_8 (abfd, contents + irel->r_offset - 1);
          if (code == 0x7e || code == 0xbd)
            {
              offset = value - (irel->r_offset
                                + sec->output_section->vma
                                + sec->output_offset + 1);
              offset += bfd_get_16 (abfd, contents + irel->r_offset);

              /* If the offset is still out of -128..+127 range,
                 leave that far branch unchanged.  */
              if ((offset & 0xff80) == 0 || (offset & 0xff80) == 0xff80)
                {

                  /* Note that we've changed the relocation contents, etc.  */
                  elf_section_data (sec)->relocs = internal_relocs;
                  free_relocs = NULL;

                  elf_section_data (sec)->this_hdr.contents = contents;
                  free_contents = NULL;

                  symtab_hdr->contents = (bfd_byte *) isymbuf;
                  free_extsyms = NULL;

                  /* Shrink the branch.  */
                  code = (code == 0x7e) ? 0x20 : 0x8d;
                  bfd_put_8 (abfd, code,
                             contents + irel->r_offset - 1);
                  bfd_put_8 (abfd, 0xff,
                             contents + irel->r_offset);
                  irel->r_info = ELF32_R_INFO (ELF32_R_SYM (irel->r_info),
                                               R_M68XG_PCREL_9);
                  m9s12xg_elf_relax_delete_bytes (abfd, sec,
                                                  irel->r_offset + 1, 1);
                  /* That will change things, so, we should relax again.  */
                  *again = TRUE;
                }
            }
        }
      prev_insn_branch = 0;
      prev_insn_group = 0;
    }

  if (free_relocs != NULL)
    {
      free (free_relocs);
      free_relocs = NULL;
    }

  if (free_contents != NULL)
    {
      if (! link_info->keep_memory)
	free (free_contents);
      else
	{
	  /* Cache the section contents for elf_link_input_bfd.  */
	  elf_section_data (sec)->this_hdr.contents = contents;
	}
      free_contents = NULL;
    }

  if (free_extsyms != NULL)
    {
      if (! link_info->keep_memory)
	free (free_extsyms);
      else
	{
	  /* Cache the symbols for elf_link_input_bfd.  */
	  symtab_hdr->contents = (unsigned char *) isymbuf;
	}
      free_extsyms = NULL;
    }

  return TRUE;

 error_return:
  if (free_relocs != NULL)
    free (free_relocs);
  if (free_contents != NULL)
    free (free_contents);
  if (free_extsyms != NULL)
    free (free_extsyms);
  return FALSE;
}

/* Delete some bytes from a section while relaxing.  */

static void
m9s12xg_elf_relax_delete_bytes (bfd *abfd, asection *sec,
                                bfd_vma addr, int count)
{
  Elf_Internal_Shdr *symtab_hdr;
  unsigned int sec_shndx;
  bfd_byte *contents;
  Elf_Internal_Rela *irel, *irelend;
  bfd_vma toaddr;
  Elf_Internal_Sym *isymbuf, *isym, *isymend;
  struct elf_link_hash_entry **sym_hashes;
  struct elf_link_hash_entry **end_hashes;
  unsigned int symcount;

  symtab_hdr = &elf_tdata (abfd)->symtab_hdr;
  isymbuf = (Elf_Internal_Sym *) symtab_hdr->contents;

  sec_shndx = _bfd_elf_section_from_bfd_section (abfd, sec);

  contents = elf_section_data (sec)->this_hdr.contents;

  toaddr = sec->size;

  irel = elf_section_data (sec)->relocs;
  irelend = irel + sec->reloc_count;

  /* Actually delete the bytes.  */
  memmove (contents + addr, contents + addr + count,
	   (size_t) (toaddr - addr - count));

  sec->size -= count;

  /* Adjust all the relocs.  */
  for (irel = elf_section_data (sec)->relocs; irel < irelend; irel++)
    {
      unsigned char code;
      unsigned char offset;
      unsigned short raddr;
      unsigned long old_offset;
      int branch_pos;

      old_offset = irel->r_offset;

      /* See if this reloc was for the bytes we have deleted, in which
	 case we no longer care about it.  Don't delete relocs which
	 represent addresses, though.  */
      if (ELF32_R_TYPE (irel->r_info) != R_M68HC11_RL_JUMP
          && irel->r_offset >= addr && irel->r_offset < addr + count)
        irel->r_info = ELF32_R_INFO (ELF32_R_SYM (irel->r_info),
                                     R_M68HC11_NONE);

      if (ELF32_R_TYPE (irel->r_info) == R_M68HC11_NONE)
        continue;

      /* Get the new reloc address.  */
      if ((irel->r_offset > addr
	   && irel->r_offset < toaddr))
	irel->r_offset -= count;

      /* If this is a PC relative reloc, see if the range it covers
         includes the bytes we have deleted.  */
      switch (ELF32_R_TYPE (irel->r_info))
	{
	default:
	  break;

	case R_M68HC11_RL_JUMP:
          code = bfd_get_8 (abfd, contents + irel->r_offset);
          switch (code)
            {
              /* jsr and jmp instruction are also marked with RL_JUMP
                 relocs but no adjustment must be made.  */
            case 0x7e:
            case 0x9d:
            case 0xbd:
              continue;

            case 0x12:
            case 0x13:
              branch_pos = 3;
              raddr = 4;

              /* Special case when we translate a brclr N,y into brclr *<addr>
                 In this case, the 0x18 page2 prefix is removed.
                 The reloc offset is not modified but the instruction
                 size is reduced by 1.  */
              if (old_offset == addr)
                raddr++;
              break;

            case 0x1e:
            case 0x1f:
              branch_pos = 3;
              raddr = 4;
              break;

            case 0x18:
              branch_pos = 4;
              raddr = 5;
              break;

            default:
              branch_pos = 1;
              raddr = 2;
              break;
            }
          offset = bfd_get_8 (abfd, contents + irel->r_offset + branch_pos);
          raddr += old_offset;
          raddr += ((unsigned short) offset | ((offset & 0x80) ? 0xff00 : 0));
          if (irel->r_offset < addr && raddr > addr)
            {
              offset -= count;
              bfd_put_8 (abfd, offset, contents + irel->r_offset + branch_pos);
            }
          else if (irel->r_offset >= addr && raddr <= addr)
            {
              offset += count;
              bfd_put_8 (abfd, offset, contents + irel->r_offset + branch_pos);
            }
          else
            {
              /*printf ("Not adjusted 0x%04x [0x%4x 0x%4x]\n", raddr,
                irel->r_offset, addr);*/
            }

          break;
	}
    }

  /* Adjust the local symbols defined in this section.  */
  isymend = isymbuf + symtab_hdr->sh_info;
  for (isym = isymbuf; isym < isymend; isym++)
    {
      if (isym->st_shndx == sec_shndx
	  && isym->st_value > addr
	  && isym->st_value <= toaddr)
	isym->st_value -= count;
    }

  /* Now adjust the global symbols defined in this section.  */
  symcount = (symtab_hdr->sh_size / sizeof (Elf32_External_Sym)
	      - symtab_hdr->sh_info);
  sym_hashes = elf_sym_hashes (abfd);
  end_hashes = sym_hashes + symcount;
  for (; sym_hashes < end_hashes; sym_hashes++)
    {
      struct elf_link_hash_entry *sym_hash = *sym_hashes;
      if ((sym_hash->root.type == bfd_link_hash_defined
	   || sym_hash->root.type == bfd_link_hash_defweak)
	  && sym_hash->root.u.def.section == sec
	  && sym_hash->root.u.def.value > addr
	  && sym_hash->root.u.def.value <= toaddr)
	{
	  sym_hash->root.u.def.value -= count;
	}
    }
}

/* Specific sections:
   - The .page0 is a data section that is mapped in [0x0000..0x00FF].
     Page0 accesses are faster on the M68HC11. Soft registers used by GCC-m6811
     are located in .page0.
   - The .vectors is the section that represents the interrupt
     vectors.  */
static const struct bfd_elf_special_section elf32_m9s12xg_special_sections[] =
{
  { STRING_COMMA_LEN (".eeprom"),   0, SHT_PROGBITS, SHF_ALLOC + SHF_WRITE },
  { STRING_COMMA_LEN (".page0"),    0, SHT_PROGBITS, SHF_ALLOC + SHF_WRITE },
  { STRING_COMMA_LEN (".softregs"), 0, SHT_NOBITS,   SHF_ALLOC + SHF_WRITE },
  { STRING_COMMA_LEN (".vectors"),  0, SHT_PROGBITS, SHF_ALLOC },
  { NULL,                       0,  0, 0,            0 }
};

/* sections of code taken from elf32-m68hc1x.c */
/* Return the physical address seen by the processor, taking
   into account banked memory.  */
bfd_vma
m9s12xg_phys_addr (struct m9s12xg_page_info *pinfo, bfd_vma addr)
{
  if (addr < pinfo->bank_virtual)
    return addr;

  /* Map the address to the memory bank.  */
  addr -= pinfo->bank_virtual;
  addr &= pinfo->bank_mask;
  addr += pinfo->bank_physical;
  return addr;
}

/* Return the page number corresponding to an address in banked memory.  */
bfd_vma
m9s12xg_phys_page (struct m9s12xg_page_info *pinfo, bfd_vma addr)
{
  if (addr < pinfo->bank_virtual)
    return 0;

  /* Map the address to the memory bank.  */
  addr -= pinfo->bank_virtual;
  addr >>= pinfo->bank_shift;
  addr &= 0x0ff;
  return addr;
}

/* Hook called by the linker routine which adds symbols from an object
   file.  We use it for identify far symbols and force a loading of
   the trampoline handler.  */

bfd_boolean
elf32_m9s12xg_add_symbol_hook (bfd *abfd, struct bfd_link_info *info,
                               Elf_Internal_Sym *sym,
                               const char **namep ATTRIBUTE_UNUSED,
                               flagword *flagsp ATTRIBUTE_UNUSED,
                               asection **secp ATTRIBUTE_UNUSED,
                               bfd_vma *valp ATTRIBUTE_UNUSED)
{
  if (sym->st_other & STO_M68HC12_FAR)
    {
      struct elf_link_hash_entry *h;

      h = (struct elf_link_hash_entry *)
	bfd_link_hash_lookup (info->hash, "__far_trampoline",
                              FALSE, FALSE, FALSE);
      if (h == NULL)
        {
          struct bfd_link_hash_entry* entry = NULL;

          _bfd_generic_link_add_one_symbol (info, abfd,
                                            "__far_trampoline",
                                            BSF_GLOBAL,
                                            bfd_und_section_ptr,
                                            (bfd_vma) 0, (const char*) NULL,
                                            FALSE, FALSE, &entry);
        }

    }
  return TRUE;
}

/* Look through the relocs for a section during the first phase.
   Since we don't do .gots or .plts, we just need to consider the
   virtual table relocs for gc.  */

bfd_boolean
elf32_m9s12xg_check_relocs (bfd *abfd, struct bfd_link_info *info,
                            asection *sec, const Elf_Internal_Rela *relocs)
{
  Elf_Internal_Shdr *           symtab_hdr;
  struct elf_link_hash_entry ** sym_hashes;
  struct elf_link_hash_entry ** sym_hashes_end;
  const Elf_Internal_Rela *     rel;
  const Elf_Internal_Rela *     rel_end;

  if (info->relocatable)
    return TRUE;

  symtab_hdr = & elf_tdata (abfd)->symtab_hdr;
  sym_hashes = elf_sym_hashes (abfd);
  sym_hashes_end = sym_hashes + symtab_hdr->sh_size / sizeof (Elf32_External_Sym);
  if (!elf_bad_symtab (abfd))
    sym_hashes_end -= symtab_hdr->sh_info;

  rel_end = relocs + sec->reloc_count;

  for (rel = relocs; rel < rel_end; rel++)
    {
      struct elf_link_hash_entry * h;
      unsigned long r_symndx;

      r_symndx = ELF32_R_SYM (rel->r_info);

      if (r_symndx < symtab_hdr->sh_info)
        h = NULL;
      else
	{
	  h = sym_hashes [r_symndx - symtab_hdr->sh_info];
	  while (h->root.type == bfd_link_hash_indirect
		 || h->root.type == bfd_link_hash_warning)
	    h = (struct elf_link_hash_entry *) h->root.u.i.link;
	}

      switch (ELF32_R_TYPE (rel->r_info))
        {
        /* This relocation describes the C++ object vtable hierarchy.
           Reconstruct it for later use during GC.  */
        case R_M68HC11_GNU_VTINHERIT:
          if (!bfd_elf_gc_record_vtinherit (abfd, sec, h, rel->r_offset))
            return FALSE;
          break;

        /* This relocation describes which C++ vtable entries are actually
           used.  Record for later use during GC.  */
        case R_M68HC11_GNU_VTENTRY:
          if (!bfd_elf_gc_record_vtentry (abfd, sec, h, rel->r_addend))
            return FALSE;
          break;
        }
    }

  return TRUE;
}

/* Relocate a 68hc11/68hc12 ELF section.  */
/* I don't believe this function is actually used.. uses the one in elf32-m68hc1x.c instead */
bfd_boolean
elf32_m9s12xg_relocate_section (bfd *output_bfd ATTRIBUTE_UNUSED,
                                struct bfd_link_info *info,
                                bfd *input_bfd, asection *input_section,
                                bfd_byte *contents, Elf_Internal_Rela *relocs,
                                Elf_Internal_Sym *local_syms,
                                asection **local_sections)
{
  Elf_Internal_Shdr *symtab_hdr;
  struct elf_link_hash_entry **sym_hashes;
  Elf_Internal_Rela *rel, *relend;
  const char *name = NULL;
  struct m9s12xg_page_info *pinfo;
  const struct elf_backend_data * const ebd = get_elf_backend_data (input_bfd);

  symtab_hdr = &elf_tdata (input_bfd)->symtab_hdr;
  sym_hashes = elf_sym_hashes (input_bfd);

  /* Get memory bank parameters.  */
  m9s12xg_elf_get_bank_parameters (info);
  pinfo = &m9s12xg_elf_hash_table (info)->pinfo;

  rel = relocs;
  relend = relocs + input_section->reloc_count;
  for (; rel < relend; rel++)
    {
      int r_type;
      arelent arel;
      reloc_howto_type *howto;
      unsigned long r_symndx;
      Elf_Internal_Sym *sym;
      asection *sec;
      bfd_vma relocation = 0;
      bfd_reloc_status_type r = bfd_reloc_undefined;
      bfd_vma phys_page;
      bfd_vma phys_addr;
      bfd_vma insn_addr;
      bfd_vma insn_page;
      bfd_boolean is_far = FALSE;
      struct elf_link_hash_entry *h;
      const char* stub_name = 0;

      r_symndx = ELF32_R_SYM (rel->r_info);
      r_type = ELF32_R_TYPE (rel->r_info);

      if (r_type == R_M68HC11_GNU_VTENTRY
          || r_type == R_M68HC11_GNU_VTINHERIT )
        continue;

      (*ebd->elf_info_to_howto_rel) (input_bfd, &arel, rel);
      howto = arel.howto;

      h = NULL;
      sym = NULL;
      sec = NULL;
      if (r_symndx < symtab_hdr->sh_info)
	{
	  sym = local_syms + r_symndx;
	  sec = local_sections[r_symndx];
	  relocation = (sec->output_section->vma
			+ sec->output_offset
			+ sym->st_value);
	  is_far = (sym && (sym->st_other & STO_M68HC12_FAR));
	  if (is_far)
	    stub_name = (bfd_elf_string_from_elf_section
			 (input_bfd, symtab_hdr->sh_link,
			  sym->st_name));
	}
      else
	{
	  bfd_boolean unresolved_reloc, warned;

	  RELOC_FOR_GLOBAL_SYMBOL (info, input_bfd, input_section, rel,
				   r_symndx, symtab_hdr, sym_hashes,
				   h, sec, relocation, unresolved_reloc,
				   warned);

	  is_far = (h && (h->other & STO_M68HC12_FAR));
	  stub_name = h->root.root.string;
	}

      if (sec != NULL && elf_discarded_section (sec))
	{
	  /* For relocs against symbols from removed linkonce sections,
	     or sections discarded by a linker script, we just want the
	     section contents zeroed.  Avoid any special processing.  */
	  _bfd_clear_contents (howto, input_bfd, contents + rel->r_offset);
	  rel->r_info = 0;
	  rel->r_addend = 0;
	  continue;
	}

      if (info->relocatable)
	{
	  /* This is a relocatable link.  We don't have to change
	     anything, unless the reloc is against a section symbol,
	     in which case we have to adjust according to where the
	     section symbol winds up in the output section.  */
	  if (sym != NULL && ELF_ST_TYPE (sym->st_info) == STT_SECTION)
	    rel->r_addend += sec->output_offset;
	  continue;
	}

      if (h != NULL)
	name = h->root.root.string;
      else
	{
	  name = (bfd_elf_string_from_elf_section
		  (input_bfd, symtab_hdr->sh_link, sym->st_name));
	  if (name == NULL || *name == '\0')
	    name = bfd_section_name (input_bfd, sec);
	}

      if (is_far && ELF32_R_TYPE (rel->r_info) == R_M68HC11_16)
	{
	  struct elf32_m9s12xg_stub_hash_entry* stub;
	  struct m9s12xg_elf_link_hash_table *htab;

	  htab = m9s12xg_elf_hash_table (info);
	  stub = m9s12xg_stub_hash_lookup (htab->stub_hash_table,
					   name, FALSE, FALSE);
	  if (stub)
	    {
	      relocation = stub->stub_offset
		+ stub->stub_sec->output_section->vma
		+ stub->stub_sec->output_offset;
	      is_far = FALSE;
	    }
	}

      /* Do the memory bank mapping.  */
      phys_addr = m9s12xg_phys_addr (pinfo, relocation + rel->r_addend);
      phys_page = m9s12xg_phys_page (pinfo, relocation + rel->r_addend);
      switch (r_type)
        {
        case R_M68HC11_24:
          /* Reloc used by 68HC12 call instruction.  */
          bfd_put_16 (input_bfd, phys_addr,
                      (bfd_byte*) contents + rel->r_offset);
          bfd_put_8 (input_bfd, phys_page,
                     (bfd_byte*) contents + rel->r_offset + 2);
          r = bfd_reloc_ok;
          r_type = R_M68HC11_NONE;
          break;

        case R_M68HC11_NONE:
          r = bfd_reloc_ok;
          break;

        case R_M68HC11_LO16:
          /* Reloc generated by %addr(expr) gas to obtain the
             address as mapped in the memory bank window.  */
          relocation = phys_addr;
          break;

        case R_M68HC11_PAGE:
          /* Reloc generated by %page(expr) gas to obtain the
             page number associated with the address.  */
          relocation = phys_page;
          break;

        case R_M68HC11_16:
          /* Get virtual address of instruction having the relocation.  */
          if (is_far)
            {
              const char* msg;
              char* buf;
              msg = _("Reference to the far symbol `%s' using a wrong "
                      "relocation may result in incorrect execution");
              buf = alloca (strlen (msg) + strlen (name) + 10);
              sprintf (buf, msg, name);
              
              (* info->callbacks->warning)
                (info, buf, name, input_bfd, NULL, rel->r_offset);
            }

          /* Get virtual address of instruction having the relocation.  */
          insn_addr = input_section->output_section->vma
            + input_section->output_offset
            + rel->r_offset;

          insn_page = m9s12xg_phys_page (pinfo, insn_addr);

          if (m9s12xg_addr_is_banked (pinfo, relocation + rel->r_addend)
              && m9s12xg_addr_is_banked (pinfo, insn_addr)
              && phys_page != insn_page)
            {
              const char* msg;
              char* buf;

              msg = _("banked address [%lx:%04lx] (%lx) is not in the same bank "
                      "as current banked address [%lx:%04lx] (%lx)");

              buf = alloca (strlen (msg) + 128);
              sprintf (buf, msg, phys_page, phys_addr,
                       (long) (relocation + rel->r_addend),
                       insn_page, m9s12xg_phys_addr (pinfo, insn_addr),
                       (long) (insn_addr));
              if (!((*info->callbacks->warning)
                    (info, buf, name, input_bfd, input_section,
                     rel->r_offset)))
                return FALSE;
              break;
            }
          if (phys_page != 0 && insn_page == 0)
            {
              const char* msg;
              char* buf;

              msg = _("reference to a banked address [%lx:%04lx] in the "
                      "normal address space at %04lx");

              buf = alloca (strlen (msg) + 128);
              sprintf (buf, msg, phys_page, phys_addr, insn_addr);
              if (!((*info->callbacks->warning)
                    (info, buf, name, input_bfd, input_section,
                     insn_addr)))
                return FALSE;

              relocation = phys_addr;
              break;
            }

          /* If this is a banked address use the phys_addr so that
             we stay in the banked window.  */
          if (m9s12xg_addr_is_banked (pinfo, relocation + rel->r_addend))
            relocation = phys_addr;
          break;
        }
      if (r_type != R_M68HC11_NONE)
        r = _bfd_final_link_relocate (howto, input_bfd, input_section,
                                      contents, rel->r_offset,
                                      relocation, rel->r_addend);

      if (r != bfd_reloc_ok)
	{
	  const char * msg = (const char *) 0;

	  switch (r)
	    {
	    case bfd_reloc_overflow:
	      if (!((*info->callbacks->reloc_overflow)
		    (info, NULL, name, howto->name, (bfd_vma) 0,
		     input_bfd, input_section, rel->r_offset)))
		return FALSE;
	      break;

	    case bfd_reloc_undefined:
	      if (!((*info->callbacks->undefined_symbol)
		    (info, name, input_bfd, input_section,
		     rel->r_offset, TRUE)))
		return FALSE;
	      break;

	    case bfd_reloc_outofrange:
	      msg = _ ("internal error: out of range error");
	      goto common_error;

	    case bfd_reloc_notsupported:
	      msg = _ ("internal error: unsupported relocation error");
	      goto common_error;

	    case bfd_reloc_dangerous:
	      msg = _ ("internal error: dangerous error");
	      goto common_error;

	    default:
	      msg = _ ("internal error: unknown error");
	      /* fall through */

	    common_error:
	      if (!((*info->callbacks->warning)
		    (info, msg, name, input_bfd, input_section,
		     rel->r_offset)))
		return FALSE;
	      break;
	    }
	}
    }

  return TRUE;
}

/* Merge backend specific data from an object file to the output
   object file when linking.  */

bfd_boolean
_bfd_m9s12xg_elf_merge_private_bfd_data (bfd *ibfd, bfd *obfd)
{
  flagword old_flags;
  flagword new_flags;
  bfd_boolean ok = TRUE;

  /* Check if we have the same endianess */
  if (!_bfd_generic_verify_endian_match (ibfd, obfd))
    return FALSE;

  if (bfd_get_flavour (ibfd) != bfd_target_elf_flavour
      || bfd_get_flavour (obfd) != bfd_target_elf_flavour)
    return TRUE;

  new_flags = elf_elfheader (ibfd)->e_flags;
  elf_elfheader (obfd)->e_flags |= new_flags & EF_M9S12XG_ABI;
  old_flags = elf_elfheader (obfd)->e_flags;

  if (! elf_flags_init (obfd))
    {
      elf_flags_init (obfd) = TRUE;
      elf_elfheader (obfd)->e_flags = new_flags;
      elf_elfheader (obfd)->e_ident[EI_CLASS]
	= elf_elfheader (ibfd)->e_ident[EI_CLASS];

      if (bfd_get_arch (obfd) == bfd_get_arch (ibfd)
	  && bfd_get_arch_info (obfd)->the_default)
	{
	  if (! bfd_set_arch_mach (obfd, bfd_get_arch (ibfd),
				   bfd_get_mach (ibfd)))
	    return FALSE;
	}

      return TRUE;
    }

  /* Check ABI compatibility.  */
  if ((new_flags & E_M9S12XG_I32) != (old_flags & E_M9S12XG_I32))
    {
      (*_bfd_error_handler)
	(_("%B: linking files compiled for 16-bit integers (-mshort) "
           "and others for 32-bit integers"), ibfd);
      ok = FALSE;
    }
  if ((new_flags & E_M9S12XG_F64) != (old_flags & E_M9S12XG_F64))
    {
      (*_bfd_error_handler)
	(_("%B: linking files compiled for 32-bit double (-fshort-double) "
           "and others for 64-bit double"), ibfd);
      ok = FALSE;
    }

  /* Processor compatibility.  */
  if (!EF_M9S12XG_CAN_MERGE_MACH (new_flags, old_flags))
    {
      (*_bfd_error_handler)
	(_("%B: linking files compiled for HCS12 with "
           "others compiled for HC12"), ibfd);
      ok = FALSE;
    }
  new_flags = ((new_flags & ~EF_M9S12XG_MACH_MASK)
               | (EF_M9S12XG_MERGE_MACH (new_flags, old_flags)));

  elf_elfheader (obfd)->e_flags = new_flags;

  new_flags &= ~(EF_M9S12XG_ABI | EF_M9S12XG_MACH_MASK);
  old_flags &= ~(EF_M9S12XG_ABI | EF_M9S12XG_MACH_MASK);

  /* Warn about any other mismatches */
  if (new_flags != old_flags)
    {
      (*_bfd_error_handler)
	(_("%B: uses different e_flags (0x%lx) fields than previous modules (0x%lx)"),
	 ibfd, (unsigned long) new_flags, (unsigned long) old_flags);
      ok = FALSE;
    }

  if (! ok)
    {
      bfd_set_error (bfd_error_bad_value);
      return FALSE;
    }

  return TRUE;
}

bfd_boolean
_bfd_m9s12xg_elf_print_private_bfd_data (bfd *abfd, void *ptr)
{
  FILE *file = (FILE *) ptr;

  BFD_ASSERT (abfd != NULL && ptr != NULL);

  /* Print normal ELF private data.  */
  _bfd_elf_print_private_bfd_data (abfd, ptr);

  /* xgettext:c-format */
  fprintf (file, _("private flags = %lx:"), elf_elfheader (abfd)->e_flags);

  if (elf_elfheader (abfd)->e_flags & E_M9S12XG_I32)
    fprintf (file, _("[abi=32-bit int, "));
  else
    fprintf (file, _("[abi=16-bit int, "));

  if (elf_elfheader (abfd)->e_flags & E_M9S12XG_F64)
    fprintf (file, _("64-bit double, "));
  else
    fprintf (file, _("32-bit double, "));

  if (strcmp (bfd_get_target (abfd), "elf32-m68hc11") == 0)
    fprintf (file, _("cpu=HC11]"));
  else if (strcmp (bfd_get_target (abfd), "elf32-m9s12xg") == 0)
    fprintf (file, _("cpu=M9S12XG]"));
  else if (elf_elfheader (abfd)->e_flags & EF_M68HCS12_MACH)
    fprintf (file, _("cpu=HCS12]"));
  else
    fprintf (file, _("cpu=HC12]"));    

  if (elf_elfheader (abfd)->e_flags & E_M68HC12_BANKS)
    fprintf (file, _(" [memory=bank-model]"));
  else
    fprintf (file, _(" [memory=flat]"));

  fputc ('\n', file);

  return TRUE;
}

/* Set and control ELF flags in ELF header.  */

bfd_boolean
_bfd_m9s12xg_elf_set_private_flags (bfd *abfd, flagword flags)
{
  BFD_ASSERT (!elf_flags_init (abfd)
	      || elf_elfheader (abfd)->e_flags == flags);

  elf_elfheader (abfd)->e_flags = flags;
  elf_flags_init (abfd) = TRUE;
  return TRUE;
}

/* This function is used for relocs which are only used for relaxing,
   which the linker should otherwise ignore.  */

bfd_reloc_status_type
m9s12xg_elf_ignore_reloc (bfd *abfd ATTRIBUTE_UNUSED,
                          arelent *reloc_entry,
                          asymbol *symbol ATTRIBUTE_UNUSED,
                          void *data ATTRIBUTE_UNUSED,
                          asection *input_section,
                          bfd *output_bfd,
                          char **error_message ATTRIBUTE_UNUSED)
{
  if (output_bfd != NULL)
    reloc_entry->address += input_section->output_offset;
  return bfd_reloc_ok;
}

/* Return 1 if the address is in banked memory.
   This can be applied to a virtual address and to a physical address.  */
int
m9s12xg_addr_is_banked (struct m9s12xg_page_info *pinfo, bfd_vma addr)
{
  if (addr >= pinfo->bank_virtual)
    return 1;

  if (addr >= pinfo->bank_physical && addr <= pinfo->bank_physical_end)
    return 1;

  return 0;
}

void
m9s12xg_elf_get_bank_parameters (struct bfd_link_info *info)
{
  unsigned i;
  struct m9s12xg_page_info *pinfo;
  struct bfd_link_hash_entry *h;

  pinfo = &m9s12xg_elf_hash_table (info)->pinfo;
  if (pinfo->bank_param_initialized)
    return;

  pinfo->bank_virtual = M68HC12_BANK_VIRT;
  pinfo->bank_mask = M68HC12_BANK_MASK;
  pinfo->bank_physical = M68HC12_BANK_BASE;
  pinfo->bank_shift = M68HC12_BANK_SHIFT;
  pinfo->bank_size = 1 << M68HC12_BANK_SHIFT;

  h = bfd_link_hash_lookup (info->hash, BFD_M9S12XG_BANK_START_NAME,
                            FALSE, FALSE, TRUE);
  if (h != (struct bfd_link_hash_entry*) NULL
      && h->type == bfd_link_hash_defined)
    pinfo->bank_physical = (h->u.def.value
                            + h->u.def.section->output_section->vma
                            + h->u.def.section->output_offset);

  h = bfd_link_hash_lookup (info->hash, BFD_M9S12XG_BANK_VIRTUAL_NAME,
                            FALSE, FALSE, TRUE);
  if (h != (struct bfd_link_hash_entry*) NULL
      && h->type == bfd_link_hash_defined)
    pinfo->bank_virtual = (h->u.def.value
                           + h->u.def.section->output_section->vma
                           + h->u.def.section->output_offset);

  h = bfd_link_hash_lookup (info->hash, BFD_M9S12XG_BANK_SIZE_NAME,
                            FALSE, FALSE, TRUE);
  if (h != (struct bfd_link_hash_entry*) NULL
      && h->type == bfd_link_hash_defined)
    pinfo->bank_size = (h->u.def.value
                        + h->u.def.section->output_section->vma
                        + h->u.def.section->output_offset);

  pinfo->bank_shift = 0;
  for (i = pinfo->bank_size; i != 0; i >>= 1)
    pinfo->bank_shift++;
  pinfo->bank_shift--;
  pinfo->bank_mask = (1 << pinfo->bank_shift) - 1;
  pinfo->bank_physical_end = pinfo->bank_physical + pinfo->bank_size;
  pinfo->bank_param_initialized = 1;

  h = bfd_link_hash_lookup (info->hash, "__far_trampoline", FALSE,
                            FALSE, TRUE);
  if (h != (struct bfd_link_hash_entry*) NULL
      && h->type == bfd_link_hash_defined)
    pinfo->trampoline_addr = (h->u.def.value
                              + h->u.def.section->output_section->vma
                              + h->u.def.section->output_offset);
}

/* Free the derived linker hash table.  */

void
m9s12xg_elf_bfd_link_hash_table_free (struct bfd_link_hash_table *hash)
{
  struct m9s12xg_elf_link_hash_table *ret
    = (struct m9s12xg_elf_link_hash_table *) hash;

  bfd_hash_table_free (ret->stub_hash_table);
  free (ret->stub_hash_table);
  _bfd_generic_link_hash_table_free (hash);
}

/* Create a 68HC11/68HC12 ELF linker hash table.  */

struct m9s12xg_elf_link_hash_table*
m9s12xg_elf_hash_table_create (bfd *abfd)
{
  struct m9s12xg_elf_link_hash_table *ret;
  bfd_size_type amt = sizeof (struct m9s12xg_elf_link_hash_table);

  ret = (struct m9s12xg_elf_link_hash_table *) bfd_malloc (amt);
  if (ret == (struct m9s12xg_elf_link_hash_table *) NULL)
    return NULL;

  memset (ret, 0, amt);
  if (!_bfd_elf_link_hash_table_init (&ret->root, abfd,
				      _bfd_elf_link_hash_newfunc,
				      sizeof (struct elf_link_hash_entry)))
    {
      free (ret);
      return NULL;
    }

  /* Init the stub hash table too.  */
  amt = sizeof (struct bfd_hash_table);
  ret->stub_hash_table = (struct bfd_hash_table*) bfd_malloc (amt);
  if (ret->stub_hash_table == NULL)
    {
      free (ret);
      return NULL;
    }
  if (!bfd_hash_table_init (ret->stub_hash_table, stub_hash_newfunc,
			    sizeof (struct elf32_m9s12xg_stub_hash_entry)))
    return NULL;

  ret->stub_bfd = NULL;
  ret->stub_section = 0;
  ret->add_stub_section = NULL;
  ret->sym_sec.abfd = NULL;

  return ret;
}

/* Assorted hash table functions.  */

/* Initialize an entry in the stub hash table.  */

static struct bfd_hash_entry *
stub_hash_newfunc (struct bfd_hash_entry *entry, struct bfd_hash_table *table,
                   const char *string)
{
  /* Allocate the structure if it has not already been allocated by a
     subclass.  */
  if (entry == NULL)
    {
      entry = bfd_hash_allocate (table,
				 sizeof (struct elf32_m9s12xg_stub_hash_entry));
      if (entry == NULL)
	return entry;
    }

  /* Call the allocation method of the superclass.  */
  entry = bfd_hash_newfunc (entry, table, string);
  if (entry != NULL)
    {
      struct elf32_m9s12xg_stub_hash_entry *eh;

      /* Initialize the local fields.  */
      eh = (struct elf32_m9s12xg_stub_hash_entry *) entry;
      eh->stub_sec = NULL;
      eh->stub_offset = 0;
      eh->target_value = 0;
      eh->target_section = NULL;
    }

  return entry;
}

/* Determine and set the size of the stub section for a final link.

   The basic idea here is to examine all the relocations looking for
   PC-relative calls to a target that is unreachable with a "bl"
   instruction.  */

bfd_boolean
elf32_m9s12xg_size_stubs (bfd *output_bfd, bfd *stub_bfd,
                          struct bfd_link_info *info,
                          asection * (*add_stub_section) (const char*, asection*))
{
  bfd *input_bfd;
  asection *section;
  Elf_Internal_Sym *local_syms, **all_local_syms;
  unsigned int bfd_indx, bfd_count;
  bfd_size_type amt;
  asection *stub_sec;

  struct m9s12xg_elf_link_hash_table *htab = m9s12xg_elf_hash_table (info);

  /* Stash our params away.  */
  htab->stub_bfd = stub_bfd;
  htab->add_stub_section = add_stub_section;

  /* Count the number of input BFDs and find the top input section id.  */
  for (input_bfd = info->input_bfds, bfd_count = 0;
       input_bfd != NULL;
       input_bfd = input_bfd->link_next)
    {
      bfd_count += 1;
    }

  /* We want to read in symbol extension records only once.  To do this
     we need to read in the local symbols in parallel and save them for
     later use; so hold pointers to the local symbols in an array.  */
  amt = sizeof (Elf_Internal_Sym *) * bfd_count;
  all_local_syms = (Elf_Internal_Sym **) bfd_zmalloc (amt);
  if (all_local_syms == NULL)
    return FALSE;

  /* Walk over all the input BFDs, swapping in local symbols.  */
  for (input_bfd = info->input_bfds, bfd_indx = 0;
       input_bfd != NULL;
       input_bfd = input_bfd->link_next, bfd_indx++)
    {
      Elf_Internal_Shdr *symtab_hdr;

      /* We'll need the symbol table in a second.  */
      symtab_hdr = &elf_tdata (input_bfd)->symtab_hdr;
      if (symtab_hdr->sh_info == 0)
	continue;

      /* We need an array of the local symbols attached to the input bfd.  */
      local_syms = (Elf_Internal_Sym *) symtab_hdr->contents;
      if (local_syms == NULL)
	{
	  local_syms = bfd_elf_get_elf_syms (input_bfd, symtab_hdr,
					     symtab_hdr->sh_info, 0,
					     NULL, NULL, NULL);
	  /* Cache them for elf_link_input_bfd.  */
	  symtab_hdr->contents = (unsigned char *) local_syms;
	}
      if (local_syms == NULL)
        {
          free (all_local_syms);
	  return FALSE;
        }

      all_local_syms[bfd_indx] = local_syms;
    }

  for (input_bfd = info->input_bfds, bfd_indx = 0;
       input_bfd != NULL;
       input_bfd = input_bfd->link_next, bfd_indx++)
    {
      Elf_Internal_Shdr *symtab_hdr;
      Elf_Internal_Sym *local_syms;
      struct elf_link_hash_entry ** sym_hashes;

      sym_hashes = elf_sym_hashes (input_bfd);

      /* We'll need the symbol table in a second.  */
      symtab_hdr = &elf_tdata (input_bfd)->symtab_hdr;
      if (symtab_hdr->sh_info == 0)
        continue;

      local_syms = all_local_syms[bfd_indx];

      /* Walk over each section attached to the input bfd.  */
      for (section = input_bfd->sections;
           section != NULL;
           section = section->next)
        {
          Elf_Internal_Rela *internal_relocs, *irelaend, *irela;

          /* If there aren't any relocs, then there's nothing more
             to do.  */
          if ((section->flags & SEC_RELOC) == 0
              || section->reloc_count == 0)
            continue;

          /* If this section is a link-once section that will be
             discarded, then don't create any stubs.  */
          if (section->output_section == NULL
              || section->output_section->owner != output_bfd)
            continue;

          /* Get the relocs.  */
          internal_relocs
            = _bfd_elf_link_read_relocs (input_bfd, section, NULL,
					 (Elf_Internal_Rela *) NULL,
					 info->keep_memory);
          if (internal_relocs == NULL)
            goto error_ret_free_local;

          /* Now examine each relocation.  */
          irela = internal_relocs;
          irelaend = irela + section->reloc_count;
          for (; irela < irelaend; irela++)
            {
              unsigned int r_type, r_indx;
              struct elf32_m9s12xg_stub_hash_entry *stub_entry;
              asection *sym_sec;
              bfd_vma sym_value;
              struct elf_link_hash_entry *hash;
              const char *stub_name;
              Elf_Internal_Sym *sym;

              r_type = ELF32_R_TYPE (irela->r_info);

//              /* Only look at 16-bit relocs.  */
//              if (r_type != (unsigned int) R_M68HC11_16)
//                continue;

              /* Now determine the call target, its name, value,
                 section.  */
              r_indx = ELF32_R_SYM (irela->r_info);
              if (r_indx < symtab_hdr->sh_info)
                {
                  /* It's a local symbol.  */
                  Elf_Internal_Shdr *hdr;
                  bfd_boolean is_far;

                  sym = local_syms + r_indx;
                  is_far = (sym && (sym->st_other & STO_M68HC12_FAR));
                  if (!is_far)
                    continue;

                  hdr = elf_elfsections (input_bfd)[sym->st_shndx];
                  sym_sec = hdr->bfd_section;
                  stub_name = (bfd_elf_string_from_elf_section
                               (input_bfd, symtab_hdr->sh_link,
                                sym->st_name));
                  sym_value = sym->st_value;
                  hash = NULL;
                }
              else
                {
                  /* It's an external symbol.  */
                  int e_indx;

                  e_indx = r_indx - symtab_hdr->sh_info;
                  hash = (struct elf_link_hash_entry *)
                    (sym_hashes[e_indx]);

                  while (hash->root.type == bfd_link_hash_indirect
                         || hash->root.type == bfd_link_hash_warning)
                    hash = ((struct elf_link_hash_entry *)
                            hash->root.u.i.link);

                  if (hash->root.type == bfd_link_hash_defined
                      || hash->root.type == bfd_link_hash_defweak
                      || hash->root.type == bfd_link_hash_new)
                    {
                      if (!(hash->other & STO_M68HC12_FAR))
                        continue;
                    }
                  else if (hash->root.type == bfd_link_hash_undefweak)
                    {
                      continue;
                    }
                  else if (hash->root.type == bfd_link_hash_undefined)
                    {
                      continue;
                    }
                  else
                    {
                      bfd_set_error (bfd_error_bad_value);
                      goto error_ret_free_internal;
                    }
                  sym_sec = hash->root.u.def.section;
                  sym_value = hash->root.u.def.value;
                  stub_name = hash->root.root.string;
                }

              if (!stub_name)
                goto error_ret_free_internal;

              stub_entry = m9s12xg_stub_hash_lookup
                (htab->stub_hash_table,
                 stub_name,
                 FALSE, FALSE);
              if (stub_entry == NULL)
                {
                  if (add_stub_section == 0)
                    continue;

                  stub_entry = m9s12xg_add_stub (stub_name, section, htab);
                  if (stub_entry == NULL)
                    {
                    error_ret_free_internal:
                      if (elf_section_data (section)->relocs == NULL)
                        free (internal_relocs);
                      goto error_ret_free_local;
                    }
                }

              stub_entry->target_value = sym_value;
              stub_entry->target_section = sym_sec;
            }

          /* We're done with the internal relocs, free them.  */
          if (elf_section_data (section)->relocs == NULL)
            free (internal_relocs);
        }
    }

  if (add_stub_section)
    {
      /* OK, we've added some stubs.  Find out the new size of the
         stub sections.  */
      for (stub_sec = htab->stub_bfd->sections;
           stub_sec != NULL;
           stub_sec = stub_sec->next)
        {
          stub_sec->size = 0;
        }

      bfd_hash_traverse (htab->stub_hash_table, htab->size_one_stub, htab);
    }
  free (all_local_syms);
  return TRUE;

 error_ret_free_local:
  free (all_local_syms);
  return FALSE;
}

/* Build all the stubs associated with the current output file.  The
   stubs are kept in a hash table attached to the main linker hash
   table.  This function is called via m68hc12elf_finish in the
   linker.  */

bfd_boolean
elf32_m9s12xg_build_stubs (bfd *abfd, struct bfd_link_info *info)
{
  asection *stub_sec;
  struct bfd_hash_table *table;
  struct m9s12xg_elf_link_hash_table *htab;
  struct m9s12xg_scan_param param;

  m9s12xg_elf_get_bank_parameters (info);
  htab = m9s12xg_elf_hash_table (info);

  for (stub_sec = htab->stub_bfd->sections;
       stub_sec != NULL;
       stub_sec = stub_sec->next)
    {
      bfd_size_type size;

      /* Allocate memory to hold the linker stubs.  */
      size = stub_sec->size;
      stub_sec->contents = (unsigned char *) bfd_zalloc (htab->stub_bfd, size);
      if (stub_sec->contents == NULL && size != 0)
	return FALSE;
      stub_sec->size = 0;
    }

  /* Build the stubs as directed by the stub hash table.  */
  table = htab->stub_hash_table;
  bfd_hash_traverse (table, m9s12xg_elf_export_one_stub, info);
  
  /* Scan the output sections to see if we use the memory banks.
     If so, export the symbols that define how the memory banks
     are mapped.  This is used by gdb and the simulator to obtain
     the information.  It can be used by programs to burn the eprom
     at the good addresses.  */
  param.use_memory_banks = FALSE;
  param.pinfo = &htab->pinfo;
  bfd_map_over_sections (abfd, scan_sections_for_abi, &param);
  if (param.use_memory_banks)
    {
      m9s12xg_elf_set_symbol (abfd, info, BFD_M9S12XG_BANK_START_NAME,
                              htab->pinfo.bank_physical,
                              bfd_abs_section_ptr);
      m9s12xg_elf_set_symbol (abfd, info, BFD_M9S12XG_BANK_VIRTUAL_NAME,
                              htab->pinfo.bank_virtual,
                              bfd_abs_section_ptr);
      m9s12xg_elf_set_symbol (abfd, info, BFD_M9S12XG_BANK_SIZE_NAME,
                              htab->pinfo.bank_size,
                              bfd_abs_section_ptr);
    }

  return TRUE;
}

/* External entry points for sizing and building linker stubs.  */

/* Set up various things so that we can make a list of input sections
   for each output section included in the link.  Returns -1 on error,
   0 when no stubs will be needed, and 1 on success.  */

int
elf32_m9s12xg_setup_section_lists (bfd *output_bfd, struct bfd_link_info *info)
{
  bfd *input_bfd;
  unsigned int bfd_count;
  int top_id, top_index;
  asection *section;
  asection **input_list, **list;
  bfd_size_type amt;
  asection *text_section;
  struct m9s12xg_elf_link_hash_table *htab;

  htab = m9s12xg_elf_hash_table (info);

  if (htab->root.root.creator->flavour != bfd_target_elf_flavour)
    return 0;

  /* Count the number of input BFDs and find the top input section id.
     Also search for an existing ".tramp" section so that we know
     where generated trampolines must go.  Default to ".text" if we
     can't find it.  */
  htab->tramp_section = 0;
  text_section = 0;
  for (input_bfd = info->input_bfds, bfd_count = 0, top_id = 0;
       input_bfd != NULL;
       input_bfd = input_bfd->link_next)
    {
      bfd_count += 1;
      for (section = input_bfd->sections;
	   section != NULL;
	   section = section->next)
	{
          const char* name = bfd_get_section_name (input_bfd, section);

          if (!strcmp (name, ".tramp"))
            htab->tramp_section = section;

          if (!strcmp (name, ".text"))
            text_section = section;

	  if (top_id < section->id)
	    top_id = section->id;
	}
    }
  htab->bfd_count = bfd_count;
  if (htab->tramp_section == 0)
    htab->tramp_section = text_section;

  /* We can't use output_bfd->section_count here to find the top output
     section index as some sections may have been removed, and
     strip_excluded_output_sections doesn't renumber the indices.  */
  for (section = output_bfd->sections, top_index = 0;
       section != NULL;
       section = section->next)
    {
      if (top_index < section->index)
	top_index = section->index;
    }

  htab->top_index = top_index;
  amt = sizeof (asection *) * (top_index + 1);
  input_list = (asection **) bfd_malloc (amt);
  htab->input_list = input_list;
  if (input_list == NULL)
    return -1;

  /* For sections we aren't interested in, mark their entries with a
     value we can check later.  */
  list = input_list + top_index;
  do
    *list = bfd_abs_section_ptr;
  while (list-- != input_list);

  for (section = output_bfd->sections;
       section != NULL;
       section = section->next)
    {
      if ((section->flags & SEC_CODE) != 0)
	input_list[section->index] = NULL;
    }

  return 1;
}

/* Export the trampoline addresses in the symbol table.  */
static bfd_boolean
m9s12xg_elf_export_one_stub (struct bfd_hash_entry *gen_entry, void *in_arg)
{
  struct bfd_link_info *info;
  struct m9s12xg_elf_link_hash_table *htab;
  struct elf32_m9s12xg_stub_hash_entry *stub_entry;
  char* name;
  bfd_boolean result;

  info = (struct bfd_link_info *) in_arg;
  htab = m9s12xg_elf_hash_table (info);

  /* Massage our args to the form they really have.  */
  stub_entry = (struct elf32_m9s12xg_stub_hash_entry *) gen_entry;

  /* Generate the trampoline according to HC11 or HC12.  */
  result = (* htab->build_one_stub) (gen_entry, in_arg);

  /* Make a printable name that does not conflict with the real function.  */
  name = alloca (strlen (stub_entry->root.string) + 16);
  sprintf (name, "tramp.%s", stub_entry->root.string);

  /* Export the symbol for debugging/disassembling.  */
  m9s12xg_elf_set_symbol (htab->stub_bfd, info, name,
                          stub_entry->stub_offset,
                          stub_entry->stub_sec);
  return result;
}

static void scan_sections_for_abi (bfd *abfd ATTRIBUTE_UNUSED,
                                   asection *asect, void *arg)
{
  struct m9s12xg_scan_param* p = (struct m9s12xg_scan_param*) arg;

  if (asect->vma >= p->pinfo->bank_virtual)
    p->use_memory_banks = TRUE;
}

/* Export a symbol or set its value and section.  */
static void
m9s12xg_elf_set_symbol (bfd *abfd, struct bfd_link_info *info,
                        const char *name, bfd_vma value, asection *sec)
{
  struct elf_link_hash_entry *h;

  h = (struct elf_link_hash_entry *)
    bfd_link_hash_lookup (info->hash, name, FALSE, FALSE, FALSE);
  if (h == NULL)
    {
      _bfd_generic_link_add_one_symbol (info, abfd,
                                        name,
                                        BSF_GLOBAL,
                                        sec,
                                        value,
                                        (const char*) NULL,
                                        TRUE, FALSE, NULL);
    }
  else
    {
      h->root.type = bfd_link_hash_defined;
      h->root.u.def.value = value;
      h->root.u.def.section = sec;
    }
}

/* Add a new stub entry to the stub hash.  Not all fields of the new
   stub entry are initialised.  */

static struct elf32_m9s12xg_stub_hash_entry *
m9s12xg_add_stub (const char *stub_name, asection *section,
                  struct m9s12xg_elf_link_hash_table *htab)
{
  struct elf32_m9s12xg_stub_hash_entry *stub_entry;

  /* Enter this entry into the linker stub hash table.  */
  stub_entry = m9s12xg_stub_hash_lookup (htab->stub_hash_table, stub_name,
                                         TRUE, FALSE);
  if (stub_entry == NULL)
    {
      (*_bfd_error_handler) (_("%B: cannot create stub entry %s"),
			     section->owner, stub_name);
      return NULL;
    }

  if (htab->stub_section == 0)
    {
      htab->stub_section = (*htab->add_stub_section) (".tramp",
                                                      htab->tramp_section);
    }

  stub_entry->stub_sec = htab->stub_section;
  stub_entry->stub_offset = 0;
  return stub_entry;
}


/* end sections of code taken from elf32-m68hc1x.c */

#define ELF_ARCH		bfd_arch_m9s12xg
#define ELF_MACHINE_CODE	EM_M9S12XG
#define ELF_MAXPAGESIZE		0x1000

#define TARGET_BIG_SYM          bfd_elf32_m9s12xg_vec
#define TARGET_BIG_NAME		"elf32-m9s12xg"

#define elf_info_to_howto	0
#define elf_info_to_howto_rel	m9s12xg_info_to_howto_rel
#define bfd_elf32_bfd_relax_section  m9s12xg_elf_relax_section
#define elf_backend_check_relocs     elf32_m9s12xg_check_relocs
#define elf_backend_relocate_section elf32_m9s12xg_relocate_section
#define elf_backend_add_symbol_hook  elf32_m9s12xg_add_symbol_hook
#define elf_backend_object_p	0
#define elf_backend_final_write_processing	0
#define elf_backend_can_gc_sections		1
#define elf_backend_special_sections  elf32_m9s12xg_special_sections

#define bfd_elf32_bfd_link_hash_table_create \
                                m9s12xg_elf_bfd_link_hash_table_create
#define bfd_elf32_bfd_link_hash_table_free \
				m9s12xg_elf_bfd_link_hash_table_free
#define bfd_elf32_bfd_merge_private_bfd_data \
					_bfd_m9s12xg_elf_merge_private_bfd_data
#define bfd_elf32_bfd_set_private_flags	_bfd_m9s12xg_elf_set_private_flags
#define bfd_elf32_bfd_print_private_bfd_data \
					_bfd_m9s12xg_elf_print_private_bfd_data

#include "elf32-target.h"
