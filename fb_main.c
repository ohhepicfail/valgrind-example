
/*--------------------------------------------------------------------*/
/*--- Nulgrind: The minimal Valgrind tool.               fb_main.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Nulgrind, the minimal Valgrind tool,
   which does no instrumentation or analysis.

   Copyright (C) 2002-2017 Nicholas Nethercote
      njn@valgrind.org

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307, USA.

   The GNU General Public License is contained in the file COPYING.
*/

#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_debuginfo.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_options.h"
#include "pub_tool_machine.h"     // VG_(fnptr_to_fnentry)
#include "pub_tool_libcassert.h"
#include <sys/user.h>

static void fb_post_clo_init(void)
{
}

static ULong n_st  = 0;

#define MAX_INSTR_LEN 16
static ULong max_instr_len = MAX_INSTR_LEN;
static ULong instr_len[MAX_INSTR_LEN];
static ULong mem_access[PAGE_SIZE];

static void add_instr_len(int idx)
{
  tl_assert(idx < max_instr_len);
  ++instr_len[idx];
}

static void add_mem_access(ULong addr)
{
  ++mem_access[addr % PAGE_SIZE];
}

static void add_n_guest_store(int store)
{
   n_st += store;
}

static
IRSB* fb_instrument ( VgCallbackClosure* closure,
                      IRSB* sbIn,
                      const VexGuestLayout* layout,
                      const VexGuestExtents* vge,
                      const VexArchInfo* archinfo_host,
                      IRType gWordTy, IRType hWordTy )
{
   IRDirty*   di;
   Int        i;
   IRSB*      sbOut;

   /* Set up SB */
   sbOut = deepCopyIRSBExceptStmts(sbIn);

   // Copy verbatim any IR preamble preceding the first IMark
   i = 0;
   while (i < sbIn->stmts_used && sbIn->stmts[i]->tag != Ist_IMark) {
      if (sbIn->stmts[i]->tag != Ist_NoOp)
          addStmtToIRSB( sbOut, sbIn->stmts[i] );
      i++;
   }

   HWord store_cnt = 0;
   IRExpr *arg1, **argv;
   for (/*use current i*/; i < sbIn->stmts_used; i++) {
      IRStmt* st = sbIn->stmts[i];
      if (!st || st->tag == Ist_NoOp) continue;

      switch (st->tag) {
         case Ist_Store:
           {
            /* Count guest instruction. */
            store_cnt++;

            IRExpr* addr = st->Ist.Store.addr;
            argv = mkIRExprVec_1(addr);
            di = unsafeIRDirty_0_N( 1, "add_mem_access",
                                    VG_(fnptr_to_fnentry)( &add_mem_access ),
                                    argv);
            addStmtToIRSB( sbOut, IRStmt_Dirty(di) );
            break;
           }

         case Ist_IMark:
            arg1 = mkIRExpr_HWord( st->Ist.IMark.len );
            argv = mkIRExprVec_1(arg1);

            di = unsafeIRDirty_0_N( 1, "add_instr_len",
                                    VG_(fnptr_to_fnentry)( &add_instr_len ),
                                    argv);
            addStmtToIRSB( sbOut, IRStmt_Dirty(di) );

            break;

         case Ist_Exit:
            arg1 = mkIRExpr_HWord( store_cnt );
            argv = mkIRExprVec_1(arg1);

            di = unsafeIRDirty_0_N( 1, "add_n_guest_store",
                                    VG_(fnptr_to_fnentry)( &add_n_guest_store ),
                                    argv);
            addStmtToIRSB( sbOut, IRStmt_Dirty(di) );
            store_cnt = 0;
            break;
         default:
            break;
      }

      addStmtToIRSB( sbOut, st );
   }

   if (store_cnt != 0)
   {
            arg1 = mkIRExpr_HWord( store_cnt );
            argv = mkIRExprVec_1(arg1);

            di = unsafeIRDirty_0_N( 1, "add_n_guest_store",
                                    VG_(fnptr_to_fnentry)( &add_n_guest_store ),
                                    argv);
            addStmtToIRSB( sbOut, IRStmt_Dirty(di) );
   }

   return sbOut;
}

static void fb_fini(Int exitcode)
{
   VG_(umsg)("\n");
   VG_(umsg)("Executed:\n");
   VG_(umsg)("\tguest store instrs:  %'llu\n", n_st);
   VG_(umsg)("\n");

   VG_(umsg)("\tInstr len:\n");
   for (ULong i = 1; i < max_instr_len; ++i)
    VG_(umsg)("\t\tlen: %2llu  |  n: %'llu\n", i, instr_len[i]);
   VG_(umsg)("\n\tmem stores:\n");
   for (ULong i = 0; i < PAGE_SIZE; ++i)
     if (mem_access[i])
      VG_(umsg)("\t\taddr \% page_size: %4llu  | n: %'llu\n", i, mem_access[i]);
   VG_(umsg)("Exit code:       %d\n", exitcode);
}

static void fb_pre_clo_init(void)
{
   VG_(details_name)            ("Foobargrind");
   VG_(details_version)         (NULL);
   VG_(details_description)     ("the minimal Valgrind tool");
   VG_(details_copyright_author)(
      "Copyright (C) 2002-2017, and GNU GPL'd, by Nicholas Nethercote.");
   VG_(details_bug_reports_to)  (VG_BUGS_TO);

   VG_(details_avg_translation_sizeB) ( 275 );

   VG_(basic_tool_funcs)        (fb_post_clo_init,
                                 fb_instrument,
                                 fb_fini);

   /* No needs, no core events to track */
}

VG_DETERMINE_INTERFACE_VERSION(fb_pre_clo_init)

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
