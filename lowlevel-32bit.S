/*
 * PTLsim: Cycle Accurate x86-64 Simulator
 * 32-bit low level functions
 *
 * Copyright 2003-2008 Matt T. Yourst <yourst@yourst.com>
 */

.text
.intel_syntax

.global inside_sim_escape_code_template_32bit
.global inside_sim_escape_code_template_32bit_end

inside_sim_escape_code_template_32bit:
# Pass args in registers: rdi rsi rdx rcx r8 r9
  push    %edi
  push    %esi
  push    %edx
  push    %ecx

  mov     %edi,[%esp+(4+1)*4 + 0*8]
  mov     %esi,[%esp+(4+1)*4 + 1*8]
  mov     %edx,[%esp+(4+1)*4 + 2*8]
  mov     %ecx,[%esp+(4+1)*4 + 3*8]

  # Undocumented x86 escape opcode to do PTL calls
  .byte 0x0f
  .byte 0x37

  pop     %ecx
  pop     %edx
  pop     %esi
  pop     %edi
  ret
inside_sim_escape_code_template_32bit_end:

#ifndef __x86_64__
/*
 * PTLsim32 32-bit entry code
 */

#define __ASM_ONLY__
#include <ptlhwdef.h>

.extern ptlsim_init

.extern stack_min_addr
.extern inside_ptlsim

.global ptlsim_preinit_entry
ptlsim_preinit_entry:
  fxsave x87state
  mov   word ptr [saved_cs],%cs
  mov   word ptr [saved_ss],%ss
  mov   word ptr [saved_ds],%ds
  mov   word ptr [saved_es],%es
  mov   word ptr [saved_fs],%fs
  mov   word ptr [saved_gs],%gs

  mov   byte ptr [running_in_sim_mode],1
  mov   %eax,%esp       # origrsp
  push  offset main     # next_init_func
  push  %eax
  call  ptlsim_preinit
  add   %esp,8
  test  byte ptr [inside_ptlsim],1
  jnz   1f

  # All args (argc, argv) already on stack on x86-32:
  mov   %eax,[%esp]          # argc
  lea   %ebx,[%esp+4]        # argv
  push  %ebx
  push  %eax
  call  main                 #
  int3                       # (main never returns)
1:

  mov   %ebp,%eax            # save new PTL private stack pointer

  /*
   * Give user thread a really big stack by accessing memory
   * below the grows-down stack object. We have to do this
   * now since PTLsim has no concept of grow down auto allocate
   * stacks and will just throw erroneous page faults unless
   * the stack pages are already visible to mqueryall().
   */

  xor   %eax,%eax
  mov   %esi,[stack_min_addr]
1:
  sub   %esp,4096
  mov   [%esp],%eax
  cmp   %esp,%esi
  jae   1b

  mov   %esp,%ebp            # update to new stack pointer
  mov   %eax,[%esp]          # argc
  lea   %ebx,[%esp+4]        # argv
  push  %ebx
  push  %eax
  call  main

/*
 * struct ThreadState {
 *   ThreadState* self;
 *   void* stack;
 *   ...
 * };
 */

#define ThreadState_self                              4*0
#define ThreadState_rsp                               4*1
#define ThreadState_simcall                           4*2

.extern ctx
.extern save_context_switch_to_sim
.extern x87state
.extern basetls
.extern running_in_sim_mode

.data
.global saved_fsreg
saved_fsreg:
  .word 0

.global saved_gsreg
saved_gsreg:
  .word 0
.previous

.global save_context_switch_to_sim_lowlevel
save_context_switch_to_sim_lowlevel:
  mov      byte ptr [running_in_sim_mode],1      # store must be atomic
  mov      [ctx + 8*REG_rax + 8*0],%eax
  mov      [ctx + 8*REG_rax + 8*1],%ecx
  mov      [ctx + 8*REG_rax + 8*2],%edx
  mov      [ctx + 8*REG_rax + 8*3],%ebx
  mov      [ctx + 8*REG_rax + 8*4],%esp
  mov      [ctx + 8*REG_rax + 8*5],%ebp
  mov      [ctx + 8*REG_rax + 8*6],%esi
  mov      [ctx + 8*REG_rax + 8*7],%edi

  mov      dword ptr [ctx + 8*REG_rax + 8*0 + 4],0
  mov      dword ptr [ctx + 8*REG_rax + 8*1 + 4],0
  mov      dword ptr [ctx + 8*REG_rax + 8*2 + 4],0
  mov      dword ptr [ctx + 8*REG_rax + 8*3 + 4],0
  mov      dword ptr [ctx + 8*REG_rax + 8*4 + 4],0
  mov      dword ptr [ctx + 8*REG_rax + 8*5 + 4],0
  mov      dword ptr [ctx + 8*REG_rax + 8*6 + 4],0
  mov      dword ptr [ctx + 8*REG_rax + 8*7 + 4],0

  mov      %eax,[%esp]                           # Get return %rip (if we got here through a CALL insn)
  mov      [ctx + 8*REG_rip],%eax                # Save %rip
  mov      dword ptr [ctx + 8*REG_rip + 4],0

  mov      %esp,[basetls + ThreadState_rsp]      # Switch to private thread stack

  pushfd                                         # Save rflags
  pop      dword ptr [ctx + 8*REG_flags + 8]     # Put flags into structure

  # (skip tr0/tr1/tr2)
  mov      dword ptr [ctx + 8*REG_zero],0        # Save %zero

  and      %esp,-16

  fxsave x87state

  mov   word ptr [saved_cs],%cs
  mov   word ptr [saved_ss],%ss
  mov   word ptr [saved_ds],%ds
  mov   word ptr [saved_es],%es
  mov   word ptr [saved_fs],%fs
  mov   word ptr [saved_gs],%gs

  sub      %esp,4                                # Realign stack
  jmp      save_context_switch_to_sim

.data

switch_to_native_restore_context_temp_32_to_32:
  .long 0

.previous

# extern "C" void switch_to_native_restore_context_lowlevel(const UserContext& ctx, int switch_64_to_32);
# %rdi = ctx
# %rsi = switch_64_to_32
.global switch_to_native_restore_context_lowlevel
switch_to_native_restore_context_lowlevel:
  # Calling convention:
  # %rdi = pointer to state to restore
  mov      %edi,[%esp + 4 + 0*4] # get arg 0 (pointer to state to restore)

  mov      %eax,[%edi + 8*REG_rip]        # Load %rip
  mov      [switch_to_native_restore_context_temp_32_to_32],%eax  # Save %rip for final jump

  lea      %esp,[%edi + 8*REG_flags]      # Load address of flags
  popfd                                   # Restore flags
  mov      %esp,[%edi + 8*REG_rsp]        # Restore user %esp; now on user stack

  mov      %eax,[%edi + 8*REG_rax + 8*0]
  mov      %ecx,[%edi + 8*REG_rax + 8*1]
  mov      %edx,[%edi + 8*REG_rax + 8*2]
  mov      %ebx,[%edi + 8*REG_rax + 8*3]
# mov      %esp,[%edi + 8*REG_rax + 8*4]              # (already done)
  mov      %ebp,[%edi + 8*REG_rax + 8*5]
  mov      %esi,[%edi + 8*REG_rax + 8*6]
# mov      %edi,[%edi + 8*REG_rax + 8*7]              # (done at very end)

# mov      %rip,[%edi + 8*REG_rip]      # (do later)
# mov      %rflags,[%edi + 8*REG_flags] # (already done)
  # (No need to restore %tr0, %tr1, %tr2, %zero

  fxrstor  x87state

  mov      %fs,word ptr [saved_fs]
  mov      %gs,word ptr [saved_gs]

  mov      %edi,[%edi + 8*REG_rdi]      # Restore %rdi

  mov      byte ptr [running_in_sim_mode],0      # store must be atomic
  jmp      dword ptr [switch_to_native_restore_context_temp_32_to_32]

#endif

.end
