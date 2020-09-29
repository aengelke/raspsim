/*
 * PTLsim: Cycle Accurate x86-64 Simulator
 * 64-bit low level functions
 *
 * Copyright 2003-2008 Matt T. Yourst <yourst@yourst.com>
 */

.text
.intel_syntax

#define __ASM_ONLY__
#include <ptlhwdef.h>

.section .ctors
.global __CTOR_LIST__
__CTOR_LIST__:
.previous

.extern ctx

.extern stack_min_addr

.extern x87state
.extern saved_cs
.extern saved_ss
.extern saved_ds
.extern saved_es
.extern saved_fs
.extern saved_gs

.global ptlsim_preinit_entry
ptlsim_preinit_entry:
  #
  # We may be a 64-bit process running in a 32-bit address space,
  # which means argv, argc, etc. will be in 32-bit format and need
  # to be converted before any initialization routines.
  #

  fxsave x87state

  mov   word ptr [saved_cs],%cs
  mov   word ptr [saved_ss],%ss
  mov   word ptr [saved_ds],%ds
  mov   word ptr [saved_es],%es
  mov   word ptr [saved_fs],%fs
  mov   word ptr [saved_gs],%gs

  mov   byte ptr [running_in_sim_mode],1
  mov   %rdi,%rsp            # origrsp
  mov   %rsi,offset main     # next_init_func
  call  ptlsim_preinit
  test  byte ptr [inside_ptlsim],1
  jnz   1f
  # Not inside PTLsim: just call main() directly (no stack switch)

  # Put argc, argv, etc. into arg registers
  mov   %rdi,[%rsp + 0*8]    # argc
  lea   %rsi,[%rsp + 1*8]    # argv[]
  call  main                 #
  int3                       # (main never returns)
1:

  mov   %rbp,%rax            # update to new stack pointer

  /*
   * Give user thread a really big stack by accessing memory
   * below the grows-down stack object. We have to do this
   * now since PTLsim has no concept of grow down auto allocate
   * stacks and will just throw erroneous page faults unless
   * the stack pages are already visible to mqueryall().
   */
  xor   %eax,%eax
  mov   %rsi,[stack_min_addr]
1:
  sub   %rsp,4096
  mov   [%rsp],%rax
  cmp   %rsp,%rsi
  jae   1b

  mov   %rsp,%rbp            # update to new stack pointer

  # Put argc, argv, etc. into arg registers
  mov   %rdi,[%rsp + 0*8]    # argc
  lea   %rsi,[%rsp + 1*8]    # argv[]

  call  main

/*
 * struct ThreadState {
 *   ThreadState* self;
 *   void* stack;
 *   ...
 * };
 */

#define ThreadState_self                              8*0
#define ThreadState_rsp                               8*1
#define ThreadState_simcall                           8*2

.extern ctx
.extern save_context_switch_to_sim
.extern x87state
.extern basetls
.extern running_in_sim_mode

.global save_context_switch_to_sim_lowlevel
save_context_switch_to_sim_lowlevel:
  mov      byte ptr [running_in_sim_mode],1
  mov      [ctx + 8*REG_rax + 8*0],%rax
  mov      [ctx + 8*REG_rax + 8*1],%rcx
  mov      [ctx + 8*REG_rax + 8*2],%rdx
  mov      [ctx + 8*REG_rax + 8*3],%rbx
  mov      [ctx + 8*REG_rax + 8*4],%rsp
  mov      [ctx + 8*REG_rax + 8*5],%rbp
  mov      [ctx + 8*REG_rax + 8*6],%rsi
  mov      [ctx + 8*REG_rax + 8*7],%rdi
  mov      [ctx + 8*REG_rax + 8*8],%r8
  mov      [ctx + 8*REG_rax + 8*9],%r9
  mov      [ctx + 8*REG_rax + 8*10],%r10
  mov      [ctx + 8*REG_rax + 8*11],%r11
  mov      [ctx + 8*REG_rax + 8*12],%r12
  mov      [ctx + 8*REG_rax + 8*13],%r13
  mov      [ctx + 8*REG_rax + 8*14],%r14
  mov      [ctx + 8*REG_rax + 8*15],%r15

  mov      %rax,[%rsp]                           # Get return %rip (if we got here through a CALL insn)
  mov      [ctx + 8*REG_rip],%rax                # Save %rip
  mov      %rsp,[basetls + ThreadState_rsp]      # Switch to private thread stack

  pushfq                                         # Save rflags
  pop      qword ptr [ctx + 8*REG_flags + 8]     # Put flags into structure

  # (skip tr0/tr1/tr2)
  mov      qword ptr [ctx + 8*REG_zero],0        # Save %zero

  and      %rsp,-16

  fxsave x87state

  mov   word ptr [saved_cs],%cs
  mov   word ptr [saved_ss],%ss
  mov   word ptr [saved_ds],%ds
  mov   word ptr [saved_es],%es
  mov   word ptr [saved_fs],%fs
  mov   word ptr [saved_gs],%gs

  sub      %rsp,64
  and      %rsp,-16
  call     save_context_switch_to_sim

.data
switch_to_native_restore_context_temp_64_to_64:
  .quad 0

switch_to_native_restore_context_temp_64_to_32:
  .long 0
  .word 0x23   # selector for 32-bit x86 code

switch_to_native_restore_context_temp_64_or_32_func:
  .quad 0

.previous

# extern "C" void switch_to_native_restore_context_lowlevel(const UserContext& ctx, int switch_64_to_32);
# %rdi = ctx
# %rsi = switch_64_to_32
.global switch_to_native_restore_context_lowlevel
switch_to_native_restore_context_lowlevel:
  # Calling convention:
  # %rdi = pointer to state to restore
  # %rsi = set if switching from 64-bit to 32-bit mode

  fxrstor  x87state

  mov      %rcx,offset switch_to_native_restore_context_64_to_64
  mov      %rdx,offset switch_to_native_restore_context_64_to_32
  test     %rsi,1 # Is user thread 64-bit?
  cmovnz   %rcx,%rdx
  # Only overwrite seg regs if going back to 32-bit (behavior specific to Intel x86-64 implementation)
  jz       1f
  mov      %fs,word ptr [saved_fs]
  mov      %gs,word ptr [saved_gs]
1:

  mov      [switch_to_native_restore_context_temp_64_or_32_func],%rcx

  mov      %rax,[%rdi + 8*REG_rip]        # Load %rip
  mov      [switch_to_native_restore_context_temp_64_to_64],%rax  # Save %rip for final jump
  mov      [switch_to_native_restore_context_temp_64_to_32],%eax  # Save %rip for final jump

  lea      %rsp,[%rdi + 8*REG_flags]      # Load address of flags
  popfq                                   # Restore flags
  mov      %rsp,[%rdi + 8*REG_rsp]        # Restore user %rsp; now on user stack

  mov      %rax,[%rdi + 8*REG_rax + 8*0]
  mov      %rcx,[%rdi + 8*REG_rax + 8*1]
  mov      %rdx,[%rdi + 8*REG_rax + 8*2]
  mov      %rbx,[%rdi + 8*REG_rax + 8*3]
# mov      %rsp,[%rdi + 8*REG_rax + 8*4]              # (already done)
  mov      %rbp,[%rdi + 8*REG_rax + 8*5]
  mov      %rsi,[%rdi + 8*REG_rax + 8*6]
# mov      %rdi,[%rdi + 8*REG_rax + 8*7]              # (done at very end)
  mov      %r8,[%rdi + 8*REG_rax + 8*8]
  mov      %r9,[%rdi + 8*REG_rax + 8*9]
  mov      %r10,[%rdi + 8*REG_rax + 8*10]
  mov      %r11,[%rdi + 8*REG_rax + 8*11]
  mov      %r12,[%rdi + 8*REG_rax + 8*12]
  mov      %r13,[%rdi + 8*REG_rax + 8*13]
  mov      %r14,[%rdi + 8*REG_rax + 8*14]
  mov      %r15,[%rdi + 8*REG_rax + 8*15]

  mov      %rdi,[%rdi + 8*REG_rdi]      # Restore %rdi

  jmp      qword ptr [switch_to_native_restore_context_temp_64_or_32_func]

switch_to_native_restore_context_64_to_32:
  mov  byte ptr [running_in_sim_mode],0      # store must be atomic
  jmp  fword ptr [switch_to_native_restore_context_temp_64_to_32]

switch_to_native_restore_context_64_to_64:
  mov byte ptr [running_in_sim_mode],0      # store must be atomic
  jmp qword ptr [switch_to_native_restore_context_temp_64_to_64]

.global inside_sim_escape_code_template_64bit
.global inside_sim_escape_code_template_64bit_end

inside_sim_escape_code_template_64bit:
# Pass args are already in registers: rdi rsi rdx rcx r8 r9
  # Undocumented x86 escape opcode to do PTL calls
  .byte 0x0f
  .byte 0x37
  ret
inside_sim_escape_code_template_64bit_end:

/*
 * from arch/x86_64/lib/memcpy.S
 * memcpy - Copy a memory block.
 *
 * Input:
 * rdi destination
 * rsi source
 * rdx count
 *
 * Output:
 * rax original destination
 */
.att_syntax
 	.globl __memcpy
	.globl memcpy
	.p2align 4
__memcpy:
memcpy:
	pushq %rbx
	movq %rdi,%rax

	movl %edx,%ecx
	shrl $6,%ecx
	jz .Lhandle_tail

	.p2align 4
.Lloop_64:
	decl %ecx

	movq (%rsi),%r11
	movq 8(%rsi),%r8

	movq %r11,(%rdi)
	movq %r8,1*8(%rdi)

	movq 2*8(%rsi),%r9
	movq 3*8(%rsi),%r10

	movq %r9,2*8(%rdi)
	movq %r10,3*8(%rdi)

	movq 4*8(%rsi),%r11
	movq 5*8(%rsi),%r8

	movq %r11,4*8(%rdi)
	movq %r8,5*8(%rdi)

	movq 6*8(%rsi),%r9
	movq 7*8(%rsi),%r10

	movq %r9,6*8(%rdi)
	movq %r10,7*8(%rdi)

	leaq 64(%rsi),%rsi
	leaq 64(%rdi),%rdi
	jnz  .Lloop_64

.Lhandle_tail:
	movl %edx,%ecx
	andl $63,%ecx
	shrl $3,%ecx
	jz   .Lhandle_7
	.p2align 4
.Lloop_8:
	decl %ecx
	movq (%rsi),%r8
	movq %r8,(%rdi)
	leaq 8(%rdi),%rdi
	leaq 8(%rsi),%rsi
	jnz  .Lloop_8

.Lhandle_7:
	movl %edx,%ecx
	andl $7,%ecx
	jz .Lende
	.p2align 4
.Lloop_1:
	movb (%rsi),%r8b
	movb %r8b,(%rdi)
	incq %rdi
	incq %rsi
	decl %ecx
	jnz .Lloop_1

.Lende:
	popq %rbx
	ret
.Lfinal:
.intel_syntax
