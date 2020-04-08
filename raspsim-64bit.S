/*
 * PTLsim: Cycle Accurate x86-64 Simulator
 * RASPsim low level functions
 *
 * Copyright 2020-2020 Alexis Engelke <engelke@in.tum.de>
 */

.text
.intel_syntax

.global raspsim_entry
raspsim_entry:
  # Put argc, argv, etc. into arg registers
  mov   %rdi,[%rsp + 0*8]    # argc
  lea   %rsi,[%rsp + 1*8]    # argv[]
  call  main                 #
  int3                       # (main never returns)
