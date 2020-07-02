# RASPsim

RASPsim is a cycle-accurate x86-64 simulator, forked off from PTLsim. The
`raspsim` simulator allows to configure the virtual address space and initial
register values as required, start simulation, and get back the latest register
state, requested memory dumps, and the number of cycles and instructions
simulated.

### Compile
The code can be compiled using `make` (optionally increasing parallelism) on a
recent Linux distribution. Compilation has been tested with Fedora 31.
```
make -j8
```

### Raspsim Example
This maps an empty 4k page of memory at address `0x200000`, writes some
instruction bytes at that address (`mov eax, 0x112233; int 0x80`), sets the
instruction pointer `rip` to that address. The simulation output contains the
new register state.
```
$ ./raspsim "M200000 rx" "W200000 b833221100cd80" "rip 0x200000"
[...]
Stopped after 170 cycles, 2 instructions and 0 seconds of sim time (0 Hz sim rate)
End state:
VCPU State:
  Architectural Registers:
  rax    0x0000000000112233  rcx    0x0000000000000000  rdx    0x0000000000000000  rbx    0x0000000000000000
  rsp    0x0000000000000000  rbp    0x0000000000000000  rsi    0x0000000000000000  rdi    0x0000000000000000
  r8     0x0000000000000000  r9     0x0000000000000000  r10    0x0000000000000000  r11    0x0000000000000000
  r12    0x0000000000000000  r13    0x0000000000000000  r14    0x0000000000000000  r15    0x0000000000000000
[...]
  rip    0x0000000000200007  flags  0x0000000000000000  dlend  0x0000000000000000  selfrip 0x0000000000200005
  nextrip 0x0000000000200007  ar1    0xffffffffffffff80  ar2    0x0000000000000000  zero   0x0000000000000000
[...]
```

### Raspsim commands

Raspsim is configured using command-line arguments (the `@file` syntax to read
commands from a file is supported as well). After all commands are processed,
the simulation is started. The simulation stops when either `int 0x80` is
executed or a CPU exception occurs. Syscalls are intentionally not implemented.

_Important:_ all commands, including the space, must be single arguments. Spaces
inside a configuration command must be escaped when calling the simulator from a
shell.

Supported configuration commands:

- `M<hex addr> <prot>` -- allocate a page of memory at a given (page-aligned)
  address with specified access restriction. Valid values for `prot` are `ro`,
  `rw`, `rx`. Self-modifying code is actually supported by the simulator,
  has a bug when the first executed instruction is on a writable page and raises
  an exception. Therefore, this is not exposed in the command-line.
- `W<hex addr> <hex bytes>` -- write data to a previously allocated page. The
  address does not need to be page-aligned; however, the data must not cross
  page boundaries. To write data over multiple pages, multiple write commands
  have to be used.
- `D<hex addr>` -- dump contents of a 4k page after the simulation.
- `Fnox87` -- disable x87 FPU emulation
- `Fnosse` -- disable SSE emulation
- `Fnocache` -- disable emulation of cache hierarchy, all memory accesses will
  be emulated as cache hits
- `<reg> <64-bit value>` -- set a register to a value. Valid register names are
  the 16 general-purpose registers, `rip`, and `flags`. SSE registers are split
  in _low_ and _high_ registers (each 64-bit in size) and are prefixed `xmml`
  and `xmmh`, followed by the number (0--15).

### License
This code is licensed under GPLv2 and currently maintained by
[Alexis Engelke](https://www.in.tum.de/caps/mitarbeiter/engelke/).

### Orginal PTLsim README

```
//
// PTLsim: Cycle Accurate x86-64 Simulator
//
// Copyright 2000-2008 Matt T. Yourst <yourst@yourst.com>
//

PTLsim is a state of the art cycle accurate microprocessor simulator
and virtual machine for the x86 and x86-64 instruction sets. This
release of PTLsim models a modern speculative out of order x86-64
compatible processor core, cache hierarchy and supporting hardware.

More information about PTLsim is availble at:

  http://www.ptlsim.org

To get started, please read the PTLsim User's Guide and Reference in
ptlsim/Documentation/PTLsimManual.pdf, or see our web site for other
documentation formats.

The PTLsim software and manual are free software; they are licensed
under the GNU General Public License version 2.
```
