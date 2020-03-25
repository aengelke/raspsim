# -*- makefile -*-
#
# PTLsim: Cycle Accurate x86-64 Simulator
# Makefile
#
# Copyright 2000-2008 Matt T. Yourst <yourst@yourst.com>
#

#
# If you are running on a 64-bit distro but want to build
# a 32-bit PTLsim binary, and your distro doesn't provide
# the "linux32" or "32bit" uname-changing commands, you
# will need to manually override the checks below:
#
ifndef MACHTYPE
	MACHTYPE = "$(shell uname -m)"
endif

ifneq (,$(findstring x86_64,"$(MACHTYPE)"))
	__x86_64__=1
endif
#
# Build PTLsim/X full system simulator:
#
# Make sure you have Xen installed and have applied
# the PTLsim hypervisor patches before trying this!
#
# PTLsim/X only runs on 64-bit x86-64 host processors,
# but can still run 32-bit code and guest operating
# systems. See the manual and FAQ for details.
#
# PTLSIM_HYPERVISOR=1

# For GCC versions > 4.2 install version 4.2 and uncomment the following line:
# CC = g++-4.2
CC = g++

GCCVER_SPECIFIC =

SVNREV=$(shell svn info | grep "Last Changed Rev" | cut -d " " -f4)
SVNDATE=$(shell svn info | grep "Last Changed Date" | cut -d " " -f4)

ifeq (,$(SVNREV))
# Subversion is either not installed or the current directory isn't a PTLsim repository:
	SVNREV=0
	SVNDATE=unknown
endif

INCFLAGS = -I. -DBUILDHOST="`hostname -f`" -DSVNREV="$(SVNREV)" -DSVNDATE="$(SVNDATE)"

ifdef PTLSIM_HYPERVISOR
INCFLAGS += -DPTLSIM_HYPERVISOR -D__XEN__
endif

ifdef __x86_64__
CFLAGS = -std=gnu++03 -O99 -g -fomit-frame-pointer -pipe -march=k8 -fno-builtin -falign-functions=16 -funroll-loops -funit-at-a-time -minline-all-stringops
#CFLAGS = -O2 -g3 -march=k8 -falign-functions=16 -minline-all-stringops
# -O1 doesn't work
CFLAGS32BIT = $(CFLAGS) -m32
else
# 32-bit PTLsim32 only, on a Pentium 4:
CFLAGS = -m32 -O99 -g -fomit-frame-pointer -march=pentium4 -falign-functions=16
# No optimizations:
#CFLAGS = -O1 -g3 -march=pentium4 -mtune=k8 -falign-functions=16
CFLAGS32BIT = $(CFLAGS) 
endif

ifdef PTLSIM_HYPERVISOR
CFLAGS += -fpic -mno-red-zone
endif

CFLAGS += -fno-trapping-math -fno-stack-protector -fno-exceptions -fno-rtti -funroll-loops -mpreferred-stack-boundary=4 -fno-strict-aliasing -fno-stack-protector -Wreturn-type $(GCCVER_SPECIFIC) -D_FORTIFY_SOURCE=0



BASEOBJS = superstl.o config.o mathlib.o syscalls.o
STDOBJS = glibc.o

ifdef __x86_64__
ifdef PTLSIM_HYPERVISOR
COMMONOBJS = lowlevel-64bit-xen.o ptlsim.o ptlxen.o ptlxen-memory.o ptlxen-events.o ptlxen-common.o perfctrs.o mm.o superstl.o config.o mathlib.o klibc.o ptlhwdef.o datastore.o decode-core.o decode-fast.o decode-complex.o decode-x87.o decode-sse.o uopimpl.o seqcore.o ptlsim.dst.o
else
COMMONOBJS = lowlevel-64bit.o ptlsim.o kernel.o mm.o ptlhwdef.o decode-core.o decode-fast.o decode-complex.o decode-x87.o decode-sse.o uopimpl.o datastore.o injectcode-64bit.o seqcore.o $(BASEOBJS) klibc.o ptlsim.dst.o
endif
else
# 32-bit PTLsim32 only:
COMMONOBJS = lowlevel-32bit.o ptlsim.o kernel.o mm.o ptlhwdef.o decode-core.o decode-fast.o decode-complex.o decode-x87.o decode-sse.o uopimpl.o seqcore.o datastore.o injectcode-32bit.o $(BASEOBJS) klibc.o ptlsim.dst.o
endif

OOOOBJS = branchpred.o dcache.o ooocore.o ooopipe.o oooexec.o
OBJFILES = linkstart.o $(COMMONOBJS) $(OOOOBJS) linkend.o

COMMONINCLUDES = logic.h ptlhwdef.h decode.h seqexec.h dcache.h dcache-amd-k8.h config.h ptlsim.h datastore.h superstl.h globals.h kernel.h mm.h ptlcalls.h loader.h mathlib.h klibc.h syscalls.h ptlxen.h stats.h xen-types.h
OOOINCLUDES = branchpred.h ooocore.h ooocore-amd-k8.h
INCLUDEFILES = $(COMMONINCLUDES) $(OOOINCLUDES)

COMMONCPPFILES = ptlsim.cpp kernel.cpp mm.cpp superstl.cpp ptlhwdef.cpp decode-core.cpp decode-fast.cpp decode-complex.cpp decode-x87.cpp decode-sse.cpp lowlevel-64bit.S lowlevel-32bit.S linkstart.S linkend.S uopimpl.cpp dcache.cpp config.cpp datastore.cpp injectcode.cpp ptlcalls.c cpuid.cpp ptlstats.cpp klibc.cpp glibc.cpp mathlib.cpp syscalls.cpp makeusage.cpp

ifdef PTLSIM_HYPERVISOR
COMMONCPPFILES += lowlevel-64bit-xen.S ptlxen.cpp ptlxen-memory.cpp ptlxen-events.cpp ptlxen-common.cpp perfctrs.cpp ptlmon.cpp ptlctl.cpp
endif
OOOCPPFILES = ooocore.cpp ooopipe.cpp oooexec.cpp seqcore.cpp branchpred.cpp

CPPFILES = $(COMMONCPPFILES) $(OOOCPPFILES)

CFLAGS += -D__PTLSIM_OOO_ONLY__

TOPLEVEL = ptlsim ptlstats ptlcalls.o ptlcalls-32bit.o cpuid
ifdef PTLSIM_HYPERVISOR
TOPLEVEL += ptlctl
endif

all: $(TOPLEVEL)
	@echo "Compiled successfully..."

cpuid: cpuid.o $(BASEOBJS) $(STDOBJS)
	$(CC) $(CFLAGS) -O2 cpuid.o $(BASEOBJS) $(STDOBJS) -o cpuid

ptlstats: ptlstats.o datastore.o ptlhwdef.o $(BASEOBJS) $(STDOBJS) Makefile
	$(CC) $(CFLAGS) -g -O2 ptlstats.o datastore.o ptlhwdef.o $(BASEOBJS) $(STDOBJS) -o ptlstats

ifdef __x86_64__
injectcode-64bit.o: injectcode.cpp
	$(CC) $(CFLAGS) $(INCFLAGS) -m64 -O99 -fomit-frame-pointer -c injectcode.cpp -o injectcode-64bit.o
else
injectcode-32bit.o: injectcode.cpp
	$(CC) $(CFLAGS) $(INCFLAGS) -DPTLSIM_FORCE_32BIT_ONLY -O99 -fomit-frame-pointer -c injectcode.cpp -o injectcode-32bit.o

lowlevel-32bit.o: lowlevel-32bit.S
ifdef __x86_64__
	$(CC) -c $(CFLAGS32BIT) $(INCFLAGS) -g -O3 -Wa,--32 lowlevel-32bit.S
else
	$(CC) -c $(CFLAGS32BIT) $(INCFLAGS) -g -O3 lowlevel-32bit.S
endif
endif

ptlcalls-32bit.o: ptlcalls.c
ifdef __x86_64__
	$(CC) -c $(CFLAGS) $(INCFLAGS) $(CFLAGS32BIT) -O99 -fomit-frame-pointer -Wa,--32 ptlcalls.c -o ptlcalls-32bit.o
else
	$(CC) -c $(CFLAGS) $(INCFLAGS) $(CFLAGS32BIT) -O99 -fomit-frame-pointer ptlcalls.c -o ptlcalls-32bit.o
endif

ptlsim.dst: dstbuild stats.h ptlhwdef.h ooocore.h dcache.h branchpred.h decode.h $(BASEOBJS) $(STDOBJS) datastore.o ptlhwdef.o
	$(CC) $(CFLAGS) $(INCFLAGS) -E -C stats.h > stats.i
	cat stats.i | ./dstbuild PTLsimStats > dstbuild.temp.cpp
	$(CC) $(CFLAGS) $(INCFLAGS) -DDSTBUILD -include stats.h dstbuild.temp.cpp $(BASEOBJS) $(STDOBJS) datastore.o ptlhwdef.o -o dstbuild.temp
	./dstbuild.temp > ptlsim.dst
	rm -f dstbuild.temp destbuild.temp.cpp stats.i

makeusage: makeusage.o $(BASEOBJS) $(STDOBJS)
	$(CC) $(CFLAGS) $(INCFLAGS) $(BASEOBJS) $(STDOBJS) makeusage.o -o makeusage

ifdef __x86_64__
DATA_OBJ_TYPE = elf64-x86-64
else
DATA_OBJ_TYPE = elf32-i386
endif

usage.o: makeusage Makefile
	./makeusage > usage.txt
	objcopy -I binary -O $(DATA_OBJ_TYPE) -B i386 --rename-section .data=.usage,alloc,load,readonly,data,contents usage.txt usage.o

ptlsim.dst.o: ptlsim.dst
	objcopy -I binary -O $(DATA_OBJ_TYPE) -B i386 --rename-section .data=.dst,alloc,load,readonly,data,contents ptlsim.dst ptlsim.dst.o

ifdef PTLSIM_HYPERVISOR
ifdef __x86_64__

ptlxen.bin.debug: $(OBJFILES) Makefile ptlxen.lds
	ld -v -g -O2 $(OBJFILES) -o ptlxen.bin.debug -static --allow-multiple-definition -T ptlxen.lds `gcc -print-libgcc-file-name`

ptlxen.bin.o: ptlxen.bin.debug Makefile
	strip -o ptlxen.bin ptlxen.bin.debug
	objcopy -I binary -O $(DATA_OBJ_TYPE) -B i386 --rename-section .data=.ptlxen,alloc,load,readonly,data,contents ptlxen.bin ptlxen.bin.o
#	rm -f ptlxen.bin

endif
endif

ifdef __x86_64__
ifdef PTLSIM_HYPERVISOR
ptlsim: ptlmon.o ptlxen.bin.o usage.o $(BASEOBJS) $(STDOBJS) ptlxen-common.o ptlhwdef.o ptlmon.lds Makefile
	$(CC) $(CFLAGS) ptlmon.o ptlxen.bin.o usage.o $(BASEOBJS) $(STDOBJS) ptlxen-common.o ptlhwdef.o -lxenctrl -lxenguest -lxenstore -lstdc++ -lpthread -Wl,-T,ptlmon.lds -static -o ptlsim
else
ptlsim: $(OBJFILES) Makefile
	$(CC) -nostdlib $(OBJFILES) -o ptlsim $(LIBPERFCTR) -static -static-libgcc -Wl,-Ttext-segment,0x70000000 -Wl,--allow-multiple-definition -e ptlsim_preinit_entry
endif # PTLSIM_HYPERVISOR
else
ptlsim: $(OBJFILES) Makefile ptlsim32.lds
	ld --oformat=elf32-i386 -melf_i386 -g -O2 $(OBJFILES) -o ptlsim $(LIBPERFCTR) -static --allow-multiple-definition -T ptlsim32.lds -e ptlsim_preinit_entry `gcc -m32 -print-libgcc-file-name`
endif

ptlctl: ptlctl.o $(BASEOBJS) $(STDOBJS)
	g++ $(CFLAGS) -O2 ptlctl.o $(BASEOBJS) $(STDOBJS) -o ptlctl

BASEADDR = 0

test.dat-64bit.S: test.dat Makefile
	objdump --adjust-vma=$(BASEADDR) -rtd -b binary -m i386:x86-64:intel --disassemble-all test.dat > test.dat-64bit.S
	objdump --adjust-vma=$(BASEADDR) -rtd -b binary -m i386:x86-64 --disassemble-all test.dat > test.dat-64bit.alt.S

test.dat-32bit.S: test.dat Makefile
	objdump --adjust-vma=$(BASEADDR) -rtd -b binary -m i386:intel --disassemble-all test.dat > test.dat-32bit.S
	objdump --adjust-vma=$(BASEADDR) -rtd -b binary -m i386 --disassemble-all test.dat > test.dat-32bit.alt.S

%.o: %.cpp
	$(CC) $(CFLAGS) $(INCFLAGS) -c $<

%.o: %.S
	$(CC) $(CFLAGS) $(INCFLAGS) -c $<

%.o: %.c
	$(CC) $(CFLAGS) $(INCFLAGS) -c $<

clean:
	rm -fv ptlsim ptlstats ptlctl ptlxen.bin ptlxen.bin.debug usage.txt cpuid ptlsim.dst dstbuild.temp dstbuild.temp.cpp stats.i makeusage *.o core core.[0-9]* .depend *.gch

OBJFILES = linkstart.o $(COMMONOBJS) $(PT2XOBJS) $(OOOOBJS) linkend.o
INCLUDEFILES = $(COMMONINCLUDES) $(PT2XINCLUDES) $(OOOINCLUDES)
CPPFILES = $(COMMONCPPFILES) $(PT2XCPPFILES) $(OOOCPPFILES)

#
# Miscellaneous:
#

DISTFILES = $(CPPFILES) $(INCLUDEFILES) Makefile *.lds dstbuild COPYING README

dist: $(DISTFILES)
	tar zcvf ptlsim-`date "+%Y%m%d%H%M%S"`.tar.gz $(DISTFILES)

backup: dist

distfiles: $(DISTFILES)
	@echo $(DISTFILES)

.depend:
	$(CC) $(CFLAGS) $(INCFLAGS) -MM $(CPPFILES) $(ASMFILES) > .depend

-include .depend

