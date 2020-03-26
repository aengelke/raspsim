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

CFLAGS += -fno-trapping-math -fno-stack-protector -fno-exceptions -fno-rtti -funroll-loops -mpreferred-stack-boundary=4 -fno-strict-aliasing -fno-stack-protector -Wreturn-type $(GCCVER_SPECIFIC) -D_FORTIFY_SOURCE=0



BASEOBJS = superstl.o config.o mathlib.o syscalls.o
STDOBJS = glibc.o

ifdef __x86_64__
COMMONOBJS = lowlevel-64bit.o ptlsim.o kernel.o mm.o ptlhwdef.o decode-core.o decode-fast.o decode-complex.o decode-x87.o decode-sse.o uopimpl.o datastore.o injectcode-64bit.o seqcore.o $(BASEOBJS) klibc.o ptlsim.dst.o
else
# 32-bit PTLsim32 only:
COMMONOBJS = lowlevel-32bit.o ptlsim.o kernel.o mm.o ptlhwdef.o decode-core.o decode-fast.o decode-complex.o decode-x87.o decode-sse.o uopimpl.o seqcore.o datastore.o injectcode-32bit.o $(BASEOBJS) klibc.o ptlsim.dst.o
endif

OOOOBJS = branchpred.o dcache.o ooocore.o ooopipe.o oooexec.o
OBJFILES = linkstart.o $(COMMONOBJS) $(OOOOBJS) linkend.o

COMMONINCLUDES = logic.h ptlhwdef.h decode.h seqexec.h dcache.h dcache-amd-k8.h config.h ptlsim.h datastore.h superstl.h globals.h kernel.h mm.h ptlcalls.h loader.h mathlib.h klibc.h syscalls.h stats.h
OOOINCLUDES = branchpred.h ooocore.h ooocore-amd-k8.h
INCLUDEFILES = $(COMMONINCLUDES) $(OOOINCLUDES)

COMMONCPPFILES = ptlsim.cpp kernel.cpp mm.cpp superstl.cpp ptlhwdef.cpp decode-core.cpp decode-fast.cpp decode-complex.cpp decode-x87.cpp decode-sse.cpp lowlevel-64bit.S lowlevel-32bit.S linkstart.S linkend.S uopimpl.cpp dcache.cpp config.cpp datastore.cpp injectcode.cpp ptlcalls.c cpuid.cpp ptlstats.cpp klibc.cpp glibc.cpp mathlib.cpp syscalls.cpp

OOOCPPFILES = ooocore.cpp ooopipe.cpp oooexec.cpp seqcore.cpp branchpred.cpp

CPPFILES = $(COMMONCPPFILES) $(OOOCPPFILES)

CFLAGS += -D__PTLSIM_OOO_ONLY__

TOPLEVEL = ptlsim ptlstats ptlcalls.o ptlcalls-32bit.o cpuid

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

ifdef __x86_64__
DATA_OBJ_TYPE = elf64-x86-64
else
DATA_OBJ_TYPE = elf32-i386
endif

ptlsim.dst.o: ptlsim.dst
	objcopy -I binary -O $(DATA_OBJ_TYPE) -B i386 --rename-section .data=.dst,alloc,load,readonly,data,contents ptlsim.dst ptlsim.dst.o

ifdef __x86_64__
ptlsim: $(OBJFILES) Makefile
	$(CC) -nostdlib $(OBJFILES) -o ptlsim $(LIBPERFCTR) -static -static-libgcc -Wl,-Ttext-segment,0x70000000 -Wl,--allow-multiple-definition -e ptlsim_preinit_entry
else
ptlsim: $(OBJFILES) Makefile ptlsim32.lds
	ld --oformat=elf32-i386 -melf_i386 -g -O2 $(OBJFILES) -o ptlsim $(LIBPERFCTR) -static --allow-multiple-definition -T ptlsim32.lds -e ptlsim_preinit_entry `gcc -m32 -print-libgcc-file-name`
endif

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
	rm -fv ptlsim ptlstats cpuid ptlsim.dst dstbuild.temp dstbuild.temp.cpp stats.i *.o core core.[0-9]* .depend *.gch

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

