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

#SVNREV=$(shell svn info | grep "Last Changed Rev" | cut -d " " -f4)
#SVNDATE=$(shell svn info | grep "Last Changed Date" | cut -d " " -f4)

#ifeq (,$(SVNREV))
# Subversion is either not installed or the current directory isn't a PTLsim repository:
SVNREV=0
SVNDATE=unknown
#endif

INCFLAGS = -I. -DBUILDHOST="`hostname -f`" -DSVNREV="$(SVNREV)" -DSVNDATE="$(SVNDATE)"

ifdef __x86_64__
CFLAGS = -std=gnu++11 -O1 -g -fomit-frame-pointer -pipe -march=k8 -fno-builtin-memmove -falign-functions=16 -funroll-loops -funit-at-a-time -minline-all-stringops
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



BASEOBJS = superstl.o config.o syscalls.o
COMMONOBJS = ptlsim.o mm.o ptlhwdef.o decode-core.o decode-fast.o decode-complex.o decode-x87.o decode-sse.o uopimpl.o seqcore.o $(BASEOBJS)

OOOOBJS = branchpred.o dcache.o ooocore.o ooopipe.o oooexec.o
RASPSIM_OBJFILES = $(COMMONOBJS) raspsim.o $(OOOOBJS)

COMMONINCLUDES = logic.h ptlhwdef.h decode.h seqexec.h dcache.h dcache-amd-k8.h config.h ptlsim.h superstl.h globals.h ptlsim-api.h mm.h loader.h syscalls.h stats.h
OOOINCLUDES = branchpred.h ooocore.h ooocore-amd-k8.h
INCLUDEFILES = $(COMMONINCLUDES) $(OOOINCLUDES)

COMMONCPPFILES = ptlsim.cpp raspsim.cpp mm.cpp superstl.cpp ptlhwdef.cpp decode-core.cpp decode-fast.cpp decode-complex.cpp decode-x87.cpp decode-sse.cpp uopimpl.cpp dcache.cpp config.cpp syscalls.cpp

OOOCPPFILES = ooocore.cpp ooopipe.cpp oooexec.cpp seqcore.cpp branchpred.cpp

CPPFILES = $(COMMONCPPFILES) $(OOOCPPFILES)

CFLAGS += -D__PTLSIM_OOO_ONLY__

TOPLEVEL = raspsim

all: $(TOPLEVEL)
	@echo "Compiled successfully..."

ifdef __x86_64__
raspsim: $(RASPSIM_OBJFILES) Makefile
	$(CXX) $(RASPSIM_OBJFILES) -o $@ -Wl,--allow-multiple-definition
endif

%.o: %.cpp
	$(CC) $(CFLAGS) $(INCFLAGS) -c $<

%.o: %.S
	$(CC) $(CFLAGS) $(INCFLAGS) -c $<

%.o: %.c
	$(CC) $(CFLAGS) $(INCFLAGS) -c $<

clean:
	rm -fv raspsim *.o core core.[0-9]* .depend *.gch

INCLUDEFILES = $(COMMONINCLUDES) $(PT2XINCLUDES) $(OOOINCLUDES)
CPPFILES = $(COMMONCPPFILES) $(PT2XCPPFILES) $(OOOCPPFILES)

#
# Miscellaneous:
#

DISTFILES = $(CPPFILES) $(INCLUDEFILES) Makefile COPYING README

dist: $(DISTFILES)
	tar zcvf ptlsim-`date "+%Y%m%d%H%M%S"`.tar.gz $(DISTFILES)

backup: dist

distfiles: $(DISTFILES)
	@echo $(DISTFILES)

.depend:
	$(CC) $(CFLAGS) $(INCFLAGS) -MM $(CPPFILES) $(ASMFILES) > .depend

-include .depend

