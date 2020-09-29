// -*- c++ -*-
//
// PTLsim: Cycle Accurate x86-64 Simulator
// Memory Management
//
// Copyright 2004-2008 Matt T. Yourst <yourst@yourst.com>
//

#ifndef _MM_H_
#define _MM_H_

#include <globals.h>

void* ptl_mm_alloc_private_pages(Waddr bytecount, int prot = PROT_READ|PROT_WRITE, Waddr base = 0);
void ptl_mm_free_private_pages(void* addr, Waddr bytecount);

#endif // _MM_H_
