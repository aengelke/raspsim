//
// PTLsim: Cycle Accurate x86-64 Simulator
// Memory Management
//
// Copyright 2000-2008 Matt T. Yourst <yourst@yourst.com>
//

#include <globals.h>
#include <ptlsim-api.h>
#include <mm.h>

void* ptl_mm_try_alloc_private_pages(Waddr bytecount, int prot, Waddr base, void* caller) {
  int flags = MAP_ANONYMOUS|MAP_NORESERVE|MAP_PRIVATE | (base ? MAP_FIXED : 0);
  return sys_mmap((void*)base, ceil(bytecount, PAGE_SIZE), prot, flags, 0, 0);
}

void* ptl_mm_alloc_private_pages(Waddr bytecount, int prot, Waddr base) {
  return ptl_mm_try_alloc_private_pages(bytecount, prot, base, getcaller());
}

void ptl_mm_free_private_pages(void* addr, Waddr bytecount) {
  bytecount = ceil(bytecount, PAGE_SIZE);

  sys_munmap(addr, bytecount);
}
