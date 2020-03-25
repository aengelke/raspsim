// -*- c++ -*-
//
// PTLsim: Cycle Accurate x86-64 Simulator
// Linux Kernel Interface
//
// Copyright 2003-2008 Matt T. Yourst <yourst@yourst.com>
//

#ifndef _KERNEL_H_
#define _KERNEL_H_

#include <globals.h>
#include <ptlhwdef.h>
#include <elf.h>

struct PTLsimConfig;

extern PTLsimConfig config;

extern ConfigurationParser<PTLsimConfig> configparser;

//
// Thread local storage
//
typedef W64 (*simcall_func_t)(W64 arg1, W64 arg2, W64 arg3, W64 arg4, W64 arg5, W64 arg6);

struct ThreadState {
  ThreadState* self;
  void* stack;
  simcall_func_t simcall;
};

extern ThreadState basetls;

static inline ThreadState* getcurrent() {
  return &basetls;
}

void early_printk(const char* text);

// Initialize all PTLsim kernel structures
void init_kernel();

//
// Thunk and breakpoint management
//
#ifdef __x86_64__
typedef Elf64_auxv_t native_auxv_t;
#else
typedef Elf32_auxv_t native_auxv_t;
#endif

const char* get_full_exec_filename();
native_auxv_t* find_auxv_entry(int type);

void switch_stack_and_jump_32_or_64(void* code, void* stack, bool use64);
void switch_to_native_restore_context();
void set_switch_to_sim_breakpoint(void* addr);
void enable_ptlsim_call_gate();
void disable_ptlsim_call_gate();

int ptlsim_inject(int argc, char** argv);

//
// Signal callbacks
//
void init_signal_callback();
void remove_signal_callback();
// Set whenever PTLsim is running inside some simulator loop
extern bool running_in_sim_mode;

//
// Address space management
//

#ifdef __x86_64__

// Each chunk covers 2 GB of virtual address space:
#define SPAT_TOPLEVEL_CHUNK_BITS 17
#define SPAT_PAGES_PER_CHUNK_BITS 19
#define SPAT_TOPLEVEL_CHUNKS (1 << SPAT_TOPLEVEL_CHUNK_BITS) // 262144
#define SPAT_PAGES_PER_CHUNK (1 << SPAT_PAGES_PER_CHUNK_BITS) // 524288
#define SPAT_BYTES_PER_CHUNK (SPAT_PAGES_PER_CHUNK / 8)    // 65536
#define ADDRESS_SPACE_BITS (48)
#define ADDRESS_SPACE_SIZE (1LL << ADDRESS_SPACE_BITS)

#else

// Each chunk covers 2 GB of virtual address space:
#define ADDRESS_SPACE_BITS (32)
#define ADDRESS_SPACE_SIZE (1LL << ADDRESS_SPACE_BITS)
#define SPAT_BYTES ((ADDRESS_SPACE_SIZE / PAGE_SIZE) / 8)

#endif

class AddressSpace {
public:
  AddressSpace();
  ~AddressSpace();
  void reset();
public:

  Waddr imagebase;
  Waddr entrypoint;
  Waddr end_code;

  void* brkbase;
  void* brk;

  Waddr top_of_stack;
  Waddr stack_base;

public:
  Waddr prep(int argc, char** argv, int envc, char** envp);

public:
  //
  // Shadow page attribute table
  //
#ifdef __x86_64__
  typedef byte SPATChunk[SPAT_BYTES_PER_CHUNK];
  typedef SPATChunk** spat_t;
#else
  typedef byte* spat_t;
#endif
  spat_t readmap;
  spat_t writemap;
  spat_t execmap;
  spat_t dtlbmap;
  spat_t itlbmap;
  spat_t transmap;
  spat_t dirtymap;

  spat_t allocmap();
  void freemap(spat_t top);

  byte& pageid_to_map_byte(spat_t top, Waddr pageid);
  void make_accessible(void* address, Waddr size, spat_t top);
  void make_inaccessible(void* address, Waddr size, spat_t top);

  Waddr pageid(void* address) const {
#ifdef __x86_64__
    return ((W64)lowbits((W64)address, ADDRESS_SPACE_BITS)) >> log2(PAGE_SIZE);
#else
    return ((Waddr)address) >> log2(PAGE_SIZE);
#endif
  }

  Waddr pageid(Waddr address) const { return pageid((void*)address); }

  void make_page_accessible(void* address, spat_t top) {
    setbit(pageid_to_map_byte(top, pageid(address)), lowbits(pageid(address), 3));
  }

  void make_page_inaccessible(void* address, spat_t top) {
    clearbit(pageid_to_map_byte(top, pageid(address)), lowbits(pageid(address), 3));
  }

  void allow_read(void* address, Waddr size) { make_accessible(address, size, readmap); }
  void disallow_read(void* address, Waddr size) { make_inaccessible(address, size, readmap); }
  void allow_write(void* address, Waddr size) { make_accessible(address, size, writemap); }
  void disallow_write(void* address, Waddr size) { make_inaccessible(address, size, writemap); }
  void allow_exec(void* address, Waddr size) { make_accessible(address, size, execmap); }
  void disallow_exec(void* address, Waddr size) { make_inaccessible(address, size, execmap); }

public:
  //
  // Memory management passthroughs
  //
  long sys_errno;

  void setattr(void* start, Waddr length, int prot);
  int getattr(void* start);
  int mprotect(void* start, Waddr length, int prot);
  int munmap(void* start, Waddr length);
  void* mmap(void* start, Waddr length, int prot, int flags, int fd, W64 offset);
  void* mremap(void* start, Waddr oldsize, Waddr newsize, int flags);
  void* setbrk(void* targetbrk);

  bool fastcheck(Waddr addr, spat_t top) const {
#ifdef __x86_64__
    // Is it outside of userspace address range?
    // Check disabled to allow access to VDSO in kernel space.
    // if unlikely (addr >> 48) return 0;

    W64 chunkid = pageid(addr) >> log2(SPAT_PAGES_PER_CHUNK);

    if unlikely (!top[chunkid])
      return false;

    AddressSpace::SPATChunk& chunk = *top[chunkid];
    Waddr byteid = bits(pageid(addr), 3, log2(SPAT_BYTES_PER_CHUNK));
    return bit(chunk[byteid], lowbits(pageid(addr), 3));
#else // 32-bit
    return bit(top[pageid(addr) >> 3], lowbits(pageid(addr), 3));
#endif
  }

  bool fastcheck(void* addr, spat_t top) const {
    return fastcheck((Waddr)addr, top);
  }

  bool check(void* p, int prot) const {
    if unlikely ((prot & PROT_READ) && (!fastcheck(p, readmap)))
      return false;
    
    if unlikely ((prot & PROT_WRITE) && (!fastcheck(p, writemap)))
      return false;

    if unlikely ((prot & PROT_EXEC) && (!fastcheck(p, execmap)))
      return false;
    
    return true;
  }

  bool dtlbcheck(void* page) const { return fastcheck(page, dtlbmap); }
  void dtlbset(void* page) { make_page_accessible(page, dtlbmap); }
  void dtlbclear(void* page) { make_page_inaccessible(page, dtlbmap); }

  bool itlbcheck(void* page) const { return fastcheck(page, itlbmap); }
  void itlbset(void* page) { make_page_accessible(page, itlbmap); }
  void itlbclear(void* page) { make_page_inaccessible(page, itlbmap); }

  bool istrans(Waddr mfn) { return fastcheck(mfn << 12, transmap); }
  void settrans(Waddr mfn) { make_page_accessible((void*)(mfn << 12), transmap); }
  void cleartrans(Waddr mfn) { make_page_inaccessible((void*)(mfn << 12), transmap); }

  bool isdirty(Waddr mfn) { return fastcheck(mfn << 12, dirtymap); }
  void setdirty(Waddr mfn) { make_page_accessible((void*)(mfn << 12), dirtymap); }
  void cleardirty(Waddr mfn) { make_page_inaccessible((void*)(mfn << 12), dirtymap); }

  void resync_with_process_maps();
};

extern AddressSpace asp;

static inline bool smc_istrans(Waddr mfn) { return asp.istrans(mfn); }
static inline void smc_settrans(Waddr mfn) { asp.settrans(mfn); }
static inline void smc_cleartrans(Waddr mfn) { asp.cleartrans(mfn); }

static inline bool smc_isdirty(Waddr mfn) { return asp.isdirty(mfn); }
static inline void smc_setdirty(Waddr mfn) { asp.setdirty(mfn); }
static inline void smc_cleardirty(Waddr mfn) { asp.cleardirty(mfn); }

// Only one VCPU in userspace PTLsim:
static inline Context& contextof(int vcpu) { return ctx; }

#define contextcount (1)

#define MAX_CONTEXTS 1

// virtual == physical in userspace PTLsim:
static inline void* phys_to_mapped_virt(Waddr rawphys) {
  return (void*)rawphys;
}

static inline Waddr mapped_virt_to_phys(void* rawvirt) {
  return (Waddr)rawvirt;
}

inline int Context::copy_from_user(void* target, Waddr addr, int bytes, PageFaultErrorCode& pfec, Waddr& faultaddr, bool forexec, Level1PTE& ptelo, Level1PTE& ptehi) {
  bool readable;
  bool executable;

  int n = 0;
  pfec = 0;

  ptelo = 0;
  ptehi = 0;

  readable = asp.fastcheck((byte*)addr, asp.readmap);
  if likely (forexec) executable = asp.fastcheck((byte*)addr, asp.execmap);
  if unlikely ((!readable) | (forexec & !executable)) {
    faultaddr = addr;
    pfec.p = !readable;
    pfec.nx = (forexec & (!executable));
    return n;
  }

  n = min((Waddr)(4096 - lowbits(addr, 12)), (Waddr)bytes);

  memcpy(target, (void*)addr, n);

  // All the bytes were on the first page
  if likely (n == bytes) return n;

  // Go on to second page, if present
  readable = asp.fastcheck((byte*)(addr + n), asp.readmap);
  if likely (forexec) executable = asp.fastcheck((byte*)(addr + n), asp.execmap);
  if unlikely ((!readable) | (forexec & !executable)) {
    faultaddr = addr + n;
    pfec.p = !readable;
    pfec.nx = (forexec & (!executable));
    return n;
  }

  memcpy((byte*)target + n, (void*)(addr + n), bytes - n);
  return bytes;
}

inline int Context::copy_to_user(Waddr target, void* source, int bytes, PageFaultErrorCode& pfec, Waddr& faultaddr) {
  pfec = 0;
  bool writable = asp.fastcheck((byte*)target, asp.writemap);
  if unlikely (!writable) {
    faultaddr = target;
    pfec.p = asp.fastcheck((byte*)target, asp.readmap);
    pfec.rw = 1;
    return 0;
  }

  byte* targetlo = (byte*)target;
  int nlo = min((Waddr)(4096 - lowbits(target, 12)), (Waddr)bytes);

  smc_setdirty(target >> 12);

  // All the bytes were on the first page
  if likely (nlo == bytes) {
    memcpy(targetlo, source, nlo);
    return bytes;
  }

  // Go on to second page, if present
  writable = asp.fastcheck((byte*)(target + nlo), asp.writemap);
  if unlikely (!writable) {
    faultaddr = target + nlo;
    pfec.p = asp.fastcheck((byte*)(target + nlo), asp.readmap);
    pfec.rw = 1;
    return nlo;
  }

  memcpy((byte*)(target + nlo), (byte*)source + nlo, bytes - nlo);
  memcpy(targetlo, source, nlo);

  smc_setdirty((target + nlo) >> 12);

  return bytes;
}

static const Waddr INVALID_PHYSADDR = 0;

inline Waddr Context::check_and_translate(Waddr virtaddr, int sizeshift, bool store, bool internal, int& exception, PageFaultErrorCode& pfec, PTEUpdate& pteupdate, Level1PTE& pteused) {
  exception = 0;
  pteupdate = 0;
  pteused = 0;
  pfec = 0;

  if unlikely (lowbits(virtaddr, sizeshift)) {
    exception = EXCEPTION_UnalignedAccess;
    return INVALID_PHYSADDR;
  }

  if unlikely (internal) {
    // Directly mapped to PTL space:
    return virtaddr;
  }

  AddressSpace::spat_t top = (store) ? asp.writemap : asp.readmap;

  if unlikely (!asp.fastcheck(virtaddr, top)) {
    exception = (store) ? EXCEPTION_PageFaultOnWrite : EXCEPTION_PageFaultOnRead;
    pfec.p = !store;
    pfec.rw = store;
    pfec.us = 0;
    return 0;
  }

  return virtaddr;
}

static inline W64 loadphys(Waddr addr) {
  addr = floor(signext64(addr, 48), 8);
  W64& data = *(W64*)(Waddr)addr;
  return data;
}

static inline W64 storemask(Waddr addr, W64 data, byte bytemask) {
  addr = floor(signext64(addr, 48), 8);
  W64& mem = *(W64*)(Waddr)addr;
  mem = mux64(expand_8bit_to_64bit_lut[bytemask], mem, data);
  return data;
}

// In userspace PTLsim, virtual == physical:
inline RIPVirtPhys& RIPVirtPhys::update(Context& ctx, int bytes) {
  use64 = ctx.use64;
  kernel = 0;
  df = ((ctx.internal_eflags & FLAG_DF) != 0);
  padlo = 0;
  padhi = 0;
  mfnlo = rip >> 12;
  mfnhi = (rip + (bytes-1)) >> 12;
  return *this;
}

//
// System calls
//
enum { SYSCALL_SEMANTICS_INT80, SYSCALL_SEMANTICS_SYSCALL, SYSCALL_SEMANTICS_SYSENTER };

void handle_syscall_32bit(int semantics);

// x86-64 mode has only one type of system call (the syscall instruction)
void handle_syscall_64bit();

//
// Local descriptor table
//
#define LDT_SIZE 8192
extern W64 ldt_seg_base_cache[LDT_SIZE];

//
// This is set if we are running within the target process address space;
// it controls the way PTLsim behaves on startup. If not set, PTLsim is
// acting as a regular program, typically to inject itself into another
// process (which will then have inside_ptlsim set) or to print help info.
//
extern bool inside_ptlsim;

extern bool requested_switch_to_native;

#endif // _KERNEL_H_
