//
// PTLsim: Cycle Accurate x86-64 Simulator
// Linux Kernel Interface
//
// Copyright 2000-2008 Matt T. Yourst <yourst@yourst.com>
//

#include <globals.h>
#include <superstl.h>
#include <mm.h>

#include <elf.h>
#include <asm/ldt.h>
#include <asm/ptrace.h>

#ifdef __x86_64__
#include <asm/prctl.h>
#endif

#include <ptlsim.h>
#include <ptlsim-api.h>
#include <ptlhwdef.h>
#include <config.h>
#include <stats.h>
#include <loader.h>

#define __INSIDE_PTLSIM__
#include <ptlcalls.h>

Context ctx alignto(4096) insection(".ctx");
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

AddressSpace asp;

//
// Local descriptor table
//
#define LDT_SIZE 8192
W64 ldt_seg_base_cache[LDT_SIZE];

// Userspace PTLsim only supports one VCPU:
int current_vcpuid() { return 0; }

static inline W64 do_syscall_64bit(W64 syscallid, W64 arg1, W64 arg2, W64 arg3, W64 arg4, W64 arg5, W64 arg6) {
  W64 rc;
  asm volatile ("movq %5,%%r10\n"
                "movq %6,%%r8\n"
                "movq %7,%%r9\n"
                "syscall\n"
                : "=a" (rc)
                : "0" (syscallid),"D" ((W64)(arg1)),"S" ((W64)(arg2)),
                "d" ((W64)(arg3)), "g" ((W64)(arg4)), "g" ((W64)(arg5)),
                "g" ((W64)(arg6)) 
                : "r11","rcx","memory" ,"r8", "r10", "r9" );
  return rc;
}

struct user_desc_32bit {
  W32 entry_number;
  W32 base_addr;
  W32 limit;
  W32 seg_32bit:1;
  W32 contents:2;
  W32 read_exec_only:1;
  W32 limit_in_pages:1;
  W32 seg_not_present:1;
  W32 useable:1;
};

#ifdef __x86_64__
// Parameters in: ebx ecx edx esi edi ebp
static inline W32 do_syscall_32bit(W32 sysid, W32 arg1, W32 arg2, W32 arg3, W32 arg4, W32 arg5, W32 arg6) {
  W32 rc;
  asm volatile ("push %%rbp ; movl %[arg6],%%ebp ; int $0x80 ; pop %%rbp" : "=a" (rc) :
                "a" (sysid), "b" (arg1), "c" (arg2), "d" (arg3),
                "S" (arg4), "D" (arg5), [arg6] "r" (arg6));
  return rc;
}

Waddr get_fs_base() {
  if (ctx.use64) {
    Waddr fsbase;
    assert(sys_arch_prctl(ARCH_GET_FS, &fsbase) == 0);
    return fsbase;
  } else {
    return ldt_seg_base_cache[ctx.seg[SEGID_FS].selector >> 3];
  }
}

Waddr get_gs_base() {
  if (ctx.use64) {
    W64 gsbase;
    assert(sys_arch_prctl(ARCH_GET_GS, &gsbase) == 0);
    return gsbase;
  } else {
    return ldt_seg_base_cache[ctx.seg[SEGID_GS].selector >> 3];
  }
}

#else
// 32-bit only
static inline W32 do_syscall_32bit(W32 sysid, W32 arg1, W32 arg2, W32 arg3, W32 arg4, W32 arg5, W32 arg6) {
  W32 rc;
  W32 ebp;

  asm volatile ("movl %%ebp,%[ebp]\n\t"
                "movl %%eax,%%ebp\n\t"
                "movl %[sysid],%%eax\n\t" // a 'push' would break this reference
                "int $0x80\n\t"
                "movl %[ebp],%%ebp"
              : "=a" (rc), [ebp] "=m" (ebp)
              : [sysid] "m" (sysid), "b" (arg1), "c" (arg2), "d" (arg3),
                "S" (arg4), "D" (arg5), "0" (arg6));
  return rc;
}

Waddr get_fs_base() {
  user_desc_32bit ud;
  memset(&ud, 0, sizeof(ud));
  ud.entry_number = ctx.seg[SEGID_FS].selector >> 3;
  int rc = sys_get_thread_area((user_desc*)&ud);
  return (rc) ? 0 : ud.base_addr;
}

Waddr get_gs_base() {
  user_desc_32bit ud;
  memset(&ud, 0, sizeof(ud));
  ud.entry_number = ctx.seg[SEGID_GS].selector >> 3;
  int rc = sys_get_thread_area((user_desc*)&ud);
  return (rc) ? 0 : ud.base_addr;
}

#endif // !__x86_64__

bool asp_check_exec(void* addr) { return asp.fastcheck(addr, asp.execmap); }

bool smc_istrans(Waddr mfn) { return asp.istrans(mfn); }
void smc_settrans(Waddr mfn) { asp.settrans(mfn); }
void smc_cleartrans(Waddr mfn) { asp.cleartrans(mfn); }

bool smc_isdirty(Waddr mfn) { return asp.isdirty(mfn); }
void smc_setdirty(Waddr mfn) { asp.setdirty(mfn); }
void smc_cleardirty(Waddr mfn) { asp.cleardirty(mfn); }

// Only one VCPU in userspace PTLsim:
Context& contextof(int vcpu) { return ctx; }

W64 loadphys(Waddr addr) {
  addr = floor(signext64(addr, 48), 8);
  W64& data = *(W64*)(Waddr)addr;
  return data;
}

W64 storemask(Waddr addr, W64 data, byte bytemask) {
  addr = floor(signext64(addr, 48), 8);
  W64& mem = *(W64*)(Waddr)addr;
  mem = mux64(expand_8bit_to_64bit_lut[bytemask], mem, data);
  return data;
}

// virtual == physical in userspace PTLsim:
static inline void* phys_to_mapped_virt(Waddr rawphys) {
  return (void*)rawphys;
}

static inline Waddr mapped_virt_to_phys(void* rawvirt) {
  return (Waddr)rawvirt;
}

int Context::copy_from_user(void* target, Waddr addr, int bytes, PageFaultErrorCode& pfec, Waddr& faultaddr, bool forexec, Level1PTE& ptelo, Level1PTE& ptehi) {
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

int Context::copy_to_user(Waddr target, void* source, int bytes, PageFaultErrorCode& pfec, Waddr& faultaddr) {
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

Waddr Context::check_and_translate(Waddr virtaddr, int sizeshift, bool store, bool internal, int& exception, PageFaultErrorCode& pfec, PTEUpdate& pteupdate, Level1PTE& pteused) {
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

int Context::write_segreg(unsigned int segid, W16 selector) {
  // Normal userspace PTLsim: assume it's OK
  assert(segid < SEGID_COUNT);

  seg[segid].selector = selector;
  update_shadow_segment_descriptors();
  return 0;
}

void Context::update_shadow_segment_descriptors() {
  W64 limit = (use64) ? 0xffffffffffffffffULL : 0xffffffffULL;

  SegmentDescriptorCache& cs = seg[SEGID_CS];
  cs.present = 1;
  cs.base = 0;
  cs.limit = limit;

  virt_addr_mask = limit;

  SegmentDescriptorCache& ss = seg[SEGID_SS];
  ss.present = 1;
  ss.base = 0;
  ss.limit = limit;

  SegmentDescriptorCache& ds = seg[SEGID_DS];
  ds.present = 1;
  ds.base = 0;
  ds.limit = limit;

  SegmentDescriptorCache& es = seg[SEGID_ES];
  es.present = 1;
  es.base = 0;
  es.limit = limit;
  
  SegmentDescriptorCache& fs = seg[SEGID_FS];
  fs.present = 1;
  fs.base = get_fs_base();
  fs.limit = limit;

  SegmentDescriptorCache& gs = seg[SEGID_GS];
  gs.present = 1;
  gs.base = get_gs_base();
  gs.limit = limit;
}

// Based on /usr/include/asm-i386/unistd.h:
#define __NR_32bit_mmap 90
#define __NR_32bit_mmap2 192
#define __NR_32bit_munmap 91
#define __NR_32bit_mprotect 125
#define __NR_32bit_mremap 163
#define __NR_32bit_brk 45
#define __NR_32bit_exit 1
#define __NR_32bit_exit_group 252
#define __NR_32bit_mremap 163
#define __NR_32bit_set_thread_area 243
#define __NR_32bit_rt_sigaction 174
#define __NR_32bit_alarm 27

#define __NR_64bit_mmap 9
#define __NR_64bit_munmap 11
#define __NR_64bit_mprotect 10
#define __NR_64bit_brk 12
#define __NR_64bit_mremap 25
#define __NR_64bit_arch_prctl 158
#define __NR_64bit_exit 60
#define __NR_64bit_exit_group 231
#define __NR_64bit_rt_sigaction 13
#define __NR_64bit_alarm 37

void early_printk(const char* text) {
  sys_write(2, text, strlen(text));
}

// Avoid c++ scoping problems:

// Makes it easy to identify which segments PTLsim owns versus the user address space:
bool inside_ptlsim = false;

void dump_ooo_state();
void dump_cpt_state();

extern "C" void assert_fail(const char *__assertion, const char *__file, unsigned int __line, const char *__function) {
  stringbuf sb;
  sb << "Assert ", __assertion, " failed in ", __file, ":", __line, " (", __function, ") at ", sim_cycle, " cycles, ", iterations, " iterations, ", total_user_insns_committed, " user commits", endl;

  cerr << sb, flush;

  if (logfile) {
    logfile << sb, flush;
    PTLsimMachine* machine = PTLsimMachine::getcurrent();
    if (machine) machine->dump_state(logfile);
    logfile.close();
  }

  // Crash and make a core dump:
  asm("ud2a");
  abort();
}

//
// Shadow page accessibility table format (x86-64 only): 
// Top level:  1048576 bytes: 131072 64-bit pointers to chunks
//
// Leaf level: 65536 bytes per chunk: 524288 bits, one per 4 KB page
// Total: 131072 chunks x 524288 pages per chunk x 4 KB per page = 48 bits virtual address space
// Total: 17 bits       + 19 bits                + 12 bits       = 48 bits virtual address space
//
// In 32-bit version, SPAT is a flat 131072-byte bit vector.
//

byte& AddressSpace::pageid_to_map_byte(spat_t top, Waddr pageid) {
#ifdef __x86_64__
  W64 chunkid = pageid >> log2(SPAT_PAGES_PER_CHUNK);

  if (!top[chunkid]) {
    top[chunkid] = (SPATChunk*)ptl_mm_alloc_private_pages(SPAT_BYTES_PER_CHUNK);
  }
  SPATChunk& chunk = *top[chunkid];
  W64 byteid = bits(pageid, 3, log2(SPAT_BYTES_PER_CHUNK));
  assert(byteid <= SPAT_BYTES_PER_CHUNK);
  return chunk[byteid];
#else
  return top[pageid >> 3];
#endif
}

void AddressSpace::make_accessible(void* p, Waddr size, spat_t top) {
  Waddr address = lowbits((Waddr)p, ADDRESS_SPACE_BITS);
  Waddr firstpage = (Waddr)address >> log2(PAGE_SIZE);
  Waddr lastpage = ((Waddr)address + size - 1) >> log2(PAGE_SIZE);
  if (logable(1)) {
    logfile << "SPT: Making byte range ", (void*)(firstpage << log2(PAGE_SIZE)), " to ",
      (void*)(lastpage << log2(PAGE_SIZE)), " (size ", size, ") accessible for ", 
    ((top == readmap) ? "read" : (top == writemap) ? "write" : (top == execmap) ? "exec" : "UNKNOWN"),
      endl, flush;
  }
  assert(ceil((W64)address + size, PAGE_SIZE) <= ADDRESS_SPACE_SIZE);
  for (W64 i = firstpage; i <= lastpage; i++) { setbit(pageid_to_map_byte(top, i), lowbits(i, 3)); }
}

void AddressSpace::make_inaccessible(void* p, Waddr size, spat_t top) {
  Waddr address = lowbits((Waddr)p, ADDRESS_SPACE_BITS);
  Waddr firstpage = (Waddr)address >> log2(PAGE_SIZE);
  Waddr lastpage = ((Waddr)address + size - 1) >> log2(PAGE_SIZE);
  if (logable(1)) {
    logfile << "SPT: Making byte range ", (void*)(firstpage << log2(PAGE_SIZE)), " to ",
      (void*)(lastpage << log2(PAGE_SIZE)), " (size ", size, ") inaccessible for ", 
    ((top == readmap) ? "read" : (top == writemap) ? "write" : (top == execmap) ? "exec" : "UNKNOWN"),
      endl, flush;
  }
  assert(ceil((W64)address + size, PAGE_SIZE) <= ADDRESS_SPACE_SIZE);
  for (Waddr i = firstpage; i <= lastpage; i++) { clearbit(pageid_to_map_byte(top, i), lowbits(i, 3)); }
}

AddressSpace::AddressSpace() { }

AddressSpace::~AddressSpace() { }

AddressSpace::spat_t AddressSpace::allocmap() {
#ifdef __x86_64__
  return (spat_t)ptl_mm_alloc_private_pages(SPAT_TOPLEVEL_CHUNKS * sizeof(SPATChunk*));
#else 
  return (spat_t)ptl_mm_alloc_private_pages(SPAT_BYTES);
#endif
}
void AddressSpace::freemap(AddressSpace::spat_t top) {
#ifdef __x86_64__
  if (top) {
    foreach (i, SPAT_TOPLEVEL_CHUNKS) {
      if (top[i]) ptl_mm_free_private_pages(top[i], SPAT_BYTES_PER_CHUNK);
    }
    ptl_mm_free_private_pages(top, SPAT_TOPLEVEL_CHUNKS * sizeof(SPATChunk*));
  }
#else
  if (top) {
    ptl_mm_free_private_pages(top, SPAT_BYTES);
  }
#endif
}

void AddressSpace::reset() {
  brkbase = sys_brk(0);
  brk = brkbase;

  freemap(readmap);
  freemap(writemap);
  freemap(execmap);
  freemap(dtlbmap);
  freemap(itlbmap);
  freemap(transmap);
  freemap(dirtymap);

  readmap  = allocmap();
  writemap = allocmap();
  execmap  = allocmap();
  dtlbmap  = allocmap();
  itlbmap  = allocmap();
  transmap = allocmap();
  dirtymap = allocmap();
}

void AddressSpace::setattr(void* start, Waddr length, int prot) {
  //
  // Check first if it's been assigned a non-stdin (> 0) filehandle,
  // since this may get called from ptlsim_preinit_entry before streams
  // have been set up.
  //
  if (logfile.filehandle() > 0) {
    logfile << "setattr: region ", start, " to ", (void*)((char*)start + length), " (", length >> 10, " KB) has user-visible attributes ",
      ((prot & PROT_READ) ? 'r' : '-'), ((prot & PROT_WRITE) ? 'w' : '-'), ((prot & PROT_EXEC) ? 'x' : '-'), endl;
  }

  if (prot & PROT_READ)
    allow_read(start, length);
  else disallow_read(start, length);

  if (prot & PROT_WRITE)
    allow_write(start, length);
  else disallow_write(start, length);

  if (prot & PROT_EXEC)
    allow_exec(start, length);
  else disallow_exec(start, length);
}

int AddressSpace::getattr(void* addr) {
  Waddr address = lowbits((Waddr)addr, ADDRESS_SPACE_BITS);

  Waddr page = pageid(address);

  int prot = 
    (bit(pageid_to_map_byte(readmap, page), lowbits(page, 3)) ? PROT_READ : 0) |
    (bit(pageid_to_map_byte(writemap, page), lowbits(page, 3)) ? PROT_WRITE : 0) |
    (bit(pageid_to_map_byte(execmap, page), lowbits(page, 3)) ? PROT_EXEC : 0);

  return prot;
}
 
int AddressSpace::mprotect(void* start, Waddr length, int prot) {
  length = ceil(length, PAGE_SIZE);
  int rc = sys_mprotect(start, length, prot);
  if (rc) return rc;
  setattr(start, length, prot);
  return 0;
}

int AddressSpace::munmap(void* start, Waddr length) {
  length = ceil(length, PAGE_SIZE);
  int rc = sys_munmap(start, length);
  if (rc) return rc;
  setattr(start, length, PROT_NONE);
  return 0;
}

void* AddressSpace::mmap(void* start, Waddr length, int prot, int flags, int fd, W64 offset) {
  // Guarantee enough room will be available post-alignment:
  length = ceil(length, PAGE_SIZE);
  start = sys_mmap(start, length, prot, flags, fd, offset);
  if (mmap_invalid(start)) return start;
  setattr(start, length, prot);
  if (!(flags & MAP_ANONYMOUS)) {
    //
    // Linux has strange semantics w.r.t. memory mapped files
    // when the mapped region is larger than the file itself.
    // The process should get SIGBUS when we access memory
    // beyond the end of the file, however we need a special
    // check here to emulate this behavior in the SPT bitmaps.
    // Otherwise in extremely rare cases speculative execution
    // may attempt to access memory that looks valid but isn't.
    //
    W64 origoffs = sys_seek(fd, 0, SEEK_CUR);
    W64 filesize = sys_seek(fd, 0, SEEK_END);
    sys_seek(fd, origoffs, SEEK_SET);
    if ((W64s)filesize < 0) return (void*)-EINVAL; // can't access the file?
    W64 last_page_in_file = ceil(filesize, PAGE_SIZE);
    W64 last_page_to_map = offset + length;
    W64s delta_bytes = last_page_to_map - last_page_in_file;
    if (delta_bytes <= 0) return start; // OK

    logfile << "mmap(", start, ", ", length, ", ", prot, ", ", flags, ", ", fd, ", ", offset, "): ",
      "mapping beyond end of file: file ends at byte ", last_page_in_file, " but mapping ends at byte ",
      last_page_to_map, " (", delta_bytes, " bytes marked invalid starting at ",
      ((byte*)start + length - delta_bytes), ")", endl;

    setattr((byte*)start + length - delta_bytes, delta_bytes, PROT_NONE);
  }
  return start;
}

void* AddressSpace::mremap(void* start, Waddr oldlength, Waddr newlength, int flags) {
  int oldattr = getattr(start);

  void* p = sys_mremap(start, oldlength, newlength, flags);
  if (mmap_invalid(p)) return p;

  setattr(start, oldlength, 0);
  setattr(p, newlength, oldattr);
  return p;
}

void* AddressSpace::setbrk(void* reqbrk) {
  Waddr oldsize = ceil(((Waddr)brk - (Waddr)brkbase), PAGE_SIZE);

  if (!reqbrk) {
    assert(brk == sys_brk(0));
    logfile << "setbrk(0): returning current brk ", brk, endl;
    return brk;
  }

  // Remove old brk
  setattr(brkbase, oldsize, PROT_NONE);

  logfile << "setbrk(", reqbrk, "): old range ", brkbase, "-", brk, " (", oldsize, " bytes); new range ", brkbase, "-", reqbrk, " (delta ", ((Waddr)reqbrk - (Waddr)brk), ", size ", ((Waddr)reqbrk - (Waddr)brkbase), ")", endl;

  void* newbrk = sys_brk(reqbrk);

  if (newbrk < brkbase) {
    // Contracting memory
    Waddr clearsize = (Waddr)brkbase - (Waddr)newbrk;
    logfile << "setbrk(", reqbrk, "): contracting: new range ", newbrk, "-", brkbase, " (clearsize ", clearsize, ")", endl, flush;
    brk = newbrk;
    brkbase = newbrk;
    setattr(brkbase, clearsize, PROT_NONE);
  } else {
    // Expanding memory
    Waddr newsize = (Waddr)newbrk - (Waddr)brkbase;
    logfile << "setbrk(", reqbrk, "): expanding: new range ", brkbase, "-", newbrk, " (size ", newsize, ")", endl, flush;
    brk = newbrk;
    setattr(brkbase, newsize, PROT_READ|PROT_WRITE|PROT_EXEC);
  }

  return newbrk;
}

Waddr stack_min_addr;
Waddr stack_max_addr;

/*
 * Memory map query support
 *
 * The prot field supports the same PROT_READ, PROT_WRITE, PROT_EXEC bits
 * used in the mmap() system call.
 *
 * The flags field may have the following standard mmap()-style bits set:
 *
 * MAP_SHARED       Shared (writes to map update the file)
 * MAP_PRIVATE      Private copy on write
 * MAP_ANONYMOUS    Anonymous (no file) mapping
 * MAP_GROWSDOWN    Stack
 *
 * Additionally, these additional bits may be present:
 *
 * MAP_ZERO         Inheritable shared memory on /dev/zero
 * MAP_HEAP         Heap terminated by brk
 * MAP_VDSO         VDSO (vsyscall) gateway page
 * MAP_KERNEL       special mapping reserved by kernel
 *
 */

#undef  MAP_STACK
#define MAP_STACK   MAP_GROWSDOWN
#define MAP_ZERO    0x01000000
#define MAP_HEAP    0x02000000
#define MAP_VDSO    0x04000000

struct MemoryMapExtent {
  void* start;
  unsigned long length;
  unsigned int prot;
  unsigned int flags;
  unsigned long long offset;
  unsigned long long inode;
  unsigned short devmajor;
  unsigned short devminor;
};

int mqueryall(MemoryMapExtent* startmap, size_t count);

ostream& operator <<(ostream& os, const MemoryMapExtent& map);

int mqueryall(MemoryMapExtent* startmap, size_t count) {
  MemoryMapExtent* map = startmap;

  // Atomically capture process memory: otherwise we may allocate our own memory while reading /proc/self/maps 
#define MAX_PROC_MAPS_SIZE 16*1024*1024

  char* mapdata = (char*)ptl_mm_alloc_private_pages(MAX_PROC_MAPS_SIZE);
  int mapsize = 0;

  int fd = sys_open("/proc/self/maps", O_RDONLY, 0);
  assert(fd >= 0);

  for (;;) {
    int rc = sys_read(fd, mapdata + mapsize, MAX_PROC_MAPS_SIZE-PAGE_SIZE);
    if (rc <= 0) break;
    mapsize += rc;
    assert(inrange(mapsize, 0, (int)(MAX_PROC_MAPS_SIZE-PAGE_SIZE)));
  }
  mapdata[mapsize] = 0;

  // Now process the saved maps
  char* p = mapdata;

  byte* stackbase = null;

  // Count lines
  int linecount = 0;

  while (p && (*p)) {
    p = strchr(p, '\n');
    if (p) { linecount++; p++; }
  }

  p = mapdata;

  int line = 0;

  while (p && (*p)) {
    if (map == &startmap[count]) break;

    char* s = p;
    p = strchr(p, '\n');
    if (p) *p++ = 0; // skip over newline

    byte* start = null;
    byte* stop = null;
    char rperm, wperm, xperm, private_or_shared;
    W64 offset = 0;
    int devmajor = 0;
    int devminor = 0;
    W64 inode = 0;

    int n = sscanf(s, "%lx-%lx %c%c%c%c %llx %x:%x %lld", (unsigned long*) &start, (unsigned long*) &stop, &rperm, &wperm, &xperm, &private_or_shared, &offset, &devmajor, &devminor, &inode);

    if (n != 10) {
      cout << "Warning: /proc/self/maps not in proper format (n = ", n, ")", endl, flush;
      assert(false);
      break;
    }

    char* pattr = strrchr(s, '[');
    char* pfilename = strrchr(s, '/');
    //
    // vdso is the kernel syscall gateway page and contains things
    // like the gettimeofday and getpid vsyscalls, various TLS fields
    // and so on. It is not really a user page, it just happens to
    // be accessible to accelerate common syscalls. Unfortunately
    // some kernels incorrectly report the size of this region,
    // but it is always 4 KB long.
    //

    map->start = start;
    map->length = stop - start;

    bool vdso = ((pattr && strequal(pattr, "[vdso]")) || 
        ((map->start == (byte*)0xffffe000) &&
         (map->length == PAGE_SIZE)));

    // 2.6 kernels always have the stack second-to-last and vdso last in the list:
    bool stack = (((pattr && strequal(pattr, "[stack]")) || 
                   (line == (linecount-2))) ? MAP_STACK : 0);

    map->prot = 
      ((rperm == 'r') ? PROT_READ : 0) |
      ((wperm == 'w') ? PROT_WRITE : 0) |
      ((xperm == 'x') ? PROT_EXEC : 0);
    map->flags =
      ((private_or_shared == 'p') ? MAP_PRIVATE : 0) |
      ((private_or_shared == 's') ? MAP_SHARED : 0) |
      ((!devmajor && !devminor && !inode) ? MAP_ANONYMOUS : 0) |
      (stack ? MAP_STACK : 0) |
      ((pattr && strequal(pattr, "[heap]")) ? MAP_HEAP : 0) |
      ((pfilename && strequal(pfilename, "/zero (deleted)")) ? MAP_ZERO : 0) |
      (vdso ? MAP_VDSO : 0);

    if (vdso) map->length = PAGE_SIZE;

    map->devmajor = devmajor;
    map->devminor = devminor;
    map->offset = (Waddr)offset;
    map->inode = inode;

    // In some kernel versions (at least 2.6.11 and below), the VDSO page is given
    // in /proc/xxx/maps with no permissions (bug?), so we correct that here:
    if (map->flags & MAP_VDSO) map->prot |= PROT_READ|PROT_EXEC;

    map++;
    line++;
  }

  ptl_mm_free_private_pages(mapdata, MAX_PROC_MAPS_SIZE);
  sys_close(fd);
  return map - startmap;
}

ostream& operator <<(ostream& os, const MemoryMapExtent& map) {
  os << ((map.flags & MAP_ANONYMOUS) ? 'a' : '-');
  os << ((map.prot & PROT_READ) ? 'r' : '-');
  os << ((map.prot & PROT_WRITE) ? 'w' : '-');
  os << ((map.prot & PROT_EXEC) ? 'x' : '-');
  os << ((map.flags & MAP_PRIVATE) ? 'p' : 
         (map.flags & MAP_SHARED) ? 's' : '-');
  os << ((map.flags & MAP_STACK) ? 'S' : 
         (map.flags & MAP_HEAP) ? 'h' :
         (map.flags & MAP_VDSO) ? 'v' : 
         (map.flags & MAP_ZERO) ? 'z' : '-');
  os << " ";
  stringbuf sb;
  sb << (void*)map.start;
  os << "  ", padstring(sb, 18), " ", intstring(map.length >> 10, 16), " KB ";
  if (!(map.flags & MAP_ANONYMOUS)) {
    sb.reset();
    sb << "0x", hexstring(map.offset, 64);
    os << padstring((map.offset) ? (char*)sb : "0", 10), " in ", map.devmajor, ".", map.devminor, ".", map.inode;
  }
  return os;
}

#define MAX_MAPS_PER_PROCESS 65536

void AddressSpace::resync_with_process_maps() {
  bool DEBUG = 1;

  asp.reset();

  MemoryMapExtent* mapstart = (MemoryMapExtent*)ptl_mm_alloc_private_pages(MAX_MAPS_PER_PROCESS * sizeof(MemoryMapExtent));
  int n = mqueryall(mapstart, MAX_MAPS_PER_PROCESS);
  Waddr stackbase = 0;

  ThreadState* tls = getcurrent();

  MemoryMapExtent* map = mapstart;

  logfile << "resync_with_process_maps: found ", n, " memory map extents:", endl;
  foreach (i, n) {
    logfile << "  ", mapstart[i], endl;
  }
  logfile << flush;

  foreach (i, n) {
    if (map->flags & MAP_STACK) stackbase = (Waddr)map->start;
    setattr(map->start, map->length, (map->flags & MAP_ZERO) ? 0 : map->prot);
    map++;
  }

  ptl_mm_free_private_pages(mapstart, MAX_MAPS_PER_PROCESS * sizeof(MemoryMapExtent));

  // Find current brk value kernel thinks we are using:
  brk = sys_brk(null);
  if (DEBUG) logfile << "resync_with_process_maps: brk from ", (void*)brkbase, " to ", (void*)brk, endl;

  if (DEBUG) {
    logfile << "resync_with_process_maps: fs ", hexstring(ctx.seg[SEGID_FS].selector, 16),
      ", fsbase ", (void*)(Waddr)ctx.seg[SEGID_FS].base, 
      ", gs ", hexstring(ctx.seg[SEGID_GS].selector, 16),
      ", gsbase ", (void*)(Waddr)ctx.seg[SEGID_GS].base, endl;
  }

  Waddr stackleft = stackbase - stack_min_addr;

  if (DEBUG) logfile << "  Original user stack range: ", (void*)stack_min_addr, " to ", (void*)stack_max_addr, " (", (stack_max_addr - stack_min_addr), " bytes)", endl, flush;

  if (DEBUG) logfile << "  Stack from ", (void*)stack_min_addr, " to ", (void*)stackbase, " (", stackleft, " bytes) is allocate-on-access", endl, flush;

  //
  // Make sure the user code does not see and cannot access PTL native code.
  // When running x86-64 apps, all PTL native code resides (for now) at 
  // 0x70000000 - 0x78000000. This region is marked as do-not-touch.
  //
  // In arch/x86_64/kernel/sys_x86_64.c: find_start_end() and arch_get_unmapped_area():
  // If MAP_32BIT is specified, pages are only allocated
  // in the 1GB range 0x70000000 to 0x78000000.
  //
  // All 64-bit mmap allocations start at 0x2AAAAAAAA000; i.e., floor(0x800000000000 / 3, PAGE_SIZE)
  //
  // Hence, using this simplistic approach works fine on 2.6.x kernels.
  //
  setattr((void*)PTL_IMAGE_BASE, PTL_IMAGE_SIZE, PROT_NONE);
}

// In userspace PTLsim, virtual == physical:
RIPVirtPhys& RIPVirtPhys::update(Context& ctx, int bytes) {
  use64 = ctx.use64;
  kernel = 0;
  df = ((ctx.internal_eflags & FLAG_DF) != 0);
  padlo = 0;
  padhi = 0;
  mfnlo = rip >> 12;
  mfnhi = (rip + (bytes-1)) >> 12;
  return *this;
}

// Saved and restored by asm code:
FXSAVEStruct x87state;
W16 saved_cs;
W16 saved_ss;
W16 saved_ds;
W16 saved_es;
W16 saved_fs;
W16 saved_gs;

#define ARCH_ENABLE_EXIT_HOOK 0x2001
#define ARCH_SET_EXIT_HOOK_ADDR 0x2002

extern "C" void switch_to_sim_save_context();

// This can be brought down considerably in the future: 
#define SIM_THREAD_STACK_SIZE (1024*1024*4)

extern "C" void switch_to_sim_save_context();

bool running_in_sim_mode = 0;

#ifdef __x86_64__
struct FarJumpDescriptor {
  W32 offset;
  W16 seg;

  FarJumpDescriptor() { }

  void setup(void* target) {
    offset = LO32((W64)target);
    seg = 0x33;
  }

  FarJumpDescriptor(void* target) {
    setup(target);
  }
};

FarJumpDescriptor switch_to_native_desc;

void switch_stack_and_jump_32_or_64(void* code, void* stack, bool use64) {
  if (use64) {
    // Currently in 64-bit mode anyway, so no need to go through a far jump; in fact
    // this is impossible because far jumps only encode 32 bits of target address.
    asm volatile("mov %[stack],%%rsp\n"
                 "jmp *%[code]\n" : : [code] "r" (code), [stack] "m" (stack));
  } else {
    // 64-bit PTLsim to 32-bit x86 jump:
    
    switch_to_native_desc.offset = (W64)code;
    switch_to_native_desc.seg = 0x23;

    asm volatile("mov %[stack],%%rsp\n"
                 "ljmp *(%[desc])\n" : : [desc] "r" (&switch_to_native_desc), [stack] "m" (stack));
  }
}

extern "C" void save_context_switch_to_sim_lowlevel();
FarJumpDescriptor switch_to_sim_save_context_indirect;

struct SwitchToSimThunkCode {
  byte opcode[3];
  W32 indirtarget;

  SwitchToSimThunkCode() { }

  void farjump(FarJumpDescriptor& target) {
    if (ctx.use64) {
      // ff 2c 25 xx xx xx xx = ljmp ds:[imm32]
      opcode[0] = 0xff;
      opcode[1] = 0x2c;
      opcode[2] = 0x25;
    } else {
      // 90 ff 2d xx xx xx xx = nop | ljmp ds:[imm32]
      opcode[0] = 0x90;
      opcode[1] = 0xff;
      opcode[2] = 0x2d;
    }
    indirtarget = LO32((W64)&target);
  }

  void indircall(W64& ptr) {
    if (ctx.use64) {
      // ff 14 25 xx xx xx xx = call ds:[imm32]
      opcode[0] = 0xff; opcode[1] = 0x14; opcode[2] = 0x25;
    } else {
      // 90 ff 15 xx xx xx xx = nop | call ds:[imm32]
      opcode[0] = 0x90; opcode[1] = 0xff; opcode[2] = 0x15;
    }
    indirtarget = LO32((W64)&ptr);
  }

  void indirjump(W64& ptr) {
    if (ctx.use64) {
      // ff 24 25 xx xx xx xx = jmp ds:[imm32]
      opcode[0] = 0xff; opcode[1] = 0x24; opcode[2] = 0x25;
    } else {
      // 90 ff 25 xx xx xx xx = nop | jmp ds:[imm32]
      opcode[0] = 0x90; opcode[1] = 0xff; opcode[2] = 0x25;
    }
    indirtarget = LO32((W64)&ptr);
  }
} __attribute__((packed));

#ifdef __x86_64__
extern "C" void inside_sim_escape_code_template_64bit();
extern "C" void inside_sim_escape_code_template_64bit_end();
#else
extern "C" void inside_sim_escape_code_template_32bit();
extern "C" void inside_sim_escape_code_template_32bit_end();
#endif

struct InsideSimEscapeCode { 
  byte bytes[64];

  void prep() {
    byte* src;
    int length;
    // Make sure PTLsim build type matches target process type:
#ifdef __x86_64__
    assert(ctx.use64);
    src = (byte*)&inside_sim_escape_code_template_64bit;
    length = ((byte*)&inside_sim_escape_code_template_64bit_end) - src;
#else
    assert(!ctx.use64);
    src = (byte*)&inside_sim_escape_code_template_32bit;
    length = ((byte*)&inside_sim_escape_code_template_32bit_end) - src;
#endif
    assert(length <= lengthof(bytes));
    memcpy(&bytes, src, length);
  }
};
#else // ! __x86_64__

extern "C" void save_context_switch_to_sim_lowlevel();
W64 switch_to_sim_save_context_indirect;

struct SwitchToSimThunkCode {
  byte opcode[3];
  W32 indirtarget;

  SwitchToSimThunkCode() { }

  void indirjump(W64& ptr) {
    // 90 ff 25 xx xx xx xx = nop | jmp ds:[imm32]
    opcode[0] = 0x90; opcode[1] = 0xff; opcode[2] = 0x25;
    indirtarget = LO32((W32)&ptr);
  }
} __attribute__((packed));

extern "C" void inside_sim_escape_code_template_32bit();
extern "C" void inside_sim_escape_code_template_32bit_end();

struct InsideSimEscapeCode { 
  byte bytes[64];

  void prep() {
    byte* src;
    int length;
    src = (byte*)&inside_sim_escape_code_template_32bit;
    length = ((byte*)&inside_sim_escape_code_template_32bit_end) - src;
    assert(length <= lengthof(bytes));
    memcpy(&bytes, src, length);
  }
};

#endif // ! __x86_64__

struct PTLsimThunkPagePrivate: public PTLsimThunkPage {
  SwitchToSimThunkCode switch_to_sim_thunk;
  InsideSimEscapeCode call_within_sim_thunk;
};

void enable_ptlsim_call_gate() {
  PTLsimThunkPagePrivate* thunkpage = (PTLsimThunkPagePrivate*)PTLSIM_THUNK_PAGE;
  thunkpage->magic = PTLSIM_THUNK_MAGIC;
}

void disable_ptlsim_call_gate() {
  PTLsimThunkPagePrivate* thunkpage = (PTLsimThunkPagePrivate*)PTLSIM_THUNK_PAGE;
  thunkpage->magic = 0;
}

void setup_sim_thunk_page() {
  PTLsimThunkPagePrivate* thunkpage = (PTLsimThunkPagePrivate*)PTLSIM_THUNK_PAGE;

  // Map in the PTL call gate page. This is NOT a PTL private page, so make sure the user can access it too:
  Waddr v = (Waddr)asp.mmap(thunkpage, 4*PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
  assert(v == PTLSIM_THUNK_PAGE);

  thunkpage->simulated = 0;
  thunkpage->call_code_addr = 0; // (initialized later)
#ifdef __x86_64__
  switch_to_sim_save_context_indirect.setup((void*)&save_context_switch_to_sim_lowlevel);
  thunkpage->switch_to_sim_thunk.farjump(switch_to_sim_save_context_indirect);
#else // ! __x86_64__
  switch_to_sim_save_context_indirect = (Waddr)&save_context_switch_to_sim_lowlevel;
  thunkpage->switch_to_sim_thunk.indirjump(switch_to_sim_save_context_indirect);
#endif
  thunkpage->call_within_sim_thunk.prep();
  enable_ptlsim_call_gate();
}

SwitchToSimThunkCode saved_bytes_behind_switch_to_sim_thunk;
SwitchToSimThunkCode* pending_patched_switch_to_sim_addr = null;

void set_switch_to_sim_breakpoint(void* addr) {
  SwitchToSimThunkCode* thunk = (SwitchToSimThunkCode*)addr;
  PTLsimThunkPagePrivate* thunkpage = (PTLsimThunkPagePrivate*)PTLSIM_THUNK_PAGE;

  sys_mprotect(floorptr(addr, PAGE_SIZE), 2*PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC);
  saved_bytes_behind_switch_to_sim_thunk = *thunk;
  thunk->indirjump(thunkpage->call_code_addr);
  pending_patched_switch_to_sim_addr = thunk;

  logfile << endl, "Breakpoint inserted at rip ", addr, endl, flush;
}

bool remove_switch_to_sim_breakpoint() {
  if (pending_patched_switch_to_sim_addr) {
    ctx.commitarf[REG_rip] = (Waddr)pending_patched_switch_to_sim_addr;
    logfile << endl, "=== Removed thunk patch at rip ", pending_patched_switch_to_sim_addr, " ===", endl, flush;
    *pending_patched_switch_to_sim_addr = saved_bytes_behind_switch_to_sim_thunk;
    pending_patched_switch_to_sim_addr = 0;
    return true;
  }
  return false;
}

extern "C" void switch_to_native_restore_context_lowlevel(const UserContext& ctx, int switch_64_to_32);

void switch_to_native_restore_context() {
  PTLsimThunkPagePrivate* thunkpage = (PTLsimThunkPagePrivate*)PTLSIM_THUNK_PAGE;

  thunkpage->call_code_addr = (Waddr)&thunkpage->switch_to_sim_thunk;
  thunkpage->simulated = 0;

  saved_cs = ctx.seg[SEGID_CS].selector;
  saved_ss = ctx.seg[SEGID_SS].selector;
  saved_ds = ctx.seg[SEGID_DS].selector;
  saved_es = ctx.seg[SEGID_ES].selector;
  saved_fs = ctx.seg[SEGID_FS].selector;
  saved_gs = ctx.seg[SEGID_GS].selector;

  ctx.commitarf[REG_flags] = 
    (ctx.internal_eflags & ~(FLAG_ZAPS|FLAG_CF|FLAG_OF)) |
    (ctx.commitarf[REG_flags] & (FLAG_ZAPS|FLAG_CF|FLAG_OF));

  ctx.fxsave(x87state);

  logfile << endl, "=== Preparing to switch to native mode at rip ", (void*)(Waddr)ctx.commitarf[REG_rip], " ===", endl, endl, flush;

  logfile << "Final state:", endl;
  logfile << ctx;

  logfile << endl, "=== Switching to native mode at rip ", (void*)(Waddr)ctx.commitarf[REG_rip], " ===", endl, endl, flush;
  switch_to_native_restore_context_lowlevel(ctx.commitarf, !ctx.use64);
}

// Main function (see below)
void switch_to_sim();

// Called by save_context_switch_to_sim_lowlevel
extern "C" void save_context_switch_to_sim() {
  if (!remove_switch_to_sim_breakpoint()) {
    logfile << endl, "=== Trigger request ===", endl, flush;
    // REG_rip set from first word on stack, but REG_rsp needs to be incremented
    ctx.commitarf[REG_rsp] += (ctx.use64) ? 8 : 4;
  }

  ctx.commitarf[REG_ctx] = (Waddr)&ctx;
  ctx.commitarf[REG_fpstack] = (Waddr)&ctx.fpstack;

  ctx.internal_eflags = ctx.commitarf[REG_flags];
  ctx.commitarf[REG_flags] &= ~(FLAG_INV|FLAG_WAIT);
  ctx.seg[SEGID_CS].selector = saved_cs;
  ctx.seg[SEGID_SS].selector = saved_ss;
  ctx.seg[SEGID_DS].selector = saved_ds;
  ctx.seg[SEGID_ES].selector = saved_es;
  ctx.seg[SEGID_FS].selector = saved_fs;
  ctx.seg[SEGID_GS].selector = saved_gs;
  ctx.update_shadow_segment_descriptors();
  ctx.fxrstor(x87state);

#ifdef __x86_64__
  if (!ctx.use64) ctx.commitarf[REG_rip] &= 0xffffffff;
#endif

  logfile << endl, "=== Switching to simulation mode at rip ", (void*)(Waddr)ctx.commitarf[REG_rip], " ===", endl, endl, flush;

  asp.resync_with_process_maps();

  PTLsimThunkPagePrivate* thunkpage = (PTLsimThunkPagePrivate*)PTLSIM_THUNK_PAGE;
  thunkpage->call_code_addr = (Waddr)&thunkpage->call_within_sim_thunk;
  thunkpage->simulated = 1;

  switch_to_sim();
}

void Context::propagate_x86_exception(byte exception, W32 errorcode, Waddr virtaddr) {
  Waddr rip = ctx.commitarf[REG_selfrip];

  logfile << "Exception ", exception, " (", x86_exception_names[exception], ") @ rip ", (void*)(Waddr)commitarf[REG_rip], " (", total_user_insns_committed, " commits, ", sim_cycle, " cycles)", endl, flush;
  cerr << "Exception ", exception, " (", x86_exception_names[exception], ") @ rip ", (void*)(Waddr)commitarf[REG_rip], " (", total_user_insns_committed, " commits, ", sim_cycle, " cycles)", endl, flush;

  if (config.dumpcode_filename.set()) {
    byte insnbuf[1024];
    PageFaultErrorCode insn_pfec;
    Waddr insn_faultaddr;
    int valid_byte_count = copy_from_user(insnbuf, rip, sizeof(insnbuf), insn_pfec, insn_faultaddr);

    logfile << "Writing ", valid_byte_count, " bytes from rip ", (void*)rip, " to ", ((char*)config.dumpcode_filename), "...", endl, flush;
    odstream("dumpcode.dat").write(insnbuf, sizeof(insnbuf));
  }

  logfile << "Aborting...", endl, flush;
  cerr << "Aborting...", endl, flush;
  assert(false);
}

#ifdef __x86_64__

const char* syscall_names_64bit[] = {
  "read", "write", "open", "close", "stat", "fstat", "lstat", "poll", "lseek", "mmap", "mprotect", "munmap", "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl", "pread64", "pwrite64", "readv", "writev", "access", "pipe", "select", "sched_yield", "mremap", "msync", "mincore", "madvise", "shmget", "shmat", "shmctl", "dup", "dup2", "pause", "nanosleep", "getitimer", "alarm", "setitimer", "getpid", "sendfile", "socket", "connect", "accept", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown", "bind", "listen", "getsockname", "getpeername", "socketpair", "setsockopt", "getsockopt", "clone", "fork", "vfork", "execve", "exit", "wait4", "kill", "uname", "semget", "semop", "semctl", "shmdt", "msgget", "msgsnd", "msgrcv", "msgctl", "fcntl", "flock", "fsync", "fdatasync", "truncate", "ftruncate", "getdents", "getcwd", "chdir", "fchdir", "rename", "mkdir", "rmdir", "creat", "link", "unlink", "symlink", "readlink", "chmod", "fchmod", "chown", "fchown", "lchown", "umask", "gettimeofday", "getrlimit", "getrusage", "sysinfo", "times", "ptrace", "getuid", "syslog", "getgid", "setuid", "setgid", "geteuid", "getegid", "setpgid", "getppid", "getpgrp", "setsid", "setreuid", "setregid", "getgroups", "setgroups", "setresuid", "getresuid", "setresgid", "getresgid", "getpgid", "setfsuid", "setfsgid", "getsid", "capget", "capset", "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo", "rt_sigsuspend", "sigaltstack", "utime", "mknod", "uselib", "personality", "ustat", "statfs", "fstatfs", "sysfs", "getpriority", "setpriority", "sched_setparam", "sched_getparam", "sched_setscheduler", "sched_getscheduler", "sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval", "mlock", "munlock", "mlockall", "munlockall", "vhangup", "modify_ldt", "pivot_root", "_sysctl", "prctl", "arch_prctl", "adjtimex", "setrlimit", "chroot", "sync", "acct", "settimeofday", "mount", "umount2", "swapon", "swapoff", "reboot", "sethostname", "setdomainname", "iopl", "ioperm", "create_module", "init_module", "delete_module", "get_kernel_syms", "query_module", "quotactl", "nfsservctl", "getpmsg", "putpmsg", "afs_syscall", "tuxcall", "security", "gettid", "readahead", "setxattr", "lsetxattr", "fsetxattr", "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr", "removexattr", "lremovexattr", "fremovexattr", "tkill", "time", "futex", "sched_setaffinity", "sched_getaffinity", "set_thread_area", "io_setup", "io_destroy", "io_getevents", "io_submit", "io_cancel", "get_thread_area", "lookup_dcookie", "epoll_create", "epoll_ctl_old", "epoll_wait_old", "remap_file_pages", "getdents64", "set_tid_address", "restart_syscall", "semtimedop", "fadvise64", "timer_create", "timer_settime", "timer_gettime", "timer_getoverrun", "timer_delete", "clock_settime", "clock_gettime", "clock_getres", "clock_nanosleep", "exit_group", "epoll_wait", "epoll_ctl", "tgkill", "utimes", "vserver", "vserver", "mbind", "set_mempolicy", "get_mempolicy", "mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive", "mq_notify", "mq_getsetattr", "kexec_load", "waitid"};

//
// SYSCALL instruction from x86-64 mode
//

void handle_syscall_64bit() {
  bool DEBUG = 1; //analyze_in_detail();
  //
  // Handle an x86-64 syscall:
  // (This is called from the assist_syscall ucode assist)
  //

  int syscallid = ctx.commitarf[REG_rax];
  W64 arg1 = ctx.commitarf[REG_rdi];
  W64 arg2 = ctx.commitarf[REG_rsi];
  W64 arg3 = ctx.commitarf[REG_rdx];
  W64 arg4 = ctx.commitarf[REG_r10];
  W64 arg5 = ctx.commitarf[REG_r8];
  W64 arg6 = ctx.commitarf[REG_r9];

  if (DEBUG) 
    logfile << "handle_syscall -> (#", syscallid, " ", ((syscallid < lengthof(syscall_names_64bit)) ? syscall_names_64bit[syscallid] : "???"), 
      ") from ", (void*)ctx.commitarf[REG_rcx], " args ", " (", (void*)arg1, ", ", (void*)arg2, ", ", (void*)arg3, ", ", (void*)arg4, ", ",
      (void*)arg5, ", ", (void*)arg6, ") at iteration ", iterations, endl, flush;

  switch (syscallid) {
  case __NR_64bit_mmap:
    ctx.commitarf[REG_rax] = (W64)asp.mmap((void*)arg1, arg2, arg3, arg4, arg5, arg6);
    break;
  case __NR_64bit_munmap:
    ctx.commitarf[REG_rax] = asp.munmap((void*)arg1, arg2);
    break;
  case __NR_64bit_mprotect:
    ctx.commitarf[REG_rax] = asp.mprotect((void*)arg1, arg2, arg3);
    break;
  case __NR_64bit_brk:
    ctx.commitarf[REG_rax] = (W64)asp.setbrk((void*)arg1);
    break;
  case __NR_64bit_mremap: {
    ctx.commitarf[REG_rax] = (W64)asp.mremap((void*)arg1, arg2, arg3, arg4);
    break;
  }
  case __NR_64bit_arch_prctl: {
    // We need to trap this so we can virtualize ARCH_SET_FS and ARCH_SET_GS:
    ctx.commitarf[REG_rax] = sys_arch_prctl(arg1, (void*)arg2);
    ctx.update_shadow_segment_descriptors();
    switch (arg1) {
    case ARCH_SET_FS:
      ctx.seg[SEGID_FS].base = arg2;
      logfile << "arch_prctl: set FS base to ", (void*)ctx.seg[SEGID_FS].base, endl;
      break;
    case ARCH_SET_GS:
      ctx.seg[SEGID_GS].base = arg2;
      logfile << "arch_prctl: set GS base to ", (void*)ctx.seg[SEGID_GS].base, endl;
      break;
    }
    break;
  }
  case __NR_64bit_exit: {
    logfile << "handle_syscall at iteration ", iterations, ": exit(): exiting with arg ", (W64s)arg1, "...", endl, flush;
    user_process_terminated((int)arg1);
  }
  case __NR_64bit_exit_group: {
    logfile << "handle_syscall at iteration ", iterations, ": exit_group(): exiting with arg ", (W64s)arg1, "...", endl, flush;
    user_process_terminated((int)arg1);
  }
  case __NR_64bit_rt_sigaction: {
    // This is only so we receive SIGSEGV on our own:
#if 1
    logfile << "handle_syscall: signal(", arg1, ", ", (void*)arg2, ")", endl, flush;
    ctx.commitarf[REG_rax] = 0;
#else
    ctx.commitarf[REG_rax] = do_syscall_64bit(syscallid, arg1, arg2, arg3, arg4, arg5, arg6);
#endif
    break;
  }
  case __NR_64bit_alarm: {
    // Do not allow SIGALRM (we cannot handle it properly inside PTLsim and the timing is wrong anyway)
    // NOTE: This may break some programs!
#if 1
    logfile << "handle_syscall: alarm(", arg1, ")", endl, flush;
    ctx.commitarf[REG_rax] = 0;
#else
    ctx.commitarf[REG_rax] = do_syscall_64bit(syscallid, arg1, arg2, arg3, arg4, arg5, arg6);
#endif
    break;
  }
  default:
    ctx.commitarf[REG_rax] = do_syscall_64bit(syscallid, arg1, arg2, arg3, arg4, arg5, arg6);
    break;
  }
  //ctx.commitarf[REG_rax] = -EINVAL;
  ctx.commitarf[REG_rip] = ctx.commitarf[REG_rcx];

  if (DEBUG) logfile << "handle_syscall: result ", ctx.commitarf[REG_rax], " (", (void*)ctx.commitarf[REG_rax], "); returning to ", (void*)ctx.commitarf[REG_rip], endl, flush;
}

#endif // __x86_64__

struct old_mmap32_arg_struct {
  W32 addr;
  W32 len;
  W32 prot;
  W32 flags;
  W32 fd;
  W32 offset;
};

const char* syscall_names_32bit[] = {"restart_syscall", "exit", "fork", "read", "write", "open", "close", "waitpid", "creat", "link", "unlink", "execve", "chdir", "time", "mknod", "chmod", "lchown", "break", "oldstat", "lseek", "getpid", "mount", "umount", "setuid", "getuid", "stime", "ptrace", "alarm", "oldfstat", "pause", "utime", "stty", "gtty", "access", "nice", "ftime", "sync", "kill", "rename", "mkdir", "rmdir", "dup", "pipe", "times", "prof", "brk", "setgid", "getgid", "signal", "geteuid", "getegid", "acct", "umount2", "lock", "ioctl", "fcntl", "mpx", "setpgid", "ulimit", "oldolduname", "umask", "chroot", "ustat", "dup2", "getppid", "getpgrp", "setsid", "sigaction", "sgetmask", "ssetmask", "setreuid", "setregid", "sigsuspend", "sigpending", "sethostname", "setrlimit", "getrlimit", "getrusage", "gettimeofday", "settimeofday", "getgroups", "setgroups", "select", "symlink", "oldlstat", "readlink", "uselib", "swapon", "reboot", "readdir", "mmap", "munmap", "truncate", "ftruncate", "fchmod", "fchown", "getpriority", "setpriority", "profil", "statfs", "fstatfs", "ioperm", "socketcall", "syslog", "setitimer", "getitimer", "stat", "lstat", "fstat", "olduname", "iopl", "vhangup", "idle", "vm86old", "wait4", "swapoff", "sysinfo", "ipc", "fsync", "sigreturn", "clone", "setdomainname", "uname", "modify_ldt", "adjtimex", "mprotect", "sigprocmask", "create_module", "init_module", "delete_module", "get_kernel_syms", "quotactl", "getpgid", "fchdir", "bdflush", "sysfs", "personality", "afs_syscall", "setfsuid", "setfsgid", "_llseek", "getdents", "_newselect", "flock", "msync", "readv", "writev", "getsid", "fdatasync", "_sysctl", "mlock", "munlock", "mlockall", "munlockall", "sched_setparam", "sched_getparam", "sched_setscheduler", "sched_getscheduler", "sched_yield", "sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval", "nanosleep", "mremap", "setresuid", "getresuid", "vm86", "query_module", "poll", "nfsservctl", "setresgid", "getresgid", "prctl", "rt_sigreturn", "rt_sigaction", "rt_sigprocmask", "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo", "rt_sigsuspend", "pread64", "pwrite64", "chown", "getcwd", "capget", "capset", "sigaltstack", "sendfile", "getpmsg", "putpmsg", "vfork", "ugetrlimit", "mmap2", "truncate64", "ftruncate64", "stat64", "lstat64", "fstat64", "lchown32", "getuid32", "getgid32", "geteuid32", "getegid32", "setreuid32", "setregid32", "getgroups32", "setgroups32", "fchown32", "setresuid32", "getresuid32", "setresgid32", "getresgid32", "chown32", "setuid32", "setgid32", "setfsuid32", "setfsgid32", "pivot_root", "mincore", "madvise", "madvise1", "getdents64", "fcntl64", "<unused>", "<unused>", "gettid", "readahead", "setxattr", "lsetxattr", "fsetxattr", "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr", "removexattr", "lremovexattr", "fremovexattr", "tkill", "sendfile64", "futex", "sched_setaffinity", "sched_getaffinity", "set_thread_area", "get_thread_area", "io_setup", "io_destroy", "io_getevents", "io_submit", "io_cancel", "fadvise64", "<unused>", "exit_group", "lookup_dcookie", "epoll_create", "epoll_ctl", "epoll_wait", "remap_file_pages", "set_tid_address", "timer_create", "statfs64", "fstatfs64", "tgkill", "utimes", "fadvise64_64", "vserver", "mbind", "get_mempolicy", "set_mempolicy", "mq_open", "sys_kexec_load", "waitid"};

W32 sysenter_retaddr = 0;

W32 get_sysenter_retaddr(W32 end_of_sysenter_insn) {
  if (!sysenter_retaddr) {
    byte* p = (byte*)(Waddr)end_of_sysenter_insn;
    logfile << "First sysenter call: finding return point starting from ", p, endl, flush;
    while (*p == 0x90) p++;
    assert(*p == 0xeb); // short jump
    p += 2;
    assert(*p == 0x5d); // "pop %ebp" instruction
    logfile << "Found sysenter return address at ", p, endl, flush;
    sysenter_retaddr = (W32)(Waddr)p;
  }
  return sysenter_retaddr;
}

void handle_syscall_32bit(int semantics) {
  bool DEBUG = 1; //analyze_in_detail();
  //
  // Handle a 32-bit syscall:
  // (This is called from the assist_syscall ucode assist)
  //

  static const char* semantics_name[] = {"int80", "syscall", "sysenter"};

  int syscallid;
  W32 arg1, arg2, arg3, arg4, arg5, arg6;
  W32 retaddr;

  if (semantics == SYSCALL_SEMANTICS_INT80) {
    //
    // int 0x80 can be called from either 32-bit or 64-bit mode,
    // but in 64-bit mode, its semantics exactly match the 32-bit
    // semantics, i.e. x86 syscall IDs, truncates addresses to 32
    // bits, etc.
    //
    syscallid = ctx.commitarf[REG_rax];
    arg1 = ctx.commitarf[REG_rbx];
    arg2 = ctx.commitarf[REG_rcx];
    arg3 = ctx.commitarf[REG_rdx];
    arg4 = ctx.commitarf[REG_rsi];
    arg5 = ctx.commitarf[REG_rdi];
    arg6 = ctx.commitarf[REG_rbp];
    retaddr = ctx.commitarf[REG_nextrip];
  } else if (semantics == SYSCALL_SEMANTICS_SYSENTER) {
    //
    // SYSENTER is just like int 0x80, but it only works in 32-bit
    // mode. Its semantics are identical to int 0x80, except that
    // %ebp contains the stack pointer to restore, and *(%ebp)
    // is the sixth argument. It always returns to a fixed address
    // in the VDSO page, so there's no need to store the address.
    // We do need to dynamically find that address though.
    //
    retaddr = get_sysenter_retaddr(ctx.commitarf[REG_nextrip]);

    assert(!ctx.use64);
    syscallid = ctx.commitarf[REG_rax];
    arg1 = ctx.commitarf[REG_rbx];
    arg2 = ctx.commitarf[REG_rcx];
    arg3 = ctx.commitarf[REG_rdx];
    arg4 = ctx.commitarf[REG_rsi];
    arg5 = ctx.commitarf[REG_rdi];

    W32* arg6ptr = (W32*)(Waddr)LO32(ctx.commitarf[REG_rbp]);

    if (!asp.check(arg6ptr, PROT_READ)) {
      ctx.commitarf[REG_rax] = (W64)(-EFAULT);
      ctx.commitarf[REG_rip] = retaddr;
      if (DEBUG) logfile << "handle_syscall (#", syscallid, " ", ((syscallid < lengthof(syscall_names_32bit)) ? syscall_names_32bit[syscallid] : "???"), 
                   " via ", semantics_name[semantics], ") from ", (void*)(Waddr)retaddr, " args ", " (", (void*)(Waddr)arg1, ", ", (void*)(Waddr)arg2, ", ", 
                   (void*)(Waddr)arg3, ", ", (void*)(Waddr)arg4, ", ", (void*)(Waddr)arg5, ", ???", ") at iteration ", iterations, ": arg6 @ ", arg6ptr,
                   " inaccessible via SYSENTER; returning -EFAULT", endl, flush;
    }

    arg6 = *arg6ptr;

  } else if (semantics == SYSCALL_SEMANTICS_SYSCALL) {
    assert(!ctx.use64);
    //
    // SYSCALL can also be used from 32-bit mode when the vsyscall
    // kernel page is used. The semantics are then as follows:
    //
    // Arguments:
    // %eax System call number.
    // %ebx Arg1
    // %ecx return EIP 
    // %edx Arg3
    // %esi Arg4
    // %edi Arg5
    // %ebp Arg2    [note: not saved in the stack frame, should not be touched]
    // %esp user stack 
    // 0(%esp) Arg6
    //
    syscallid = LO32(ctx.commitarf[REG_rax]);
    arg1 = LO32(ctx.commitarf[REG_rbx]);
    arg2 = LO32(ctx.commitarf[REG_rbp]);
    arg3 = LO32(ctx.commitarf[REG_rdx]);
    arg4 = LO32(ctx.commitarf[REG_rsi]);
    arg5 = LO32(ctx.commitarf[REG_rdi]);
    retaddr = ctx.commitarf[REG_rcx];

    W32* arg6ptr = (W32*)(Waddr)LO32(ctx.commitarf[REG_rsp]);

    if (!asp.check(arg6ptr, PROT_READ)) {
      ctx.commitarf[REG_rax] = (W64)(-EFAULT);
      ctx.commitarf[REG_rip] = retaddr;
      if (DEBUG) logfile << "handle_syscall (#", syscallid, " ", ((syscallid < lengthof(syscall_names_32bit)) ? syscall_names_32bit[syscallid] : "???"), 
                   " via ", semantics_name[semantics], ") from ", (void*)(Waddr)retaddr, " args ", " (", (void*)(Waddr)arg1, ", ", (void*)(Waddr)arg2, ", ", 
                   (void*)(Waddr)arg3, ", ", (void*)(Waddr)arg4, ", ", (void*)(Waddr)arg5, ", ???", ") at iteration ", iterations, ": arg6 @ ", arg6ptr,
                   " inaccessible; returning -EFAULT", endl, flush;
    }

    arg6 = *arg6ptr;
  } else {
    assert(false);
  }

  if (DEBUG) 
    logfile << "handle_syscall (#", syscallid, " ", ((syscallid < lengthof(syscall_names_32bit)) ? syscall_names_32bit[syscallid] : "???"), 
      " via ", semantics_name[semantics], ") from ", (void*)(Waddr)retaddr, " args ", " (", (void*)(Waddr)arg1, ", ", 
      (void*)(Waddr)arg2, ", ", (void*)(Waddr)arg3, ", ", (void*)(Waddr)arg4, ", ", (void*)(Waddr)arg5, ", ", (void*)(Waddr)arg6,
      ") at iteration ", iterations, endl, flush;

  switch (syscallid) {
  case __NR_32bit_mmap2:
    // mmap2 specifies the 4KB page number to allow mapping 2^(32+12) = 2^44 bit
    // files; x86-64 mmap doesn't have this silliness:
    ctx.commitarf[REG_rax] = (Waddr)asp.mmap((void*)(Waddr)arg1, arg2, arg3, arg4, arg5, arg6 << log2(PAGE_SIZE));
    break;
  case __NR_32bit_munmap:
    ctx.commitarf[REG_rax] = asp.munmap((void*)(Waddr)arg1, arg2);
    break;
  case __NR_32bit_mprotect:
    ctx.commitarf[REG_rax] = asp.mprotect((void*)(Waddr)arg1, arg2, arg3);
    break;
  case __NR_32bit_brk:
    ctx.commitarf[REG_rax] = (Waddr)asp.setbrk((void*)(Waddr)arg1);
    break;
  case __NR_32bit_mremap:
    ctx.commitarf[REG_rax] = (Waddr)asp.mremap((void*)(Waddr)arg1, arg2, arg3, arg4);
    break;
  case __NR_32bit_exit: {
    logfile << "handle_syscall at iteration ", iterations, ": exit(): exiting with arg ", (W64s)arg1, "...", endl, flush;
    user_process_terminated((int)arg1);
  }
  case __NR_32bit_exit_group: {
    logfile << "handle_syscall at iteration ", iterations, ": exit_group(): exiting with arg ", (W64s)arg1, "...", endl, flush;
    user_process_terminated((int)arg1);
  }
  case __NR_32bit_set_thread_area: {
    user_desc_32bit* desc = (user_desc_32bit*)(Waddr)arg1;
    ctx.commitarf[REG_rax] = do_syscall_32bit(syscallid, arg1, 0, 0, 0, 0, 0);
    if (!ctx.commitarf[REG_rax]) {
      logfile << "handle_syscall at iteration ", iterations, ": set_thread_area: LDT desc 0x", 
        hexstring(((desc->entry_number << 3) + 3), 16), " now has base ", (void*)(Waddr)desc->base_addr, endl, flush;
      ldt_seg_base_cache[desc->entry_number] = desc->base_addr;
      ctx.update_shadow_segment_descriptors();
    }
    break;
  }
  case __NR_32bit_rt_sigaction: {
    //++MTY This is only so we receive SIGSEGV on our own:
#if 1
    logfile << "handle_syscall: signal(", arg1, ", ", (void*)(Waddr)arg2, ")", endl, flush;
    ctx.commitarf[REG_rax] = 0;
#else
    ctx.commitarf[REG_rax] = do_syscall_32bit(syscallid, arg1, arg2, arg3, arg4, arg5, arg6);
#endif
    break;
  }
  case __NR_32bit_alarm: {
    // Do not allow SIGALRM (we cannot handle it properly inside PTLsim and the timing is wrong anyway)
    // NOTE: This may break some programs!
#if 1
    logfile << "handle_syscall: alarm(", arg1, ")", endl, flush;
    ctx.commitarf[REG_rax] = 0;
#else
    ctx.commitarf[REG_rax] = do_syscall_64bit(syscallid, arg1, arg2, arg3, arg4, arg5, arg6);
#endif
    break;
  }
  case __NR_32bit_mmap: {
    old_mmap32_arg_struct* mm = (old_mmap32_arg_struct*)(Waddr)arg1;
    ctx.commitarf[REG_rax] = (Waddr)asp.mmap((void*)(Waddr)mm->addr, mm->len, mm->prot, mm->flags, mm->fd, mm->offset);
    break;
  }
  default:
    ctx.commitarf[REG_rax] = do_syscall_32bit(syscallid, arg1, arg2, arg3, arg4, arg5, arg6);
    break;
  }
  ctx.commitarf[REG_rip] = retaddr;

  if (DEBUG) logfile << "handle_syscall: result ", ctx.commitarf[REG_rax], " (", (void*)(Waddr)ctx.commitarf[REG_rax], "); returning to ", (void*)(Waddr)ctx.commitarf[REG_rip], endl, flush;
}

const char* ptlcall_names[PTLCALL_COUNT] = {"nop", "marker", "switch_to_sim", "switch_to_native", "capture_stats"};

bool requested_switch_to_native = 0;

W64 handle_ptlcall(W64 rip, W64 callid, W64 arg1, W64 arg2, W64 arg3, W64 arg4, W64 arg5) {
  logfile << "PTL call from userspace (", (void*)(Waddr)rip, "): callid ", callid, " (", ((callid < PTLCALL_COUNT) ? ptlcall_names[callid] : "UNKNOWN"), 
    ") args (", (void*)(Waddr)arg1, ", ", (void*)(Waddr)arg2, ", ", (void*)(Waddr)arg3, ", ", (void*)(Waddr)arg4, ", ", (void*)(Waddr)arg5, ")", endl, flush;
  if (callid >= PTLCALL_COUNT) return (W64)(-EINVAL);

  switch (callid) {
  case PTLCALL_NOP: {
    logfile << "  (no operation)", endl;
    break;
  }
  case PTLCALL_MARKER: {
    logfile << "  MARKER: iteration ", iterations, ", cycle ", sim_cycle, ", user commits ", total_user_insns_committed, endl;
    break;
  };
  case PTLCALL_SWITCH_TO_SIM: {
    logfile << "  WARNING: already running in simulation mode", endl;
    return (W64)(-EINVAL);
  }
  case PTLCALL_CAPTURE_STATS: {
    const char* snapshotname = (const char*)(Waddr)arg1;
    if (asp.check((void*)snapshotname, PROT_READ)) {
      capture_stats_snapshot(snapshotname);
    } else {
      logfile << "WARNING: invalid snapshotname pointer (", snapshotname, "); using default snapshot ID", endl;
      capture_stats_snapshot(null);
    }
    break;
  }
  case PTLCALL_SWITCH_TO_NATIVE: {
    logfile << "  Switching to native mode at rip ", (void*)(Waddr)rip, endl;
    requested_switch_to_native = 1;
    break;
  }
  }
  return 0;
}

// This is where we end up after issuing opcode 0x0f37 (undocumented x86 PTL call opcode)
void assist_ptlcall(Context& ctx) {
  ctx.commitarf[REG_rax] = handle_ptlcall(ctx.commitarf[REG_nextrip], ctx.commitarf[REG_rdi], ctx.commitarf[REG_rsi], ctx.commitarf[REG_rdx], ctx.commitarf[REG_rcx], ctx.commitarf[REG_r8], ctx.commitarf[REG_r9]);
  ctx.commitarf[REG_rip] = ctx.commitarf[REG_nextrip];
}

//
// Get the processor core frequency in cycles/second:
//
static W64 core_freq_hz = 0;

W64 get_core_freq_hz() {
  if likely (core_freq_hz) return core_freq_hz;

  W64 hz = 0;

  istream cpufreqis("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq");
  if (cpufreqis) {
    char s[256];
    cpufreqis >> readline(s, sizeof(s));      
    
    int khz;
    int n = sscanf(s, "%d", &khz);
    
    if (n == 1) {
      hz = (W64)khz * 1000;
      core_freq_hz = hz;
      return hz;
    }
  }
  
  istream is("/proc/cpuinfo");
  
  if (!is) {
    cerr << "get_core_freq_hz(): warning: cannot open /proc/cpuinfo. Is this a Linux machine?", endl;
    core_freq_hz = hz;
    return hz;
  }
  
  while (is) {
    char s[256];
    is >> readline(s, sizeof(s));
    
    int mhz;
    int n = sscanf(s, "cpu MHz : %d", &mhz);
    if (n == 1) {
      hz = (W64)mhz * 1000000;
      core_freq_hz = hz;
      return hz;
    }
  }

  // Can't read either of these procfiles: abort
  assert(false);
  return 0;
}

const char* get_full_exec_filename() {
  static char full_exec_filename[1024];
  int rc = sys_readlink("/proc/self/exe", full_exec_filename, sizeof(full_exec_filename)-1);
  assert(inrange(rc, 0, (int)sizeof(full_exec_filename)-1));
  full_exec_filename[rc] = 0;
  return full_exec_filename;
}

void print_sysinfo(ostream& os) {
  // Nothing special on userspace PTLsim
}

//
// Injection into target process
//

#ifdef __x86_64__

void copy_from_process_memory(int pid, void* target, const void* source, int size) {
  W64* destp = (W64*)target;
  W64* srcp = (W64*)source;

  foreach (i, ceil(size, 8) / sizeof(W64)) {
    W64 rc = sys_ptrace(PTRACE_PEEKDATA, pid, (W64)srcp++, (W64)destp++);
  }
}

void copy_to_process_memory(int pid, void* target, const void* source, int size) {
  W64* destp = (W64*)target;
  W64* srcp = (W64*)source;

  foreach (i, ceil(size, 8) / sizeof(W64)) {
    W64 rc = sys_ptrace(PTRACE_POKEDATA, pid, (W64)(destp++), (W64)(*srcp++));
    assert(rc == 0);
  }
}

void write_process_memory_W64(int pid, W64 target, W64 data) {
  int rc = sys_ptrace(PTRACE_POKEDATA, pid, target, data);
  assert(rc == 0);
}

W64 read_process_memory_W64(int pid, W64 source) {
  W64 data;
  int rc = sys_ptrace(PTRACE_PEEKDATA, pid, source, (W64)&data);
  assert(rc == 0);
  return data;
}

void write_process_memory_W32(int pid, W64 target, W32 data) {
  // This is tricky because writes are always 64 bits on x86-64, so we must read, merge and write:
  W64 v;
  int rc = sys_ptrace(PTRACE_PEEKDATA, pid, target, (W64)&v);
  assert(rc == 0);
  v = (v & 0xffffffff00000000ULL) | data;
  rc = sys_ptrace(PTRACE_POKEDATA, pid, target, v);
  assert(rc == 0);
}

W32 read_process_memory_W32(int pid, W64 source) {
  W64 data;
  int rc = sys_ptrace(PTRACE_PEEKDATA, pid, source, (W64)&data);
  assert(rc == 0);
  return LO32(data);
}

extern "C" void ptlsim_loader_thunk_64bit(LoaderInfo* info);

int is_elf_64bit(const char* filename) {
  idstream is;
  is.open(filename);
  if (!is) return -1;

  struct ELFPartialHeader {
    W32 magic;
    byte class3264;
  };

  ELFPartialHeader h;
  static const W32 ELFMAGIC = 0x464c457f; // ^ELF

  is.read(&h, sizeof(h));
  assert(h.magic == ELFMAGIC);

  return (h.class3264 == ELFCLASS64);
}

int ptlsim_inject(int argc, char** argv) {
  static const bool DEBUG = 0;

  int filename_arg = configparser.parse(config, argc - 1, argv + 1) + 1;
  const char* filename = argv[filename_arg];

  int x86_64_mode = is_elf_64bit(filename);

  if (x86_64_mode < 0) {
    cerr << "ptlsim: cannot open ", filename, endl, flush;
    sys_exit(1);
  }

  if (DEBUG) cerr << "ptlsim[", sys_gettid(), "]: ", filename, " is a ", (x86_64_mode ? "64-bit" : "32-bit"), " ELF executable", endl;

  int pid = sys_fork();

  if (!pid) {
    if (DEBUG) cerr << "ptlsim[", sys_gettid(), "]: Executing ", filename, endl, flush;
    sys_ptrace(PTRACE_TRACEME, 0, 0, 0);
    // Child process stops after execve() below:
    int rc = sys_execve(filename, (const char**)(argv + filename_arg), (const char**)environ);

    if (rc < 0) {
      cerr << "ptlsim: rc ", rc, ": unable to exec ", filename, endl, flush;
      sys_exit(2);
    }
    assert(false);
  }

  if (pid < 0) {
    cerr << "ptlsim[", sys_gettid(), "]: fork() failed with rc ", pid, endl, flush;
    sys_exit(0);
  }

  if (DEBUG) cerr << "ptlsim: waiting for child pid ", pid, "...", endl, flush;

  int status;
  int rc = sys_wait4(pid, &status, 0, NULL);
  if (rc != pid) {
    cerr << "ptlsim: waitpid returned ", rc, " (vs expected pid ", pid, ")", endl, flush;
    sys_exit(3);
  }

  assert(rc == pid);
  assert(WIFSTOPPED(status));

  struct user_regs_struct regs;
  assert(sys_ptrace(PTRACE_GETREGS, pid, 0, (Waddr)&regs) == 0);

  LoaderInfo info;
  info.initialize = 1;
  info.origrip = regs.rip;
  info.origrsp = regs.rsp;
  const char* ptlsim_filename = get_full_exec_filename();
  if (DEBUG) cerr << "ptlsim: PTLsim full filename is ", ptlsim_filename, endl;
  strncpy(info.ptlsim_filename, ptlsim_filename, sizeof(info.ptlsim_filename)-1);
  info.ptlsim_filename[sizeof(info.ptlsim_filename)-1] = 0;

  if (DEBUG) cerr << "ptlsim: Original process rip ", (void*)info.origrip, ", rsp ", (void*)info.origrsp, " for pid ", pid, endl;

  regs.rsp -= sizeof(LoaderInfo);

  if (!x86_64_mode) {
    cerr << "ptlsim: Error: This is a 64-bit build of PTLsim. It cannot run 32-bit processes.", endl;
    assert(false);
  }
  void* thunk_source = (void*)&ptlsim_loader_thunk_64bit;
  int thunk_size = LOADER_THUNK_SIZE;

  if (DEBUG) cerr << "Saving old code (", thunk_size, " bytes) at thunk rip ", (void*)regs.rip, " in pid ", pid, endl;
  copy_from_process_memory(pid, &info.saved_thunk, (void*)info.origrip, LOADER_THUNK_SIZE);

  if (DEBUG) cerr << "Writing new code (", LOADER_THUNK_SIZE, " bytes) at thunk rip ", (void*)regs.rip, " in pid ", pid, endl;
  copy_to_process_memory(pid, (void*)info.origrip, thunk_source, LOADER_THUNK_SIZE);

  //
  // Write stack frame
  //
  if (DEBUG)  cerr << "Copy loader info (", sizeof(LoaderInfo), " bytes) to rsp ", (void*)regs.rsp, " in pid ", pid, endl;
  copy_to_process_memory(pid, (void*)regs.rsp, &info, sizeof(LoaderInfo));

  W64 loader_info_base = regs.rsp;

  regs.rsp -= (x86_64_mode) ? 2*8 : 2*4;

  if (DEBUG) cerr << "Make stack frame at rsp ", (void*)regs.rsp, " in pid ", pid, endl;

  if (x86_64_mode) {
    write_process_memory_W64(pid, regs.rsp + 0*8, info.origrip); // return address
    write_process_memory_W64(pid, regs.rsp + 1*8, loader_info_base); // pointer to info block
  } else {
    write_process_memory_W32(pid, regs.rsp + 0*4, info.origrip); // return address
    write_process_memory_W32(pid, regs.rsp + 1*4, loader_info_base); // pointer to info block
    if (DEBUG) cerr << "value = ", hexstring(read_process_memory_W64(pid, regs.rsp), 64), endl;
  }

  if (DEBUG) cerr << "  retaddr = 0x", hexstring(info.origrip, 64), endl;
  if (DEBUG) cerr << "  arg[0]  = 0x", hexstring(loader_info_base, 64), endl;

  // Set up register calling convention on x86-64:
  regs.rdi = loader_info_base;

  assert(sys_ptrace(PTRACE_SETREGS, pid, 0, (W64)&regs) == 0);

  if (DEBUG) cerr << "ptlsim: restarting child pid ", pid, " at ", (void*)regs.rip, "...", endl, flush;

  rc = sys_ptrace(PTRACE_DETACH, pid, 0, 0);
  if (rc) {
    cerr << "ptlsim: detach returned ", rc, endl, flush;
    sys_exit(4);
  }
  rc = sys_wait4(pid, &status, 0, NULL);

  // (child done)
  status = WEXITSTATUS(status);
  if (DEBUG) cerr << "ptlsim: exiting with exit code ", status, endl, flush;
  return WEXITSTATUS(status);
}

#else // ! __x86_64__

void copy_from_process_memory(int pid, void* target, const void* source, int size) {
  W32* destp = (W32*)target;
  W32* srcp = (W32*)source;

  foreach (i, ceil(size, 4) / sizeof(W32)) {
    W64 rc = sys_ptrace(PTRACE_PEEKDATA, pid, (W32)srcp++, (W32)destp++);
  }
}

void copy_to_process_memory(int pid, void* target, const void* source, int size) {
  W32* destp = (W32*)target;
  W32* srcp = (W32*)source;

  foreach (i, ceil(size, 4) / sizeof(W32)) {
    W64 rc = sys_ptrace(PTRACE_POKEDATA, pid, (W32)(destp++), (W32)(*srcp++));
    assert(rc == 0);
  }
}

void write_process_memory_W64(int pid, W64 target, W64 data) {
  int rc;
  rc = sys_ptrace(PTRACE_POKEDATA, pid, target+0, LO32(data));
  assert(rc == 0);
  rc = sys_ptrace(PTRACE_POKEDATA, pid, target+4, HI32(data));
  assert(rc == 0);
}

W64 read_process_memory_W64(int pid, Waddr source) {
  W64 datalo;
  W64 datahi;
  int rc;
  rc = sys_ptrace(PTRACE_PEEKDATA, pid, source, (W32)&datalo);
  assert(rc == 0);
  rc = sys_ptrace(PTRACE_PEEKDATA, pid, source+4, (W32)&datahi);
  assert(rc == 0);

  return ((W64)datahi << 32) | datalo;
}

void write_process_memory_W32(int pid, Waddr target, W32 data) {
  int rc = sys_ptrace(PTRACE_POKEDATA, pid, target, data);
  assert(rc == 0);
}

W32 read_process_memory_W32(int pid, Waddr source) {
  W64 data;
  int rc = sys_ptrace(PTRACE_PEEKDATA, pid, source, (Waddr)&data);
  assert(rc == 0);
  return LO32(data);
}

extern "C" void ptlsim_loader_thunk_32bit(LoaderInfo* info);

int is_elf_valid(const char* filename) {
  idstream is;
  is.open(filename);
  if (!is) return 0;

  struct ELFPartialHeader {
    W32 magic;
    byte class3264;
  };

  ELFPartialHeader h;
  static const W32 ELFMAGIC = 0x464c457f; // ^ELF

  is.read(&h, sizeof(h));
  if (h.magic != ELFMAGIC) return 0;
  if (h.class3264 != ELFCLASS32) return 0;

  return 1;
}

int ptlsim_inject(int argc, char** argv) {
  static const bool DEBUG = 0;
  int status;
  int rc;

  //
  // Find the argv index of the filename to execute and its arguments:
  //
  int filename_arg = 1 + configparser.parse(config, argc - 1, argv + 1);

  const char* filename = argv[filename_arg];

  if (!is_elf_valid(filename)) {
    cerr << "ptlsim: cannot open ", filename, endl, flush;
    sys_exit(1);
  }

  if (DEBUG) cerr << "ptlsim[", sys_gettid(), "]: ", filename, " is a 32-bit ELF executable", endl;

  int pid = sys_fork();

  if (!pid) {
    if (DEBUG) cerr << "ptlsim[", sys_gettid(), "]: Executing ", filename, endl, flush;
    sys_ptrace(PTRACE_TRACEME, 0, 0, 0);
    // Child process stops after execve() below:
    int rc = sys_execve(filename, (const char**)(argv + filename_arg), (const char**)environ);

    if (rc < 0) {
      cerr << "ptlsim: rc ", rc, ": unable to exec ", filename, ": rc = ", rc, endl, flush;
      sys_exit(2);
    }
    assert(false);
  }

  if (pid < 0) {
    cerr << "ptlsim[", sys_gettid(), "]: fork() failed with rc ", pid, ": rc = ", pid, endl, flush;
    sys_exit(0);
  }

  if (DEBUG) cerr << "ptlsim: waiting for child pid ", pid, "...", endl, flush;

  rc = sys_wait4(pid, &status, 0, NULL);
  if (rc != pid) {
    cerr << "ptlsim: waitpid returned ", rc, " (vs expected pid ", pid, "); rc = ", rc, endl, flush;
    sys_exit(3);
  }

  assert(rc == pid);
  assert(WIFSTOPPED(status));

  struct user_regs_struct regs;
  assert(sys_ptrace(PTRACE_GETREGS, pid, 0, (Waddr)&regs) == 0);
  if (DEBUG) {
    cerr << "  ebx ", hexstring(regs.ebx, 32), "  ecx ", hexstring(regs.ecx, 32), "  edx ", hexstring(regs.edx, 32), "  esi ", hexstring(regs.esi, 32), endl;
    cerr << "  edi ", hexstring(regs.edi, 32), "  ebp ", hexstring(regs.ebp, 32), "  eax ", hexstring(regs.eax, 32), "  esp ", hexstring(regs.esp, 32), endl;
    cerr << "  eip ", hexstring(regs.eip, 32), "  org ", hexstring(regs.orig_eax, 32), endl;
    //cerr << "  cs ", hexstring(regs.cs, 16), "  ss ", hexstring(regs.ss, 16), "  ds ", hexstring(regs.ds, 16), endl;
  }

  LoaderInfo info;
  info.initialize = 1;
  info.origrip = regs.eip;
  info.origrsp = regs.esp;
  const char* ptlsim_filename = get_full_exec_filename();
  if (DEBUG) cerr << "ptlsim: PTLsim full filename is ", ptlsim_filename, endl;
  strncpy(info.ptlsim_filename, ptlsim_filename, sizeof(info.ptlsim_filename)-1);
  info.ptlsim_filename[sizeof(info.ptlsim_filename)-1] = 0;

  if (DEBUG) cerr << "ptlsim: Original process rip ", (void*)(Waddr)info.origrip, ", rsp ", (void*)(Waddr)info.origrsp, " for pid ", pid, endl;

  regs.esp -= sizeof(LoaderInfo);

  void* thunk_source = (void*)&ptlsim_loader_thunk_32bit;
  int thunk_size = LOADER_THUNK_SIZE;

  if (DEBUG) cerr << "Saving old code (", thunk_size, " bytes) at thunk rip ", (void*)regs.eip, " in pid ", pid, endl;
  copy_from_process_memory(pid, &info.saved_thunk, (void*)(Waddr)info.origrip, LOADER_THUNK_SIZE);

  if (DEBUG) cerr << "Writing new code (", LOADER_THUNK_SIZE, " bytes) at thunk rip ", (void*)regs.eip, " in pid ", pid, endl;
  copy_to_process_memory(pid, (void*)(Waddr)info.origrip, thunk_source, LOADER_THUNK_SIZE);

  //
  // Write stack frame
  //
  if (DEBUG) cerr << "Copy loader info (", sizeof(LoaderInfo), " bytes) to rsp ", (void*)regs.esp, " in pid ", pid, endl;
  copy_to_process_memory(pid, (void*)regs.esp, &info, sizeof(LoaderInfo));

  W64 loader_info_base = regs.esp;

  regs.esp -= 2*4;

  if (DEBUG) cerr << "Make stack frame at rsp ", (void*)regs.esp, " in pid ", pid, endl;

  write_process_memory_W32(pid, regs.esp + 0*4, info.origrip); // return address
  write_process_memory_W32(pid, regs.esp + 1*4, loader_info_base); // pointer to info block
  if (DEBUG) cerr << "value = ", hexstring(read_process_memory_W64(pid, regs.esp), 64), endl;

  if (DEBUG) cerr << "  retaddr = 0x", hexstring(info.origrip, 64), endl;
  if (DEBUG) cerr << "  arg[0]  = 0x", hexstring(loader_info_base, 64), endl;

  regs.edi = loader_info_base;

  assert(sys_ptrace(PTRACE_SETREGS, pid, 0, (Waddr)&regs) == 0);

  if (DEBUG) cerr << "ptlsim: restarting child pid ", pid, " at ", (void*)regs.eip, "...", endl, flush;

  rc = sys_ptrace(PTRACE_DETACH, pid, 0, 0);
  if (rc) {
    cerr << "ptlsim: detach returned ", rc, ", error code ", rc, endl, flush;
    sys_exit(4);
  }
  rc = sys_wait4(pid, &status, 0, NULL);

  // (child done)
  status = WEXITSTATUS(status);
  if (DEBUG) cerr << "ptlsim: exiting with exit code ", status, endl, flush;
  return WEXITSTATUS(status);
}

#endif

//
// Profiling thread exit callbacks
//

//
// Respond to external signals like XCPU and others to switch modes
// or dump statistics.
//
extern "C" void external_signal_callback(int sig, siginfo_t* si, void* contextp) {
  if (logfile) logfile << endl, "=== Thread ", sys_gettid(), " received external signal ", si->si_signo, " in ", ((running_in_sim_mode) ? "simulation" : "native"), " mode ===", endl, endl, flush;

  ucontext_t* context = (ucontext_t*)contextp;

  switch (si->si_signo) {
  case SIGXCPU: {
    if (running_in_sim_mode) {
      // Already in simulator: switch back to native mode
      if (logfile) logfile << "Switching tid ", sys_gettid(), " to native mode at cycle ", sim_cycle, ", ", total_user_insns_committed, " user commits", endl, flush;
      if (!config.quiet) cerr << endl, "//", endl, "// Switching tid ", sys_gettid(), " to native mode at cycle ", sim_cycle, ", ", total_user_insns_committed, " user commits", endl, "//", endl, endl, flush;
      // Simulator loop will perform the switch on the next iteration when it detects this
      requested_switch_to_native = 1;
    } else {
#ifdef __x86_64__
      void* rip = (void*)context->uc_mcontext.gregs[REG_RIP];
#else
      void* rip = (void*)context->uc_mcontext.gregs[REG_EIP];
#endif
      // Remove old breakpoint, if any
      remove_switch_to_sim_breakpoint();
      if (logfile) logfile << "Switching tid ", sys_gettid(), " to simulation mode at rip ", rip, endl, flush;
      if (!config.quiet) cerr << endl, "//", endl, "// Switching tid ", sys_gettid(), " to simulation mode at rip ", rip, endl, "//", endl, endl, flush;
      set_switch_to_sim_breakpoint(rip);
      // Context switch to PTLsim takes place after the sighandler returns
    }
    break;
  }
  default:
    if (logfile) logfile << "Warning: unknown signal ", si->si_signo, "; ignoring", endl, flush; break;
  }
}

void init_signal_callback() {
#ifdef __x86_64__
  // On 64-bit builds, this only works when PTLsim binary and user thread are both 64-bit:
  if (!ctx.use64) return;
#endif

  struct kernel_sigaction sa;
  setzero(sa);
  sa.k_sa_handler = external_signal_callback;
  sa.sa_flags = SA_SIGINFO;
  assert(sys_rt_sigaction(SIGXCPU, &sa, NULL, sizeof(W64)) == 0);
}

bool check_for_async_sim_break() {
  if unlikely ((sim_cycle >= config.stop_at_cycle) |
               (iterations >= config.stop_at_iteration) |
               (total_user_insns_committed >= config.stop_at_user_insns)) {
    logfile << "Stopping simulation loop at specified limits (", iterations, " iterations, ", total_user_insns_committed, " commits)", endl;
    return true;
  }

  return false;
}

int inject_events() {
  // No events or interrupts to inject in userspace PTLsim
  return 0;
}

//
// Collect system information into the stats structure
//
void collect_sysinfo(PTLsimStats& stats, int argc, char** argv) {
  collect_common_sysinfo(stats);

#define strput(x, y) (strncpy((x), (y), sizeof(x)))
  stringbuf sb;

  const char* execname = get_full_exec_filename();
  strput(stats.simulator.run.executable, execname);

  sb.reset();
  foreach (i, argc) {
    sb << argv[i];
    if (i != (argc-1)) sb << ' ';
  }

  strput(stats.simulator.run.args, sb);
}

//
// Read per-process configuration
//
int init_config(int argc, char** argv) {
  collect_sysinfo(stats, argc, argv);

  //
  // argv[] is a suffix of the parent argv[] of length argc.
  // If the parent has some configuration between the initial ptlsim 
  // executable in argv[0] and the argv[X] that starts the suffix (noting 
  // that argv[X-1] will be "--"), then send that to configparser.parse().
  //

  pid_t parent = sys_getppid();
  stringbuf cmdline;
  cmdline << "/proc/", parent, "/cmdline";

  //
  // Load p_argc and p_argv for the parent, analogous to argc/argv
  // /proc/<pid>/cmdline terminates each argument with a null character.
  //
  istream is(cmdline);
  if (unlikely (!is)) {
    cerr << "PTLsim error: cannot open /proc/<parent>/cmdline", endl, flush;
    abort();
  }

  dynarray<char*> parent_args;
  stringbuf line;
  
  for (;;) {
    line.reset();
    is >> line;
    if (!is) break;
    parent_args.push(strdup(line));
  }
  is.close();
  
  unsigned p_argc = parent_args.length;

  //
  // ConfigurationParser.parse() will automatically stop parsing at
  // the first non-option (i.e. not starting with "-xxx") argument
  // it finds (conveniently, this is always the target program name).
  //  
  int ptlsim_arg_count = 1 + configparser.parse(config, p_argc-1, parent_args+1);

  handle_config_change(config, ptlsim_arg_count, parent_args+1);

  foreach (i, parent_args.length) delete parent_args[i];

  logfile << config;

  return 0;
}

//
// State management
//
ThreadState basetls;

native_auxv_t* auxv_start;

native_auxv_t* find_auxv_entry(int type) {
  native_auxv_t* auxp = auxv_start;

  while (auxp->a_type != AT_NULL) {
    //logfile << "  auxv type ", intstring(auxp->a_type, 3), ": 0x", hexstring((W64)auxp->a_un.a_ptr, 64), " = ", intstring(auxp->a_un.a_val, 24), endl, flush;
    if (auxp->a_type == type) return auxp;
    auxp++;
  }

  return null;
}

//
// Conversion of args, environment and auxv between 64-bit and 32-bit formats:
//

template <typename ptrsize_t, typename auxv_t>
int get_stack_reqs_for_args_env_auxv(const byte* origargv) {
  // go back to argc before argv
  ptrsize_t* p = (ptrsize_t*)origargv;

  int argc = *p++;
  p += argc;

  // skip over null after args
  p++;

  // skip over environment
  int envc = 0;
  while (*p) { p++; envc++; }
  p++;

  auxv_t* auxv = (auxv_t*)p;
  int auxvc = 0;
  while (auxv->a_type != AT_NULL) { auxv++; auxvc++; }

  return ((1 + argc + 1 + envc + 1) * sizeof(char**)) + ((auxvc + 1) * sizeof(native_auxv_t));
}

struct Elf32_auxv_32bit {
  W32 a_type;
  union {
    W32 a_val;
    W32 a_ptr;
  } a_un;
};

void printenv(char** pp) {
  stringbuf sb; sb << "Environment @ ", pp, ":", endl; early_printk(sb);
  while (*pp) {
    stringbuf sb; sb << "  [", *pp, "]", endl; early_printk(sb);
    pp++;
  }
}

template <typename ptrsize_t>
char** find_environ(const byte* origargcv) {
  char** p = (char**)origargcv;
  int argc = *((int*)p);
  p++; // skip int argc
  p += argc;
  // skip over null after args
  p++;

  return p;
}

template <typename ptrsize_t, typename auxv_t>
byte* copy_args_env_auxv(byte* destptr, const byte* origargv) {
  char** dest = (char**)destptr;

  ptrsize_t* p = (ptrsize_t*)origargv;

  Waddr argc = *p++;
  *dest++ = (char*)argc;

  foreach (i, argc) *dest++ = (char*)(Waddr)(*p++);

  // skip over null at end of args
  *dest++ = 0; p++;

  while (*p) *dest++ = (char*)(Waddr)(*p++);

  // skip over null at end of environment
  *dest++ = 0; p++;

  native_auxv_t* destauxv = (native_auxv_t*)dest;

  auxv_t* auxv = (auxv_t*)p;

  auxv_start = destauxv;

  while (auxv->a_type != AT_NULL) {
    if ((auxv->a_type == AT_SYSINFO) || (auxv->a_type == AT_SYSINFO_EHDR)) {
      // We do not support SYSENTER-style VDSOs, so disable this:
      // logfile << "copy_args_env_auxv: Disabled 32-bit AT_SYSINFO auxv", endl;
      destauxv->a_type = AT_IGNORE;
      auxv->a_type = AT_IGNORE;
    } else {
      destauxv->a_type = auxv->a_type;
      destauxv->a_un.a_val = auxv->a_un.a_val;
    }
    auxv++; destauxv++;
  }
  
  destauxv->a_type = AT_NULL;
  destauxv->a_un.a_val = 0;
  auxv++; destauxv++;

  return (byte*)destauxv;
}

//
// The real PTLsim entry point called by the kernel immediately after injecting
// the ptlsim image into the target process is ptlsim_preinit_entry. This in
// turn calls ptlsim_preinit() below before returning to the libc _start to
// finish initializing PTLsim as if it were a regular program thread.
//
// ptlsim_preinit() sets up our custom memory management and threading model,
// then captures any user process arguments, environment and auxv, possibly
// converting between 64-bit and 32-bit formats.
//
extern byte ptlsim_preinit_entry;

extern "C" void* ptlsim_preinit(void* origrsp, void* nextinit) {
  //
  // We don't yet have any I/O streams or console output at this point
  // so we are limited to things we can do without using libc:
  //

  // The loader thunk patched our ELF header with the real RIP to enter at:
#ifdef __x86_64__
  Elf64_Ehdr* ptlsim_ehdr = (Elf64_Ehdr*)PTL_IMAGE_BASE;
#else
  Elf32_Ehdr* ptlsim_ehdr = (Elf32_Ehdr*)PTL_IMAGE_BASE;
#endif

  inside_ptlsim = (ptlsim_ehdr->e_type == ET_PTLSIM);

  ptl_mm_init();

  if (!inside_ptlsim) {
    // We're still a normal process - don't do anything special
    stack_min_addr = (Waddr)origrsp;
    environ = find_environ<Waddr>((const byte*)origrsp);
    call_global_constuctors();
    return origrsp;
  }

  // Set up initial context:
  ctx.reset();
  ctx.commitarf[REG_rsp] = (Waddr)origrsp;
  ctx.commitarf[REG_rip] = (Waddr)ptlsim_ehdr->e_entry;
  ctx.commitarf[REG_flags] = 0;
  ctx.internal_eflags = 0;

  ctx.seg[SEGID_CS].selector = saved_cs;
  ctx.seg[SEGID_SS].selector = saved_ss;
  ctx.seg[SEGID_DS].selector = saved_ds;
  ctx.seg[SEGID_ES].selector = saved_es;
  ctx.seg[SEGID_FS].selector = saved_fs;
  ctx.seg[SEGID_GS].selector = saved_gs;
  ctx.update_shadow_segment_descriptors();

  ctx.use32 = 1;
  ctx.use64 = (ptlsim_ehdr->e_machine == EM_X86_64);

  ctx.fxrstor(x87state);

  ctx.vcpuid = 0;
  ctx.running = 1;
  ctx.commitarf[REG_ctx] = (Waddr)&ctx;
  ctx.commitarf[REG_fpstack] = (Waddr)&ctx.fpstack;

  //
  // Generally the true stack top can be found by rounding up to some big fraction
  // of the address space on most kernels, since it is always at 0x7fffffffffff
  // on x86-64, 0xbfffffff on ia32 or 0xffffffff on ia32-on-x86-64.
  //
  stack_max_addr = ceil(ctx.commitarf[REG_rsp], 256*1024*1024);

  Waddr user_stack_size;

  struct rlimit rlimit;
  assert(sys_getrlimit(RLIMIT_STACK, &rlimit) == 0);
  //
  // If the stack is unlimited, enforce a maximum of 128 MB.
  // Some kernels give us an insanely large value here, but
  // since we must pre-zero the stack, it has to be smaller:
  //
  user_stack_size = min((W64)rlimit.rlim_cur, (W64)128*1024*1024);

  // Round up a little so we don't over-run it when we fault in the stack:
  stack_min_addr = floor(stack_max_addr - user_stack_size, PAGE_SIZE) + 65536;

  assert(stack_min_addr >= (PTL_IMAGE_BASE + 128*1024*1024));

  asp.reset();

  ThreadState* tls = &basetls;
  tls->self = tls;
  // Give PTLsim itself 64 MB for the .text, .data and .bss sections:
  void* stack = ptl_mm_alloc_private_pages(SIM_THREAD_STACK_SIZE, PROT_READ|PROT_WRITE, PTL_IMAGE_BASE + 64*1024*1024);
  assert(mmap_valid(stack));
  tls->stack = (byte*)stack + SIM_THREAD_STACK_SIZE;
  setup_sim_thunk_page();

#ifdef __x86_64__
  const byte* argv = (const byte*)origrsp;

  int bytes = (ctx.use64)
    ? get_stack_reqs_for_args_env_auxv<W64, Elf64_auxv_t>(argv)
    : get_stack_reqs_for_args_env_auxv<W32, Elf32_auxv_32bit>(argv);

  byte* sp = (byte*)(tls->stack);
  sp -= bytes;

  byte* endp = (ctx.use64)
    ? copy_args_env_auxv<W64, Elf64_auxv_t>(sp, argv)
    : copy_args_env_auxv<W32, Elf32_auxv_32bit>(sp, argv);
#else
  const byte* argv = (const byte*)origrsp;

  int bytes = get_stack_reqs_for_args_env_auxv<W32, Elf32_auxv_32bit>(argv);

  byte* sp = (byte*)(tls->stack);
  sp -= bytes;

  byte* endp = copy_args_env_auxv<W32, Elf32_auxv_32bit>(sp, argv);
#endif
  assert(endp == tls->stack);

  environ = find_environ<Waddr>(sp);

  call_global_constuctors();

  tls->stack = (void*)sp;

  return sp;
}

void user_process_terminated(int rc) {
  x86_set_mxcsr(MXCSR_DEFAULT);
  logfile << "user_process_terminated(rc = ", rc, "): initiating shutdown at ", sim_cycle, " cycles, ", total_user_insns_committed, " commits...", endl, flush;
  capture_stats_snapshot("final");
  flush_stats();
  logfile << "PTLsim exiting...", endl, flush;
  shutdown_subsystems();
  logfile.close();
  sys_exit(rc);
}

//
// Main simulation driver function
//
void switch_to_sim() {
  static const bool DEBUG = 0;

  logfile << "Baseline state:", endl;
  logfile << ctx;

  Waddr origrip = (Waddr)ctx.commitarf[REG_rip];

  bool done = false;

  //
  // Swap the FP control registers to the user process version, so FP uopimpls
  // can use the real rounding control bits.
  //
  x86_set_mxcsr(ctx.mxcsr | MXCSR_EXCEPTION_DISABLE_MASK);

  simulate(config.core_name);
  capture_stats_snapshot("final");
  flush_stats();

  done |= (config.dump_at_end | config.overshoot_and_dump);

  // Sanitize flags (AMD and Intel CPUs also use bits 1 and 3 for reserved bits, but not for INV and WAIT like we do).
  ctx.commitarf[REG_flags] &= FLAG_NOT_WAIT_INV;

  logfile << "Switching to native: returning to rip ", (void*)(Waddr)ctx.commitarf[REG_rip], endl, flush;

  x86_set_mxcsr(MXCSR_DEFAULT);

  if (config.exit_after_fullsim) {
    logfile << endl, "=== Exiting after full simulation on tid ", sys_gettid(), " at rip ", (void*)(Waddr)ctx.commitarf[REG_rip], " (", 
      sim_cycle, " cycles, ", total_user_insns_committed, " user commits, ", iterations, " iterations) ===", endl, endl;
    shutdown_subsystems();
    logfile.flush();
    sys_exit(0);
  }

  if (config.overshoot_and_dump | config.dump_at_end) {
    RIPVirtPhys rip(ctx.commitarf[REG_rip]);
    rip.update(ctx);

    BasicBlock* bb = bbcache(rip);
    if (!bb) {
      bb = bbcache.translate(ctx, rip);
    }

    assert(bb->transops[0].som);
    int bytes = bb->transops[0].bytes;
    Waddr ripafter = rip + (config.overshoot_and_dump ? bytes : 0);

    logfile << endl;
    logfile << "Overshoot and dump enabled:", endl;
    logfile << "- Return to rip ", rip, " in native mode", endl;
    if (config.overshoot_and_dump) logfile << "- Execute one x86 insn of ", bytes, " bytes at rip ", rip, endl;
    logfile << "- Breakpoint and dump core at rip ", (void*)ripafter, endl, endl, flush;

    int rc = sys_mprotect((void*)floor(ripafter, PAGE_SIZE), PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC);
    assert(!rc);

    *((byte*)ripafter) = 0xfb; // x86 invalid opcode
  }

  logfile.flush();
  switch_to_native_restore_context();
}

//
// PTLsim main: called after ptlsim_preinit() brings up boot subsystems
//
int main(int argc, char** argv) {
  configparser.setup();
  config.reset();

  if (!inside_ptlsim) {
    int rc = 0;
    if (argc < 2) {
      print_banner(cout, stats, argc, argv);
      configparser.printusage(cout, config);
    } else {
      rc = ptlsim_inject(argc, argv);
    }
    cout.flush();
    cerr.flush();
    sys_exit(rc);
  }

  init_config(argc, argv);
  init_signal_callback();
  CycleTimer::gethz();

  if (config.pause_at_startup) {
    logfile << "ptlsim: Paused for ", config.pause_at_startup, " seconds; attach debugger to PID ", sys_getpid(), " now...", endl, flush;
    cerr << "ptlsim: Paused for ", config.pause_at_startup, " seconds; attach debugger to PID ", sys_getpid(), " now...", endl, flush;
    sys_nanosleep((W64)config.pause_at_startup * 1000000000);
    cerr << "ptlsim: Continuing...", endl, flush;
    logfile << "ptlsim: Continuing...", endl, flush;
  }

  init_uops();
  init_decode();

  void* interp_entry = (void*)(Waddr)ctx.commitarf[REG_rip];
  void* program_entry = (void*)(Waddr)find_auxv_entry(AT_ENTRY)->a_un.a_val;

  logfile << "loader: interp_entry ", interp_entry, ", program_entry ", program_entry, endl, flush;

  if (!config.trigger_mode) {
    if (config.start_at_rip != INVALIDRIP)
      set_switch_to_sim_breakpoint((void*)(Waddr)config.start_at_rip);
    else if (config.include_dyn_linker)
      set_switch_to_sim_breakpoint(interp_entry);
    else set_switch_to_sim_breakpoint(program_entry);
  }

  // Context switch into virtual machine:
  switch_to_native_restore_context();
}
