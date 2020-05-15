//
// PTLsim: Cycle Accurate x86-64 Simulator
// RASPsim application
//
// Copyright 2020-2020 Alexis Engelke <engelke@in.tum.de>
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

Context ctx alignto(4096) insection(".ctx");
struct PTLsimConfig;

extern PTLsimConfig config;

extern ConfigurationParser<PTLsimConfig> configparser;

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
  Hashtable<Waddr, W8*> mapped_mem;

  void map(Waddr start, Waddr length, int prot) {
    start = floor(start, PAGE_SIZE);
    length = ceil(length, PAGE_SIZE);
    Waddr num_pages = length / PAGE_SIZE;
    foreach (i, num_pages) {
      W8* old_val;
      if (mapped_mem.remove(start + i * PAGE_SIZE, old_val))
        delete[] old_val;
      mapped_mem.add(start + i * PAGE_SIZE, new W8[PAGE_SIZE]());
    }
    setattr((byte*)start, length, prot);
  }
  void unmap(Waddr start, Waddr length) {
    start = floor(start, PAGE_SIZE);
    length = ceil(length, PAGE_SIZE);
    Waddr num_pages = length / PAGE_SIZE;
    foreach (i, num_pages) {
      W8* old_val;
      if (mapped_mem.remove(start + i * PAGE_SIZE, old_val))
        delete[] old_val;
    }
    setattr((byte*)start, length, PROT_NONE);
  }

  void* page_virt_to_mapped(Waddr addr) {
    W8** res = mapped_mem.get(floor(addr, PAGE_SIZE));
    if (!res) return res;
    return (W8*)*res + lowbits(addr, 12);
  }

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
  void setattr(void* start, Waddr length, int prot);
  int getattr(void* start);

  bool fastcheck(Waddr addr, spat_t top) const {
#ifdef __x86_64__
    // Is it outside of userspace address range?
    // Check disabled to allow access to VDSO in kernel space.
    if unlikely (addr >> 48) return 0;

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

  bool isdirty(Waddr mfn) { return fastcheck(mfn << 12, dirtymap); }
  void setdirty(Waddr mfn) { make_page_accessible((void*)(mfn << 12), dirtymap); }
  void cleardirty(Waddr mfn) { make_page_inaccessible((void*)(mfn << 12), dirtymap); }

  void resync_with_process_maps();
};

AddressSpace asp;

// Userspace PTLsim only supports one VCPU:
int current_vcpuid() { return 0; }

bool asp_check_exec(void* addr) { return asp.fastcheck(addr, asp.execmap); }

bool smc_isdirty(Waddr mfn) { return asp.isdirty(mfn); }
void smc_setdirty(Waddr mfn) { asp.setdirty(mfn); }
void smc_cleardirty(Waddr mfn) { asp.cleardirty(mfn); }

bool check_for_async_sim_break() { return false; }

int inject_events() { return 0; }
void print_sysinfo(ostream& os) {}

// This is where we end up after issuing opcode 0x0f37 (undocumented x86 PTL call opcode)
void assist_ptlcall(Context& ctx) {
  ctx.commitarf[REG_rip] = ctx.commitarf[REG_nextrip];
}

// Only one VCPU in userspace PTLsim:
Context& contextof(int vcpu) { return ctx; }

W64 loadphys(Waddr addr) {
  W64& data = *(W64*)addr;
  return data;
}

W64 storemask(Waddr addr, W64 data, byte bytemask) {
  W64& mem = *(W64*)addr;
  mem = mux64(expand_8bit_to_64bit_lut[bytemask], mem, data);
  return data;
}

int Context::copy_from_user(void* target, Waddr addr, int bytes, PageFaultErrorCode& pfec, Waddr& faultaddr, bool forexec, Level1PTE& ptelo, Level1PTE& ptehi) {
  // logfile << "VMEM: Read from user ", (void*)addr, " (", bytes, ")", endl, flush;

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
    pfec.p = readable;
    pfec.nx = (forexec & (!executable));
    pfec.us = 1;
    return n;
  }

  n = min((Waddr)(4096 - lowbits(addr, 12)), (Waddr)bytes);

  void* mapped_addr = asp.page_virt_to_mapped(addr);
  assert(mapped_addr);
  // logfile << "VMEM: Read ", mapped_addr, " = ", *(W8*)mapped_addr, endl, flush;
  memcpy(target, mapped_addr, n);

  // All the bytes were on the first page
  if likely (n == bytes) return n;

  // Go on to second page, if present
  readable = asp.fastcheck((byte*)(addr + n), asp.readmap);
  if likely (forexec) executable = asp.fastcheck((byte*)(addr + n), asp.execmap);
  if unlikely ((!readable) | (forexec & !executable)) {
    faultaddr = addr + n;
    pfec.p = readable;
    pfec.nx = (forexec & (!executable));
    pfec.us = 1;
    return n;
  }

  memcpy((byte*)target + n, asp.page_virt_to_mapped(addr + n), bytes - n);
  return bytes;
}

int Context::copy_to_user(Waddr target, void* source, int bytes, PageFaultErrorCode& pfec, Waddr& faultaddr) {
  // logfile << "VMEM: Write to user ", (void*)target, " (", bytes, ")", endl, flush;

  pfec = 0;
  bool writable = asp.fastcheck((byte*)target, asp.writemap);
  if unlikely (!writable) {
    faultaddr = target;
    pfec.p = asp.fastcheck((byte*)target, asp.readmap);
    pfec.rw = 1;
    return 0;
  }

  byte* targetlo = (byte*)asp.page_virt_to_mapped(target);
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
    pfec.us = 1;
    return nlo;
  }

  memcpy(asp.page_virt_to_mapped(target + nlo), (byte*)source + nlo, bytes - nlo);
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
    pfec.p = asp.fastcheck(virtaddr, asp.readmap);
    pfec.rw = store;
    pfec.us = 1;
    return 0;
  }

  return (Waddr) asp.page_virt_to_mapped(floor(signext64(virtaddr, 48), 8));
}

int Context::write_segreg(unsigned int segid, W16 selector) {
  // Well, we don't want to play with the fire...
  return EXCEPTION_x86_gp_fault;
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
  fs.base = 0;
  fs.limit = limit;

  SegmentDescriptorCache& gs = seg[SEGID_GS];
  gs.present = 1;
  gs.base = 0;
  gs.limit = limit;
}

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

  sys_exit(1); // Well, we don't want core dumps.

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
  freemap(readmap);
  freemap(writemap);
  freemap(execmap);
  freemap(dirtymap);

  readmap  = allocmap();
  writemap = allocmap();
  execmap  = allocmap();
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

// In userspace PTLsim, virtual == physical:
// FIXME(AE): software virtual memory
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

void Context::propagate_x86_exception(byte exception, W32 errorcode, Waddr virtaddr) {
  Waddr rip = ctx.commitarf[REG_selfrip];

  logfile << "Exception ", exception, " (", x86_exception_names[exception], ") code=", errorcode, " addr=", (void*)virtaddr, " @ rip ", (void*)(Waddr)commitarf[REG_rip], " (", total_user_insns_committed, " commits, ", sim_cycle, " cycles)", endl, flush;
  cerr << "Exception ", exception, " (", x86_exception_names[exception], ") code=", errorcode, " addr=", (void*)virtaddr, " @ rip ", (void*)(Waddr)commitarf[REG_rip], " (", total_user_insns_committed, " commits, ", sim_cycle, " cycles)", endl, flush;

  // PF
  if (exception == 14) {
    // PF Flags
    W8 p    = errorcode & 0x00000001;
    W8 wr   = errorcode & 0x00000002;
    W8 us   = errorcode & 0x00000004;
    W8 rsvd = errorcode & 0x00000008;
    W8 id   = errorcode & 0x00000010;
    W8 pk   = errorcode & 0x00000020;

    logfile << "PageFault error code: 0x", hexstring(errorcode, 32), ", Flags: ", (pk ? "PK " : ""), (id ? "I " : "D "), (rsvd ? "RSVD " : ""), (us ? "U " : "S "), (wr ? "W " : "R "), (p ? "P" : ""), endl, flush;
    cerr    << "PageFault error code: 0x", hexstring(errorcode, 32), ", Flags: ", (pk ? "PK " : ""), (id ? "I " : "D "), (rsvd ? "RSVD " : ""), (us ? "U " : "S "), (wr ? "W " : "R "), (p ? "P" : ""), endl, flush;
  }

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

  ctx.commitarf[REG_rax] = -ENOSYS;
  ctx.commitarf[REG_rip] = ctx.commitarf[REG_rcx];

  if (DEBUG) logfile << "handle_syscall: result ", ctx.commitarf[REG_rax], " (", (void*)ctx.commitarf[REG_rax], "); returning to ", (void*)ctx.commitarf[REG_rip], endl, flush;
}

#endif // __x86_64__

void handle_syscall_32bit(int semantics) {
  bool DEBUG = 1; //analyze_in_detail();
  //
  // Handle a 32-bit syscall:
  // (This is called from the assist_syscall ucode assist)
  //
  if (semantics == SYSCALL_SEMANTICS_INT80) {
    // Our exit operation.
    requested_switch_to_native = 1;
  } else {
    // But don't clobber RAX when we want out guest to quit.
    ctx.commitarf[REG_rax] = -ENOSYS;
  }

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

//
// Main simulation driver function
//
void switch_to_sim() {
  static const bool DEBUG = 0;
}

bool handle_config_arg(char* line, dynarray<Waddr>* dump_pages) {
  if (*line == '\0') return false;
  dynarray<char*> toks;
  toks.tokenize(line, " ");
  if (toks.empty())
    return false;

  if (toks[0][0] == '#') {
    return false;
  }

  if (toks[0][0] == 'M') { // allocate page M<addr> <prot>
    if (toks.size() != 2) {
      cerr << "Error: option ", line, " has wrong number of arguments", endl;
      return true;
    }
    char* endp;
    W64 addr = strtoull(toks[0] + 1, &endp, 16);
    if (*endp != '\0' || lowbits(addr, 12)) {
      cerr << "Error: invalid value ", toks[0], " ", endp, endl;
      return true;
    }
    int prot = 0;
    if (!strcmp(toks[1], "ro")) prot = PROT_READ;
    else if (!strcmp(toks[1], "rw")) prot = PROT_READ | PROT_WRITE;
    else if (!strcmp(toks[1], "rx")) prot = PROT_READ | PROT_EXEC;
    else {
      cerr << "Error: invalid mem prot ", toks[1], endl;
      return true;
    }
    asp.map(addr, 0x1000, prot);
  } else if (toks[0][0] == 'W') { // write to mem W<addr> <hexbytes>, may not cross page boundaries
    if (toks.size() != 2) {
      cerr << "Error: option ", line, " has wrong number of arguments", endl;
      return true;
    }
    char* endp;
    W64 addr = strtoull(toks[0] + 1, &endp, 16);
    if (*endp != '\0') {
      cerr << "Error: invalid value ", toks[0], endl;
      return true;
    }
    W8* mapped = (W8*)asp.page_virt_to_mapped(addr);
    if (!mapped) {
      cerr << "Error: page not mapped ", (void*) addr, endl;
      return true;
    }
    Waddr arglen = strlen(toks[1]);
    if ((arglen & 1) || arglen/2 > 4096-lowbits(addr, 12)) {
      cerr << "Error: arg has odd size or crosses page boundary", (void*) addr, endl;
      return true;
    }
    unsigned n = min((Waddr)(4096 - lowbits(addr, 12)), arglen/2);
    foreach (i, n) {
      char hex_byte[3] = {toks[1][i*2],toks[1][i*2+1], 0};
      mapped[i] = strtoul(hex_byte, NULL, 16);
    }
  } else if (toks[0][0] == 'D') { // dump page D<page>
    if (toks.size() != 1) {
      cerr << "Error: option ", line, " has wrong number of arguments", endl;
      return true;
    }
    char* endp;
    W64 addr = strtoull(toks[0] + 1, &endp, 16);
    if (*endp != '\0') {
      cerr << "Error: invalid value ", toks[0], endl;
      return true;
    }
    dump_pages->push(floor(addr, PAGE_SIZE));
  } else if (!strcmp(toks[0], "Fnox87")) {
    ctx.no_x87 = 1;
  } else if (!strcmp(toks[0], "Fnosse")) {
    ctx.no_sse = 1;
  } else if (!strcmp(toks[0], "Fnocache")) {
    config.perfect_cache = 1;
  } else {
    if (toks.size() != 2) {
      cerr << "Error: option ", line, " has wrong number of arguments", endl;
      return true;
    }
    int reg = -1;
    foreach (j, sizeof(arch_reg_names) / sizeof(arch_reg_names[0])) {
      if (!strcmp(toks[0], arch_reg_names[j])) {
        reg = j; break;
      }
    }
    if (reg < 0) {
      cerr << "Error: invalid register ", toks[0], endl;
      return true;
    }
    char* endp;
    W64 v = strtoull(toks[1], &endp, 0);
    if (*endp != '\0') {
      cerr << "Error: invalid value ", toks[1], endl;
      return true;
    }
    ctx.commitarf[reg] = v;
  }

  return false;
}

//
// PTLsim main: called after ptlsim_preinit() brings up boot subsystems
//
int main(int argc, char** argv) {
  ptl_mm_init();
  call_global_constuctors();

  configparser.setup();
  config.reset();

  int ptlsim_arg_count = 1 + configparser.parse(config, argc-1, argv+1);
  if (ptlsim_arg_count == 0) ptlsim_arg_count = argc;
  handle_config_change(config, ptlsim_arg_count - 1, argv+1);

  CycleTimer::gethz();

  init_uops();
  init_decode();


  // Set up initial context:
  ctx.reset();
  asp.reset();
  ctx.use32 = 1;
  ctx.use64 = 1;
  ctx.commitarf[REG_rsp] = 0;
  ctx.commitarf[REG_rip] = 0x100000;
  ctx.commitarf[REG_flags] = 0;
  ctx.internal_eflags = 0;

  ctx.seg[SEGID_CS].selector = 0x33;
  ctx.seg[SEGID_SS].selector = 0x2b;
  ctx.seg[SEGID_DS].selector = 0x00;
  ctx.seg[SEGID_ES].selector = 0x00;
  ctx.seg[SEGID_FS].selector = 0x00;
  ctx.seg[SEGID_GS].selector = 0x00;
  ctx.update_shadow_segment_descriptors();


  // ctx.fxrstor(x87state);

  ctx.vcpuid = 0;
  ctx.running = 1;
  ctx.commitarf[REG_ctx] = (Waddr)&ctx;
  ctx.commitarf[REG_fpstack] = (Waddr)&ctx.fpstack;

  dynarray<Waddr> dump_pages;

  // TODO(AE): set seccomp filter before parsing arguments
  bool parse_err = false;
  for (unsigned i = ptlsim_arg_count; i < argc; i++) {
    if (argv[i][0] == '@') {
      stringbuf line;
      istream is(argv[i] + 1);
      if (!is) {
        cerr << "Warning: cannot open command list file '", argv[i], "'", endl;
        continue;
      }

      for (;;) {
        line.reset();
        is >> line;
        if (!is) break;

        char* p = strchr(line, '#');
        if (p) *p = 0;
        parse_err |= handle_config_arg(line, &dump_pages);
      }
    } else {
      parse_err |= handle_config_arg(argv[i], &dump_pages);
    }
  }

  if (parse_err) {
    cerr << "Error: could not parse all arguments", endl, flush;
    sys_exit(1);
  }

  // asp.map(0x100000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC);
  // W64 endless_loop = 0x80cdc031c031;
  // // endless_loop = 0xfeeb;
  // assert(ctx.copy_to_user(0x100000, &endless_loop, 8) == 8);
  // asp.cleardirty(0x100000 >> 12);
  // asp.setattr((void*)0x100000, 0x1000, PROT_READ|PROT_EXEC);

  logfile << endl, "=== Switching to simulation mode at rip ", (void*)(Waddr)ctx.commitarf[REG_rip], " ===", endl, endl, flush;


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

  cerr << "End state:", endl;
  cerr << ctx, endl;
  foreach (i, dump_pages.length) {
    Waddr addr = dump_pages[i];
    byte* mapped = (byte*)asp.page_virt_to_mapped(addr);
    if (!mapped) {
      cerr << "Error dumping memory: page not mapped ", (void*) addr, endl;
    } else {
      cerr << "Dump of memory at ", (void*) addr, ": ", endl;
      cerr << bytestring(mapped, PAGE_SIZE), endl;
    }
  }
  cerr << "Decoder stats:";
  foreach(i, DECODE_TYPE_COUNT) {
    cerr << " ", decode_type_names[i], "=", stats.decoder.x86_decode_type[i];
  }
  cerr << endl;
  cerr << flush;

  cerr << endl, "=== Exiting after full simulation on tid ", sys_gettid(), " at rip ", (void*)(Waddr)ctx.commitarf[REG_rip], " (",
    sim_cycle, " cycles, ", total_user_insns_committed, " user commits, ", iterations, " iterations) ===", endl, endl;
  shutdown_subsystems();
  logfile.flush();
  sys_exit(0);
}

bool inside_ptlsim = 1;
bool requested_switch_to_native = 0;
