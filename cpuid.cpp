//
// CPUID: print information about current CPU
//
// Copyright 2000-2008 Matt T. Yourst <yourst@yourst.com>
//

#include <globals.h>
#include <superstl.h>
#include <ptlcalls.h>
#include <config.h>
#include <logic.h>

#define PTLSIM_PUBLIC_ONLY
#include <ptlhwdef.h>

union CPUVendorID {
  char text[13];
  W32 data[3];
};

union ProcessorModelInfo {
  struct { W32 stepping:4, model:4, family:4, reserved1:4, extmodel:4, extfamily:8, reserved2:4; } fields;
  W32 data;
};

union ProcessorMiscInfo {
  struct { W32 brandid:8, clflush:8, reserved:8, apicid:8; } fields;
  W32 data;
};

union TLBInfo {
  struct { W32 itlbsize:8, itlbways:8, dtlbsize:8, dtlbways:8; } fields;
  W32 data;
};

union CacheInfo {
  struct { W32 linesize:8, linespertag:8, ways:8, size:8; } fields;
  W32 data;
};

union L2CacheInfo {
  struct { W32 linesize:8, linespertag:4, ways:4, size:16; } fields;
  W32 data;
};

static const char* x86_cap_flags[] = {
  // Intel-defined
  "fpu", "vme", "de", "pse", "tsc", "msr", "pae", "mce",
  "cx8", "apic", "CAP10", "sep", "mtrr", "pge", "mca", "cmov",
  "pat", "pse36", "pn", "clflush", "CAP20", "dts", "acpi", "mmx",
  "fxsr", "sse", "sse2", "ss", "ht", "tm", "ia64", "CAP31",
  // AMD and Intel-defined
};

static const char* x86_ext_cap_flags[] = {
  "x87", "vme", "de", "pse", "tsc", "msr", "pae", "mce",
  "cx8", "apic", "CAP10", "syscall", "mtrr", "pge", "mca", "cmov",
  "pat", "pse36", "pn", "clflush", "nx", "CAP21", "mmxext", "mmx",
  "fxsr", "CAP25", "CAP26", "CAP27", "CAP28", "lm", "3dnowext", "3dnow",
};

struct DescriptorTablePointer {
  W16 bytes;
  W64 virtaddr;
} packedstruct;

ostream& operator <<(ostream& os, const DescriptorTablePointer& dtp) {
  return os << (void*)(Waddr)dtp.virtaddr, ", limit ", dtp.bytes, " (", (void*)(Waddr)dtp.bytes, ")";
}

static inline void sgdt(DescriptorTablePointer& p) {
  setzero(p);
  asm volatile("sgdt %[p]" : [p] "=m" (p) : : "memory");
}

static inline void sidt(DescriptorTablePointer& p) {
  setzero(p);
  asm volatile("sidt %[p]" : [p] "=m" (p) : : "memory");
}

static inline void sldt(W16& selector) {
  selector = 0;
  asm volatile("sldt %[selector]" : [selector] "=m" (selector) : : "memory");
}

#define XEN_EMULATE_PREFIX ".byte 0x0f,0x0b,0x78,0x65,0x6e ; "

static inline void cpuidxen(int op, W32& eax, W32& ebx, W32& ecx, W32& edx) {
	asm(XEN_EMULATE_PREFIX "cpuid" : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx) : "0" (op + 0x40000000));
}

static inline W64 rdpmc(W32 op) {
  W32 eax;
  W32 edx;
	asm volatile("rdpmc" : "=a" (eax), "=d" (edx) : "c" (op));
  return (((W64)edx) << 32) + ((W64)eax);
}

int main(int argc, char* argv[]) {
  W32 eax, ebx, ecx, edx;
  W32 maxfuncs;

  {
    cout << "Function 0:", endl;
    CPUVendorID vendor;
    memset(&vendor, 0, sizeof(vendor));
    cpuid(0, maxfuncs, vendor.data[0], vendor.data[2], vendor.data[1]);
    cout << "  Maximum functions: ", maxfuncs, endl;
    cout << "  Vendor ID:         ", vendor.text, endl;
  }

  if (maxfuncs < 1) return 0;

  {
    cout << "Function 1:", endl;
    ProcessorModelInfo model;
    ProcessorMiscInfo miscinfo;
    W32 features;
    cpuid(1, model.data, miscinfo.data, ecx, features);
    cout << "  Model Information (0x", hexstring(model.data, 32), "):", endl;
    cout << "    Family:    ", intstring(model.fields.family, 3), endl;
    cout << "    Model:     ", intstring(model.fields.model, 3), endl;
    cout << "    Stepping:  ", intstring(model.fields.stepping, 3), endl;
    cout << "    ExtModel:  ", intstring(model.fields.extmodel, 3), endl;
    cout << "    ExtFamily: ", intstring(model.fields.extfamily, 3), endl;
    cout << "    Reserved1: ", intstring(model.fields.reserved1, 3), endl;
    cout << "    Reserved2: ", intstring(model.fields.reserved1, 3), endl;
    cout << "  Other Information (0x", hexstring(miscinfo.data, 32), "):", endl;
    cout << "    Brand ID:  ", intstring(miscinfo.fields.brandid, 3), endl;
    cout << "    Line Size: ", intstring(miscinfo.fields.clflush*8, 3), endl;
    cout << "    APIC ID:   ", intstring(miscinfo.fields.apicid, 3), endl;
    cout << "    Reserved:  ", intstring(miscinfo.fields.reserved, 3), endl;
    cout << "  Features (0x", hexstring(features, 32), "):", endl;
    cout << "    Features:  ";
    foreach (i, 32) {
      if (bit(features, i)) cout << x86_cap_flags[i], " ";
    }
    cout << endl;
    cout << "  ECX value:   ", "0x", hexstring(ecx, 32), endl;
  }

  {
    cout << "Extended Function 0:", endl;
    CPUVendorID vendor;
    memset(&vendor, 0, sizeof(vendor));
    cpuid(0x80000000, maxfuncs, vendor.data[0], vendor.data[2], vendor.data[1]);
    maxfuncs -= 0x80000000;
    cout << "  Maximum functions: ", maxfuncs, endl;
    cout << "  Vendor ID:         ", vendor.text, endl;
  }

  if (maxfuncs < 1) return 0;

  {
    cout << "Extended Function 1:", endl;
    ProcessorModelInfo model;
    W32 features;
    cpuid(0x80000001, model.data, ebx, ecx, features);
    cout << "  Model Information (0x", hexstring(model.data, 32), "):", endl;
    cout << "    Family:    ", model.fields.family, endl;
    cout << "    Model:     ", model.fields.model, endl;
    cout << "    Stepping:  ", model.fields.stepping, endl;
    cout << "    ExtModel:  ", model.fields.extmodel, endl;
    cout << "    ExtFamily: ", model.fields.extfamily, endl;
    cout << "    Reserved1: ", model.fields.reserved1, endl;
    cout << "    Reserved2: ", model.fields.reserved1, endl;
    cout << "  EBX value:   ", "0x", hexstring(ebx, 32), endl;
    cout << "  ECX value:   ", "0x", hexstring(ecx, 32), endl;

    cout << "  Vendor Specific Features (0x", hexstring(features, 32), "):", endl;
    cout << "    Features:  ";
    foreach (i, 32) {
      if (bit(features, i)) cout << x86_ext_cap_flags[i], " ";
    }
    cout << endl;
  }

  if (maxfuncs < 4) return 0;

  {
    cout << "Extended Functions 2-4: Processor Name", endl;
    W32 namedata[13];
    cpuid(0x80000002, namedata[0], namedata[1], namedata[2], namedata[3]);
    cpuid(0x80000003, namedata[4], namedata[5], namedata[6], namedata[7]);
    cpuid(0x80000004, namedata[8], namedata[9], namedata[10], namedata[11]);
    namedata[13] = 0;
    cout << "    Description: '", (char*)&namedata, "'", endl;
  }

  if (maxfuncs < 5) return 0;

  {
    cout << "Extended Function 5: L1 Cache and TLB Info", endl;
    TLBInfo tlb;
    CacheInfo L1D;
    CacheInfo L1I;
    cpuid(0x80000005, eax, tlb.data, L1D.data, L1I.data);
    cout << "  DTLB:   ", tlb.fields.dtlbsize, " in ", (tlb.fields.dtlbways == 0xff ? tlb.fields.dtlbsize : tlb.fields.dtlbways), " ways", endl;
    cout << "  ITLB:   ", tlb.fields.itlbsize, " in ", (tlb.fields.itlbways == 0xff ? tlb.fields.dtlbsize : tlb.fields.dtlbways), " ways", endl;
    cout << "  L1D:    ", L1D.fields.size, " KB, ", L1D.fields.linesize, " bytes/line, ", L1D.fields.linespertag, " lines/tag, ", L1D.fields.ways, " ways", endl;
    cout << "  L1I:    ", L1I.fields.size, " KB, ", L1I.fields.linesize, " bytes/line, ", L1I.fields.linespertag, " lines/tag, ", L1I.fields.ways, " ways", endl;
  }

  if (maxfuncs < 6) return 0;

  {
    cout << "Extended Function 5: L2 Cache and TLB Info", endl;
    TLBInfo tlb4k;
    TLBInfo tlb2m;
    L2CacheInfo L2;

    int way_decode[16] = {0, 1, 2, -1, 4, -1, 8, -1, 16, -1, -1, -1, -1, -1, -1, 256};

    cpuid(0x80000006, tlb2m.data, tlb4k.data, L2.data, edx);
    cout << "  DTLB4K: ", tlb4k.fields.dtlbsize, " in ", (tlb4k.fields.dtlbways == 0xff ? tlb4k.fields.dtlbsize : tlb4k.fields.dtlbways), " ways", endl;
    cout << "  ITLB4K: ", tlb4k.fields.itlbsize, " in ", (tlb4k.fields.itlbways == 0xff ? tlb4k.fields.itlbsize : tlb4k.fields.itlbways), " ways", endl;
    cout << "  DTLB2M: ", tlb2m.fields.dtlbsize, " in ", (tlb2m.fields.dtlbways == 0xff ? tlb2m.fields.dtlbsize : tlb2m.fields.dtlbways), " ways", endl;
    cout << "  ITLB2M: ", tlb2m.fields.itlbsize, " in ", (tlb2m.fields.itlbways == 0xff ? tlb2m.fields.dtlbsize : tlb2m.fields.dtlbways), " ways", endl;
    cout << "  L2:     ", L2.fields.size, " KB, ", L2.fields.linesize, " bytes/line, ", L2.fields.linespertag, " lines/tag, ", way_decode[L2.fields.ways], " ways", endl;
    cout << "  EDX:    ", "0x", hexstring(edx, 32), endl;
  }

  {
    DescriptorTablePointer gdt, idt;
    W16 ldt;

    // sgdt(gdt);
    // sidt(idt);
    // sldt(ldt);
    cout << "Descriptor Tables", endl, flush;
    cout << "  GDT: ", gdt, endl;
    cout << "  IDT: ", idt, endl;
    cout << "  LDT: ", hexstring(ldt, 16), endl;
  }

  {
    W64 tsc = rdtsc();
    cout << "Timestamp counter:", endl;
    cout << "  Timestamp counter: ", intstring(tsc, 32), " = 0x", hexstring(tsc, 64), endl;
    cout << "  Core frequency:    ", intstring(get_core_freq_hz(), 32), endl;
  }

  cout << endl;
}

