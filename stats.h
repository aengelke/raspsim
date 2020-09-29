// -*- c++ -*-
//
// PTLsim: Cycle Accurate x86-64 Simulator
// Statistics data store tree
//
// Copyright 2005-2008 Matt T. Yourst <yourst@yourst.com>
//

#ifndef _STATS_H_
#define _STATS_H_

#include <globals.h>
#include <superstl.h>
#include <ptlsim.h>

#define STATS_ONLY
#include <decode.h>
#include <ooocore.h>
#include <dcache.h>
#include <branchpred.h>
#undef STATS_ONLY


#define increment_clipped_histogram(h, slot, incr) h[clipto(W64(slot), W64(0), W64(lengthof(h)-1))] += incr;

//
// This file is run through dstbuild to auto-generate
// the code to instantiate a DataStoreNodeTemplate tree.
// Its format must be parsable by dstbuild.
//
// All character array fields MUST be a multiple of 8 bytes!
// Otherwise the structure parser and gcc will not have
// the same interpretation of things.
//

//
// IMPORTANT! PTLsim must be statically compiled with a maximum
// limit on the number of VCPUs. If you increase this, you'll
// need to replicate the vcpu0,vcpu1,... structures in several
// places below.
//
static const int MAX_SIMULATED_VCPUS = 4;

struct EventsInMode { // rootnode: summable
  W64 user64;
  W64 user32;
  W64 kernel64;
  W64 kernel32;
  W64 legacy16;
  W64 microcode;
  W64 idle;
};

struct PTLsimStats { // rootnode:
  W64 snapshot_uuid;
  char snapshot_name[64];

  struct summary {
    W64 cycles;
    W64 insns;
    W64 uops;
    W64 basicblocks;
  } summary;

  struct simulator {
    // Compile time information
    struct version {
      char build_timestamp[32];
      W64 svn_revision;
      char svn_timestamp[32];
      char build_hostname[64];
      char build_compiler[16];
    } version;

    // Runtime information
    struct run {
      W64 timestamp;
      char hostname[64];
      char kernel_version[32];
#ifdef PTLSIM_HYPERVISOR
      char hypervisor_version[32];
#else
      char executable[128];
      char args[256];
#endif
      W64 native_cpuid;
      W64 native_hz;
    } run;

    struct config {
      // Configuration string passed for this run
      char config[256];
    } config;

    struct performance {
      struct rate {
        double cycles_per_sec;
        double issues_per_sec;
        double user_commits_per_sec;
      } rate;
    } performance;
  } simulator;

  //
  // Decoder and basic block cache
  //
  struct decoder {
    struct throughput {
      W64 basic_blocks;
      W64 x86_insns;
      W64 uops;
      W64 bytes;
    } throughput;

    W64 x86_decode_type[DECODE_TYPE_COUNT]; // label: decode_type_names

    struct bb_decode_type { // node: summable
      W64 all_insns_fast;
      W64 some_complex_insns;
    } bb_decode_type;

    // Alignment of instructions within pages
    struct page_crossings { // node: summable
      W64 within_page;
      W64 crosses_page;
    } page_crossings;

    // Basic block cache
    struct bbcache {
      W64 count;
      W64 inserts;
      W64 invalidates[INVALIDATE_REASON_COUNT]; // label: invalidate_reason_names
    } bbcache;

    // Page cache
    struct pagecache {
      W64 count;
      W64 inserts;
      W64 invalidates[INVALIDATE_REASON_COUNT]; // label: invalidate_reason_names
    } pagecache;

    W64 reclaim_rounds;
  } decoder;

  OutOfOrderCoreStats ooocore;
  DataCacheStats dcache;


  struct external {
    W64 assists[ASSIST_COUNT]; // label: assist_names
    W64 traps[256]; // label: x86_exception_names
#ifdef PTLSIM_HYPERVISOR
    EventsInMode cycles_in_mode;
    EventsInMode insns_in_mode;
    EventsInMode uops_in_mode;
#endif
  } external;
};

extern struct PTLsimStats stats;

#endif // _STATS_H_
