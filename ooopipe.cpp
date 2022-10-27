//
// PTLsim: Cycle Accurate x86-64 Simulator
// Out-of-Order Core Simulator
// Core Pipeline Stages: Frontend, Writeback, Commit
//
// Copyright 2003-2008 Matt T. Yourst <yourst@yourst.com>
// Copyright 2006-2008 Hui Zeng <hzeng@cs.binghamton.edu>
//

#include <globals.h>
#include <elf.h>
#include <ptlsim.h>
#include <branchpred.h>
#include <logic.h>
#include <dcache.h>

#define INSIDE_OOOCORE
#include <ooocore.h>
#include <stats.h>

#ifndef ENABLE_CHECKS
#undef assert
#define assert(x) (x)
#endif

#ifndef ENABLE_LOGGING
#undef logable
#define logable(level) (0)
#endif

using namespace OutOfOrderModel;

void OutOfOrderCoreCacheCallbacks::icache_wakeup(LoadStoreInfo lsi, W64 physaddr) {
  foreach (i, core.threadcount) {
    ThreadContext* thread = core.threads[i];
    if unlikely (thread && thread->waiting_for_icache_fill && (floor(thread->waiting_for_icache_fill_physaddr, CacheSubsystem::L1_LINE_SIZE) == physaddr)) {
      if (logable(6)) logfile << "[vcpu ", thread->ctx.vcpuid, "] i-cache wakeup of physaddr ", (void*)(Waddr)physaddr, endl;
      thread->waiting_for_icache_fill = 0;
      thread->waiting_for_icache_fill_physaddr = 0;
    }
  }
}

//
// Determine which physical register files can be written
// by a given type of uop.
//
// This must be customized if the physical register files
// are altered in smthwdef.h.
//
static W32 phys_reg_files_writable_by_uop(const TransOp& uop) {
  W32 c = opinfo[uop.opcode].opclass;

#ifdef UNIFIED_INT_FP_PHYS_REG_FILE
  return
    (c & OPCLASS_STORE) ? OutOfOrderCore::PHYS_REG_FILE_MASK_ST :
    (c & OPCLASS_BRANCH) ? OutOfOrderCore::PHYS_REG_FILE_MASK_BR :
    OutOfOrderCore::PHYS_REG_FILE_MASK_INT;
#else
  return
    (c & OPCLASS_STORE) ? OutOfOrderCore::PHYS_REG_FILE_MASK_ST :
    (c & OPCLASS_BRANCH) ? OutOfOrderCore::PHYS_REG_FILE_MASK_BR :
    (c & (OPCLASS_LOAD | OPCLASS_PREFETCH)) ? ((uop.datatype == DATATYPE_INT) ? OutOfOrderCore::PHYS_REG_FILE_MASK_INT : OutOfOrderCore::PHYS_REG_FILE_MASK_FP) :
    ((c & OPCLASS_FP) | inrange((int)uop.rd, REG_xmml0, REG_xmmh15) | inrange((int)uop.rd, REG_fptos, REG_ctx)) ? OutOfOrderCore::PHYS_REG_FILE_MASK_FP :
    OutOfOrderCore::PHYS_REG_FILE_MASK_INT;
#endif
}

void ThreadContext::annul_fetchq() {
  //
  // There may be return address stack (RAS) updates from calls and returns
  // in the fetch queue that never made it to renaming, so they have no ROB
  // that the core can annul normally. Therefore, we must go backwards in
  // the fetch queue to annul these updates, in addition to checking the ROB.
  //
  foreach_backward (fetchq, i) {
    FetchBufferEntry& fetchbuf = fetchq[i];
    if unlikely (isbranch(fetchbuf.opcode) && (fetchbuf.predinfo.bptype & (BRANCH_HINT_CALL|BRANCH_HINT_RET))) {
      if unlikely (config.event_log_enabled) core.eventlog.add(EVENT_ANNUL_FETCHQ_RAS, fetchbuf);
      branchpred.annulras(fetchbuf.predinfo);
    }
  }
}

//
// Flush entire pipeline immediately, reset all processor
// structures to their initial state, and resume from the
// state saved in ctx.commitarf.
//

void OutOfOrderCore::flush_pipeline_all() {
  // Clear per-thread state:
  foreach (i, threadcount) {
    ThreadContext* thread = threads[i];
    thread->flush_pipeline();
  }
  // Clear out everything global:
  setzero(robs_on_fu);
}

void ThreadContext::flush_pipeline() {
  // SD: I wonder if flush_pipeline should really be able to flush halfway
  // through a partially committed x86 instruction. This is dangerous,
  // especially if the instruction has already partially updated
  // architectural state.
  if unlikely (logable(1) && rob_ready_to_commit_queue.count &&
               !ROB.peekhead()->uop.som) {

    logfile << "[vcpu ", ctx.vcpuid, "] thread ", threadid, ": Flushing through a "
               "partially committed x86 instruction, this is likely BAD:",endl;

    foreach_forward(ROB, i) {
      ReorderBufferEntry& rob = ROB[i];
      logfile <<"  ", rob, endl;
      if (rob.uop.eom) break;
    }
  }

  core.caches.complete(threadid);
  annul_fetchq();

  foreach_forward(ROB, i) {
    ReorderBufferEntry& rob = ROB[i];
    rob.release_mem_lock(true);
    //
    // Note that we might actually flush halfway through a locked RMW
    // instruction, but this is not as bad as in the annul case, as the
    // store (the W-part of the RMW) will be wiped too.
    //
    flush_mem_lock_release_list();
    rob.physreg->reset(threadid); // free all register allocated by rob

    if unlikely (config.event_log_enabled)
      core.eventlog.add(EVENT_ANNUL_FLUSH, &rob);

  }

  // free all register in arch state:
  foreach (i, PHYS_REG_FILE_COUNT){
    StateList& list = core.physregfiles[i].states[PHYSREG_ARCH];
    PhysicalRegister* obj;
    int n = 0;
    foreach_list_mutable( list, obj, entry, nextentry) {
      n++;
      obj->reset(threadid);
    }
  }

  // free all register in arch state:
  foreach (i, PHYS_REG_FILE_COUNT){
    StateList& list = core.physregfiles[i].states[PHYSREG_PENDINGFREE];
    PhysicalRegister* obj;
    int n = 0;
    foreach_list_mutable( list, obj, entry, nextentry) {
      n++;
      obj->reset(threadid);
    }
  }

  reset_fetch_unit(ctx.commitarf[REG_rip]);
  rob_states.reset();

  ROB.reset();
  foreach (i, ROB_SIZE) {
    ROB[i].coreid = core.coreid;
    ROB[i].threadid = threadid;
    ROB[i].changestate(rob_free_list);
  }
  LSQ.reset();
  foreach (i, LSQ_SIZE) {
    LSQ[i].coreid = core.coreid;
  }
  loads_in_flight = 0;
  stores_in_flight = 0;
  foreach_issueq(reset(core.coreid, threadid));

  dispatch_deadlock_countdown = DISPATCH_DEADLOCK_COUNTDOWN_CYCLES;
  last_commit_at_cycle = sim_cycle;
  external_to_core_state();
}

//
// Respond to a branch mispredict or other redirection:
//
void ThreadContext::reset_fetch_unit(W64 realrip) {
  if (current_basic_block) {
    // Release our lock on the cached basic block we're currently fetching
    current_basic_block->release();
    current_basic_block = null;
  }

  fetchrip = realrip;
  fetchrip.update(ctx);
  stall_frontend = 0;
  waiting_for_icache_fill = 0;
  fetchq.reset();
  current_basic_block_transop_index = 0;
  unaligned_ldst_buf.reset();
}

//
// Process any pending self-modifying code invalidate requests.
// This must be called on all cores *after* flushing all pipelines,
// to ensure no stale BBs are referenced, thus preventing them
// from being freed.
//
void ThreadContext::invalidate_smc() {
  if unlikely (smc_invalidate_pending) {
    if (logable(5)) logfile << "SMC invalidate pending on ", smc_invalidate_rvp, endl;
    bbcache.invalidate_page(smc_invalidate_rvp.mfnlo, INVALIDATE_REASON_SMC);
    if unlikely (smc_invalidate_rvp.mfnlo != smc_invalidate_rvp.mfnhi) bbcache.invalidate_page(smc_invalidate_rvp.mfnhi, INVALIDATE_REASON_SMC);
    smc_invalidate_pending = 0;
  }
}

//
// Copy external archregs to physregs and reset all rename tables
//
void ThreadContext::external_to_core_state() {
  foreach (i, PHYS_REG_FILE_COUNT) {
    PhysicalRegisterFile& rf = core.physregfiles[i];
    PhysicalRegister* zeroreg = rf.alloc(threadid, PHYS_REG_NULL);
    zeroreg->addspecref(0, threadid);
    zeroreg->commit();
    zeroreg->data = 0;
    zeroreg->flags = 0;
    zeroreg->archreg = REG_zero;
  }

  // Always start out on cluster 0:
  PhysicalRegister* zeroreg = &core.physregfiles[0][PHYS_REG_NULL];

  //
  // Allocate and commit each architectural register
  //
  foreach (i, ARCHREG_COUNT) {
    //
    // IMPORTANT! If using some register file configuration other
    // than (integer, fp), this needs to be changed!
    //
#ifdef UNIFIED_INT_FP_PHYS_REG_FILE
    int rfid = (i == REG_rip) ? PHYS_REG_FILE_BR : PHYS_REG_FILE_INT;
#else
    bool fp = inrange((int)i, REG_xmml0, REG_xmmh15) | (inrange((int)i, REG_fptos, REG_ctx));
    int rfid = (fp) ? core.PHYS_REG_FILE_FP : (i == REG_rip) ? core.PHYS_REG_FILE_BR : core.PHYS_REG_FILE_INT;
#endif
    PhysicalRegisterFile& rf = core.physregfiles[rfid];
    PhysicalRegister* physreg = (i == REG_zero) ? zeroreg : rf.alloc(threadid);
    assert(physreg); /// need increase rf size if failed.
    physreg->archreg = i;
    physreg->data = ctx.commitarf[i];
    physreg->flags = 0;
    commitrrt[i] = physreg;
  }

  commitrrt[REG_flags]->flags = (W16)commitrrt[REG_flags]->data;

  //
  // Internal translation registers are never used before
  // they are written for the first time:
  //
  for (int i = ARCHREG_COUNT; i < TRANSREG_COUNT; i++) {
    commitrrt[i] = zeroreg;
  }

  //
  // Set renamable flags
  //
  commitrrt[REG_zf] = commitrrt[REG_flags];
  commitrrt[REG_cf] = commitrrt[REG_flags];
  commitrrt[REG_of] = commitrrt[REG_flags];

  //
  // Copy commitrrt to specrrt and update refcounts
  //
  foreach (i, TRANSREG_COUNT) {
    commitrrt[i]->commit();
    specrrt[i] = commitrrt[i];
    specrrt[i]->addspecref(i, threadid);
    commitrrt[i]->addcommitref(i, threadid);
  }

#ifdef ENABLE_TRANSIENT_VALUE_TRACKING
  specrrt.renamed_in_this_basic_block.reset();
  commitrrt.renamed_in_this_basic_block.reset();
#endif
}

//
// Re-dispatch all uops in the ROB that have not yet generated
// a result or are otherwise stalled.
//
void ThreadContext::redispatch_deadlock_recovery() {
  if (logable(6)) core.dump_smt_state(logfile);

  per_context_ooocore_stats_update(threadid, dispatch.redispatch.deadlock_flushes++);
  // don't want to reset the counter for no commit in this case
  W64 previous_last_commit_at_cycle = last_commit_at_cycle;
  flush_pipeline();
  last_commit_at_cycle = previous_last_commit_at_cycle; /// so we can exit after no commit after deadlock recovery a few times in a roll
  logfile << "[vcpu ", ctx.vcpuid, "] thread ", threadid, ": reset thread.last_commit_at_cycle to be before redispatch_deadlock_recovery() ", previous_last_commit_at_cycle, endl;
  /*
  //
  // This is a more selective scheme than the full pipeline flush.
  // Presently it does not work correctly with some combinations
  // of user-modifiable parameters, so it's disabled to ensure
  // deadlock-free operation in every configuration.
  //

  ReorderBufferEntry* prevrob = null;
  bitvec<MAX_OPERANDS> noops = 0;

  foreach_forward(ROB, robidx) {
  ReorderBufferEntry& rob = ROB[robidx];

  //
  // Only re-dispatch those uops that have not yet generated a value
  // or are guaranteed to produce a value soon without tying up resources.
  // This must occur in program order to avoid deadlock!
  //
  // bool recovery_required = (rob.current_state_list->flags & ROB_STATE_IN_ISSUE_QUEUE) || (rob.current_state_list == &rob_ready_to_dispatch_list);
  bool recovery_required = 1; // for now, just to be safe

  if (recovery_required) {
  rob.redispatch(noops, prevrob);
  prevrob = &rob;
  per_context_ooocore_stats_update(threadid, dispatch.redispatch.deadlock_uops_flushed++);
  }
  }

  if (logable(6)) dump_smt_state();
  */
}


//
// Fetch Stage
//
// Fetch a stream of x86 instructions from the L1 i-cache along predicted
// branch paths.
//
// Internally, up to N uops per clock corresponding to instructions in
// the current basic block are fetched per cycle and placed in the uopq
// as TransOps. When we run out of uops in one basic block, we proceed
// to lookup or translate the next basic block.
//

//
// Used to debug crashes when cycle to start logging can't be determined:
//
static RIPVirtPhys fetch_bb_address_ringbuf[256];
static W64 fetch_bb_address_ringbuf_head = 0;

static void print_fetch_bb_address_ringbuf(ostream& os) {
  os << "Head: ", fetch_bb_address_ringbuf_head, endl;
  foreach (i, lengthof(fetch_bb_address_ringbuf)) {
    int j = (fetch_bb_address_ringbuf_head + i) % lengthof(fetch_bb_address_ringbuf);
    const RIPVirtPhys& addr = fetch_bb_address_ringbuf[j];
    os << "  ", intstring(i, 16), ": ", addr, endl;
  }
}

int OutOfOrderCore::hash_unaligned_predictor_slot(const RIPVirtPhysBase& rvp) {
  W32 h = rvp.rip ^ rvp.mfnlo;
  return lowbits(h, log2(UNALIGNED_PREDICTOR_SIZE));
}

bool OutOfOrderCore::get_unaligned_hint(const RIPVirtPhysBase& rvp) const {
  int slot = hash_unaligned_predictor_slot(rvp);
  return unaligned_predictor[slot];
}

void OutOfOrderCore::set_unaligned_hint(const RIPVirtPhysBase& rvp, bool value) {
  int slot = hash_unaligned_predictor_slot(rvp);
  assert(inrange(slot, 0, UNALIGNED_PREDICTOR_SIZE));
  unaligned_predictor[slot] = value;
}

bool ThreadContext::fetch() {
  OutOfOrderCore& core = getcore();
  EventLog& eventlog = core.eventlog;

  int fetchcount = 0;
  int taken_branch_count = 0;

  OutOfOrderCoreEvent* event;

  if unlikely (stall_frontend) {
    if unlikely (config.event_log_enabled) {
      event = eventlog.add(EVENT_FETCH_STALLED);
      event->threadid = threadid;
    }
    per_context_ooocore_stats_update(threadid, fetch.stop.stalled++);
    return true;
  }

  if unlikely (waiting_for_icache_fill) {
    if unlikely (config.event_log_enabled){
      event = eventlog.add(EVENT_FETCH_ICACHE_WAIT);
      event->threadid = threadid;
      event->rip = fetchrip;
      event->uuid = fetch_uuid;
    }
    per_context_ooocore_stats_update(threadid, fetch.stop.icache_miss++);
    return true;
  }

  while ((fetchcount < FETCH_WIDTH) && (taken_branch_count == 0)) {
    if unlikely (!fetchq.remaining()) {
      if unlikely (config.event_log_enabled) {
        if (!fetchcount) {
          event =  eventlog.add(EVENT_FETCH_FETCHQ_FULL);
          event->threadid = threadid;
          event->uuid = fetch_uuid;
        }
      }
      per_context_ooocore_stats_update(threadid, fetch.stop.fetchq_full++);
      break;
    }

#ifndef MULTI_IQ
    if unlikely (core.threadcount > 1) {
      if ((issueq_count + fetchcount) >= core.reserved_iq_entries) {
        bool empty = false;
        issueq_operation_on_cluster_with_result(core, cluster, empty, shared_empty());
        //
        //++MTY FIXME starvation occurs when only one thread is in running state:
        // we should re-balance reserved pool depending on number of running threads,
        // not total number of threads!
        //
        if (empty) {
          // no shared entries left, stop fetching
          break;
        } else {
          // found a shared entry: continue fetching
        }
      } else {
        // still have reserved entries left, continue fetching
      }
    }
#endif

    if unlikely ((fetchrip.rip == config.start_log_at_rip) && (fetchrip.rip != 0xffffffffffffffffULL)) {
      config.start_log_at_iteration = 0;
      logenable = 1;
    }

    if unlikely ((!current_basic_block) || (current_basic_block_transop_index >= current_basic_block->count)) {
      fetch_bb_address_ringbuf[fetch_bb_address_ringbuf_head] = fetchrip;
      fetch_bb_address_ringbuf_head = add_index_modulo(fetch_bb_address_ringbuf_head, +1, lengthof(fetch_bb_address_ringbuf));
      fetch_or_translate_basic_block(fetchrip);
    }

    if unlikely (current_basic_block->invalidblock) {
      if unlikely (config.event_log_enabled) {
        event = eventlog.add(EVENT_FETCH_BOGUS_RIP, fetchrip);
        event->threadid = threadid;
      }
      per_context_ooocore_stats_update(threadid, fetch.stop.bogus_rip++);
      //
      // Keep fetching - the decoder has injected assist microcode that
      // branches to the invalid opcode or exec page fault handler.
      //
    }

#ifdef PTLSIM_HYPERVISOR
    Waddr physaddr = (fetchrip.mfnlo << 12) + lowbits(fetchrip, 12);
#else
    Waddr physaddr = fetchrip;
#endif

    W64 req_icache_block = floor(physaddr, ICACHE_FETCH_GRANULARITY);
    if ((!current_basic_block->invalidblock) && (req_icache_block != current_icache_block)) {
      bool hit = core.caches.probe_icache(fetchrip, physaddr);
      hit |= config.perfect_cache;
      if unlikely (!hit) {
        int missbuf = core.caches.initiate_icache_miss(physaddr, fetch_uuid,threadid);
        if unlikely (config.event_log_enabled) {
          event = eventlog.add(EVENT_FETCH_ICACHE_MISS, fetchrip);
          event->fetch.missbuf = missbuf;
          event->threadid = threadid;
          event->uuid = fetch_uuid;
        }

        if unlikely (missbuf < 0) {
          // Try to re-allocate a miss buffer on the next cycle
          break;
        }
        waiting_for_icache_fill = 1;
        waiting_for_icache_fill_physaddr = req_icache_block;
        per_context_ooocore_stats_update(threadid, fetch.stop.icache_miss++);
        break;
      }

      per_context_ooocore_stats_update(threadid, fetch.blocks++);
      current_icache_block = req_icache_block;
      per_context_dcache_stats_update(threadid, fetch.hit.L1++);
    }

    FetchBufferEntry& transop = *fetchq.alloc();
    uopimpl_func_t synthop = null;

    assert(current_basic_block->synthops);

    if likely (!unaligned_ldst_buf.get(transop, synthop)) {
      transop = current_basic_block->transops[current_basic_block_transop_index];
      synthop = current_basic_block->synthops[current_basic_block_transop_index];
    }

    // If opcode is OP_ld_a16/OP_st_a16, it must be aligned.
    transop.unaligned = core.get_unaligned_hint(fetchrip) &&
      ((transop.opcode == OP_ld) | (transop.opcode == OP_ldx) | (transop.opcode == OP_st)) &&
      (transop.cond == LDST_ALIGN_NORMAL);
    transop.ld_st_truly_unaligned = 0;
    transop.rip = fetchrip;
    transop.uuid = fetch_uuid;
    transop.threadid = threadid;

    //
    // Handle loads and stores marked as unaligned in the unaligned
    // predictor predecode information. These uops are split into two
    // parts (ld.lo, ld.hi or st.lo, st.hi) and the parts are put into
    // a 4-entry buffer (unaligned_ldst_pair). Fetching continues
    // from this buffer instead of the basic block until both uops
    // are forced into the pipeline.
    //
    if unlikely (transop.unaligned) {
      if unlikely (config.event_log_enabled) eventlog.add(EVENT_FETCH_SPLIT, transop);
      split_unaligned(transop, unaligned_ldst_buf);
      assert(unaligned_ldst_buf.get(transop, synthop));
    }

    assert(transop.bbindex == current_basic_block_transop_index);
    transop.synthop = synthop;

    current_basic_block_transop_index += (unaligned_ldst_buf.empty());

    per_context_ooocore_stats_update(threadid, fetch.user_insns += transop.som);

    if unlikely (isclass(transop.opcode, OPCLASS_BARRIER)) {
      // We've hit an assist: stall the frontend until we resume or redirect
      if unlikely (config.event_log_enabled) eventlog.add(EVENT_FETCH_ASSIST, transop);
      per_context_ooocore_stats_update(threadid, fetch.stop.microcode_assist++);
      stall_frontend = 1;
    }

    per_context_ooocore_stats_update(threadid, fetch.uops++);

    Waddr predrip = 0;
    bool redirectrip = false;

    transop.rip = fetchrip;
    transop.uuid = fetch_uuid++;

    if (isbranch(transop.opcode)) {
      transop.predinfo.uuid = transop.uuid;
      transop.predinfo.bptype =
        (isclass(transop.opcode, OPCLASS_COND_BRANCH) << log2(BRANCH_HINT_COND)) |
        (isclass(transop.opcode, OPCLASS_INDIR_BRANCH) << log2(BRANCH_HINT_INDIRECT)) |
        (bit(transop.extshift, log2(BRANCH_HINT_PUSH_RAS)) << log2(BRANCH_HINT_CALL)) |
        (bit(transop.extshift, log2(BRANCH_HINT_POP_RAS)) << log2(BRANCH_HINT_RET));

      // SMP/SMT: Fill in with target thread ID (if the predictor supports this):
      transop.predinfo.ctxid = 0;
      transop.predinfo.ripafter = fetchrip + transop.bytes;
      predrip = branchpred.predict(transop.predinfo, transop.predinfo.bptype, transop.predinfo.ripafter, transop.riptaken);
      redirectrip = 1;
      per_context_ooocore_stats_update(threadid, branchpred.predictions++);
    }

    // Set up branches so mispredicts can be calculated correctly:
    if unlikely (isclass(transop.opcode, OPCLASS_COND_BRANCH)) {
      if unlikely (predrip != transop.riptaken) {
        assert(predrip == transop.ripseq);
        transop.cond = invert_cond(transop.cond);
        //
        // We need to be careful here: we already looked up the synthop for this
        // uop according to the old condition, so redo that here so we call the
        // correct code for the swapped condition.
        //
        transop.synthop = get_synthcode_for_cond_branch(transop.opcode, transop.cond, transop.size, 0);
        swap(transop.riptaken, transop.ripseq);
      }
    } else if unlikely (isclass(transop.opcode, OPCLASS_INDIR_BRANCH)) {
      transop.riptaken = predrip;
      transop.ripseq = predrip;
    }

    per_context_ooocore_stats_update(threadid, fetch.opclass[opclassof(transop.opcode)]++);

    if unlikely (config.event_log_enabled) {
      event = eventlog.add(EVENT_FETCH_OK, transop);
      event->fetch.predrip = predrip;
    }

    if likely (transop.eom) {
      fetchrip.rip += transop.bytes;
      fetchrip.update(ctx);

      if unlikely (isbranch(transop.opcode) && (transop.predinfo.bptype & (BRANCH_HINT_CALL|BRANCH_HINT_RET)))
                    branchpred.updateras(transop.predinfo, transop.predinfo.ripafter);

      if unlikely (redirectrip) {
        // follow to target, then end fetching for this cycle if predicted taken
        bool taken = (predrip != fetchrip);
        taken_branch_count += taken;
        fetchrip = predrip;
        fetchrip.update(ctx);
        if (taken) {
          fetchcount++;
          per_context_ooocore_stats_update(threadid, fetch.stop.branch_taken++);
          break;
        }
      }
    }

    fetchcount++;
  }

  per_context_ooocore_stats_update(threadid, fetch.stop.full_width += (fetchcount == FETCH_WIDTH));
  per_context_ooocore_stats_update(threadid, fetch.width[fetchcount]++);

  return true;
}

BasicBlock* ThreadContext::fetch_or_translate_basic_block(const RIPVirtPhys& rvp) {
  if likely (current_basic_block) {
    // Release our ref to the old basic block being fetched
    current_basic_block->release();
    current_basic_block = null;
  }

  BasicBlock* bb = bbcache(rvp);

  if likely (bb) {
    current_basic_block = bb;
  } else {
    current_basic_block = bbcache.translate(ctx, rvp);
    assert(current_basic_block);
    if unlikely (config.event_log_enabled) {
      OutOfOrderCoreEvent* event = core.eventlog.add(EVENT_FETCH_TRANSLATE, rvp);
      event->fetch.bb_uop_count = current_basic_block->count;
      event->threadid = threadid;
    }
  }

  //
  // Acquire a reference to the new basic block being fetched.
  // This must be done right away so future allocations do not
  // reclaim the BB while we still have a reference to it.
  //
  current_basic_block->acquire();
  current_basic_block->use(sim_cycle);

  if unlikely (!current_basic_block->synthops) synth_uops_for_bb(*current_basic_block);
  assert(current_basic_block->synthops);

  current_basic_block_transop_index = 0;
  assert(current_basic_block->rip == rvp);

  return current_basic_block;
}

//
// Allocate and Rename Stages
//

void ThreadContext::rename() {
  OutOfOrderCoreEvent* event;

  int prepcount = 0;

  while (prepcount < FRONTEND_WIDTH) {
    if unlikely (fetchq.empty()) {
      if unlikely (config.event_log_enabled) {
        if likely (!prepcount) {
          event = core.eventlog.add(EVENT_RENAME_FETCHQ_EMPTY);
          event->threadid = threadid;
        }
      }
      per_context_ooocore_stats_update(threadid, frontend.status.fetchq_empty++);
      break;
    }

    if unlikely (!ROB.remaining()) {
      if unlikely (config.event_log_enabled) {
        if likely (!prepcount) {
          event = core.eventlog.add(EVENT_RENAME_ROB_FULL);
          event->threadid = threadid;
        }
      }
      per_context_ooocore_stats_update(threadid, frontend.status.rob_full++);
      break;
    }

    FetchBufferEntry& fetchbuf = *fetchq.peek();

    int phys_reg_file = -1;

    W32 acceptable_phys_reg_files = phys_reg_files_writable_by_uop(fetchbuf);

    foreach (i, PHYS_REG_FILE_COUNT) {
      int reg_file_to_check = add_index_modulo(core.round_robin_reg_file_offset, i, PHYS_REG_FILE_COUNT);
      if likely (bit(acceptable_phys_reg_files, reg_file_to_check) && core.physregfiles[reg_file_to_check].remaining()) {
        phys_reg_file = reg_file_to_check; break;
      }
    }

    if (phys_reg_file < 0) {
      if unlikely (config.event_log_enabled) {
        if likely (!prepcount) {
          event = core.eventlog.add()->fill(EVENT_RENAME_PHYSREGS_FULL);
          event->threadid = threadid;
        }
      }
      per_context_ooocore_stats_update(threadid, frontend.status.physregs_full++);
      break;
    }

    bool ld = isload(fetchbuf.opcode);
    bool st = isstore(fetchbuf.opcode);
    bool br = isbranch(fetchbuf.opcode);

    if unlikely (ld && (loads_in_flight >= LDQ_SIZE)) {
      if unlikely (config.event_log_enabled) { if likely (!prepcount) core.eventlog.add(EVENT_RENAME_LDQ_FULL)->threadid = threadid; }
      per_context_ooocore_stats_update(threadid, frontend.status.ldq_full++);
      break;
    }

    if unlikely (st && (stores_in_flight >= STQ_SIZE)) {
      if unlikely (config.event_log_enabled) { if likely (!prepcount) core.eventlog.add(EVENT_RENAME_STQ_FULL)->threadid = threadid; }
      per_context_ooocore_stats_update(threadid, frontend.status.stq_full++);
      break;
    }

    if unlikely ((ld|st) && (!LSQ.remaining())) {
      if unlikely (config.event_log_enabled) { if likely (!prepcount) core.eventlog.add(EVENT_RENAME_MEMQ_FULL)->threadid = threadid; }
      break;
    }

    per_context_ooocore_stats_update(threadid, frontend.status.complete++);

    FetchBufferEntry& transop = *fetchq.dequeue();
    ReorderBufferEntry& rob = *ROB.alloc();
    PhysicalRegister* physreg = null;

    LoadStoreQueueEntry* lsqp = (ld|st) ? LSQ.alloc() : null;
    LoadStoreQueueEntry& lsq = *lsqp;

    rob.reset();
    rob.uop = transop;
    rob.entry_valid = 1;
    rob.cycles_left = FRONTEND_STAGES;
    rob.lsq = null;
    if unlikely (ld|st) {
      rob.lsq = &lsq;
      lsq.rob = &rob;
      lsq.store = st;
      lsq.lfence = (transop.opcode == OP_mf) & ((transop.extshift & MF_TYPE_LFENCE) != 0);
      lsq.sfence = (transop.opcode == OP_mf) & ((transop.extshift & MF_TYPE_SFENCE) != 0);
      lsq.datavalid = 0;
      lsq.addrvalid = 0;
      lsq.invalid = 0;
      loads_in_flight += (st == 0);
      stores_in_flight += (st == 1);
    }

    per_context_ooocore_stats_update(threadid, frontend.alloc.reg += (!(ld|st|br)));
    per_context_ooocore_stats_update(threadid, frontend.alloc.ldreg += ld);
    per_context_ooocore_stats_update(threadid, frontend.alloc.sfr += st);
    per_context_ooocore_stats_update(threadid, frontend.alloc.br += br);

    //
    // Rename operands:
    //

    rob.operands[RA] = specrrt[transop.ra];
    rob.operands[RB] = specrrt[transop.rb];
    rob.operands[RC] = specrrt[transop.rc];
    rob.operands[RS] = &core.physregfiles[0][PHYS_REG_NULL]; // used for loads and stores only

    // See notes above on Physical Register Recycling Complications
    foreach (i, MAX_OPERANDS) {
      rob.operands[i]->addref(rob, threadid);
      assert(rob.operands[i]->state != PHYSREG_FREE);

      if likely ((rob.operands[i]->state == PHYSREG_WAITING) |
                 (rob.operands[i]->state == PHYSREG_BYPASS) |
                 (rob.operands[i]->state == PHYSREG_WRITTEN)) {
        rob.operands[i]->rob->consumer_count = min(rob.operands[i]->rob->consumer_count + 1, 255);
      }
    }

    //
    // Select a physical register file based on desired
    // heuristics. We only consider a given register
    // file N if bit N in the acceptable_phys_reg_files
    // bitmap is set (otherwise it is off limits for
    // the type of functional unit or cluster the uop
    // must execute on).
    //
    // The phys_reg_file variable should be set to the
    // register file ID selected by the heuristics.
    //

    //
    // Default heuristics from above: phys_reg_file is already
    // set to the first acceptable physical register file ID
    // which has free registers.
    //
    rob.executable_on_cluster_mask = uop_executable_on_cluster[transop.opcode];

    // This is used if there is exactly one physical register file per cluster:
    // rob.executable_on_cluster_mask = (1 << phys_reg_file);

    // For assignment only:
    assert(bit(acceptable_phys_reg_files, phys_reg_file));

    //
    // Allocate the physical register
    //

    physreg = core.physregfiles[phys_reg_file].alloc(threadid);
    assert(physreg);
    physreg->flags = FLAG_WAIT;
    physreg->data = 0xdeadbeefdeadbeefULL;
    physreg->rob = &rob;
    physreg->archreg = rob.uop.rd;
    rob.physreg = physreg;


    //
    // Logging
    //

    if unlikely (config.event_log_enabled) {
      OutOfOrderCoreEvent* event = core.eventlog.add(EVENT_RENAME_OK, &rob);

      foreach (i, MAX_OPERANDS) rob.operands[i]->fill_operand_info(event->rename.opinfo[i]);

      if likely (archdest_can_commit[transop.rd]) {
        event->rename.oldphys = specrrt[transop.rd]->index();
        event->rename.oldzf = specrrt[REG_zf]->index();
        event->rename.oldcf = specrrt[REG_cf]->index();
        event->rename.oldof = specrrt[REG_of]->index();
      }
    }

    bool renamed_reg = 0;
    bool renamed_flags = 0;

    if likely (archdest_can_commit[transop.rd]) {
#ifdef ENABLE_TRANSIENT_VALUE_TRACKING
      PhysicalRegister* oldmapping = specrrt[transop.rd];
      if ((oldmapping->current_state_list == &physreg_waiting_list) |
          (oldmapping->current_state_list == &physreg_ready_list)) {
        oldmapping->rob->dest_renamed_before_writeback = 1;
      }

      if ((oldmapping->current_state_list == &physreg_waiting_list) |
          (oldmapping->current_state_list == &physreg_ready_list) |
          (oldmapping->current_state_list == &physreg_written_list)) {
        oldmapping->rob->no_branches_between_renamings = specrrt.renamed_in_this_basic_block[transop.rd];
      }

      specrrt.renamed_in_this_basic_block[transop.rd] = 1;
#endif

      specrrt[transop.rd]->unspecref(transop.rd, threadid);
      specrrt[transop.rd] = rob.physreg;
      rob.physreg->addspecref(transop.rd, threadid);
      renamed_reg = archdest_is_visible[transop.rd];
    }

    if unlikely (!transop.nouserflags) {
      if (transop.setflags & SETFLAG_ZF) {
        specrrt[REG_zf]->unspecref(REG_zf, threadid);
        specrrt[REG_zf] = rob.physreg;
        rob.physreg->addspecref(REG_zf, threadid);
      }
      if (transop.setflags & SETFLAG_CF) {
        specrrt[REG_cf]->unspecref(REG_cf, threadid);
        specrrt[REG_cf] = rob.physreg;
        rob.physreg->addspecref(REG_cf, threadid);
      }
      if (transop.setflags & SETFLAG_OF) {
        specrrt[REG_of]->unspecref(REG_of, threadid);
        specrrt[REG_of] = rob.physreg;
        rob.physreg->addspecref(REG_of, threadid);
      }
      renamed_flags = (transop.setflags != 0);
    }

    foreach (i, MAX_OPERANDS) {
      assert(rob.operands[i]->allocated());
    }

#ifdef ENABLE_TRANSIENT_VALUE_TRACKING
    if unlikely (br) specrrt.renamed_in_this_basic_block.reset();
#endif

    per_context_ooocore_stats_update(threadid, frontend.renamed.none += ((!renamed_reg) && (!renamed_flags)));
    per_context_ooocore_stats_update(threadid, frontend.renamed.reg += ((renamed_reg) && (!renamed_flags)));
    per_context_ooocore_stats_update(threadid, frontend.renamed.flags += ((!renamed_reg) && (renamed_flags)));
    per_context_ooocore_stats_update(threadid, frontend.renamed.reg_and_flags += ((renamed_reg) && (renamed_flags)));
    rob.changestate(rob_frontend_list);

    prepcount++;
  }

  per_context_ooocore_stats_update(threadid, frontend.width[prepcount]++);
}

void ThreadContext::frontend() {
  ReorderBufferEntry* rob;
  foreach_list_mutable(rob_frontend_list, rob, entry, nextentry) {
    if unlikely (rob->cycles_left <= 0) {
      rob->cycles_left = -1;
      rob->changestate(rob_ready_to_dispatch_list);
    } else {
      if unlikely (config.event_log_enabled) {
        OutOfOrderCoreEvent* event = core.eventlog.add(EVENT_FRONTEND, rob);
        event->frontend.cycles_left = rob->cycles_left;
      }
    }

    rob->cycles_left--;
  }
}

//
// Dispatch and Cluster Selection
//
static byte bit_indices_set_8bits[1<<8][8] = {
  {0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0},
  {1, 1, 1, 1, 1, 1, 1, 1}, {0, 1, 0, 1, 0, 1, 0, 1},
  {2, 2, 2, 2, 2, 2, 2, 2}, {0, 2, 0, 2, 0, 2, 0, 2},
  {1, 2, 1, 2, 1, 2, 1, 2}, {0, 1, 2, 0, 1, 2, 0, 1},
  {3, 3, 3, 3, 3, 3, 3, 3}, {0, 3, 0, 3, 0, 3, 0, 3},
  {1, 3, 1, 3, 1, 3, 1, 3}, {0, 1, 3, 0, 1, 3, 0, 1},
  {2, 3, 2, 3, 2, 3, 2, 3}, {0, 2, 3, 0, 2, 3, 0, 2},
  {1, 2, 3, 1, 2, 3, 1, 2}, {0, 1, 2, 3, 0, 1, 2, 3},
  {4, 4, 4, 4, 4, 4, 4, 4}, {0, 4, 0, 4, 0, 4, 0, 4},
  {1, 4, 1, 4, 1, 4, 1, 4}, {0, 1, 4, 0, 1, 4, 0, 1},
  {2, 4, 2, 4, 2, 4, 2, 4}, {0, 2, 4, 0, 2, 4, 0, 2},
  {1, 2, 4, 1, 2, 4, 1, 2}, {0, 1, 2, 4, 0, 1, 2, 4},
  {3, 4, 3, 4, 3, 4, 3, 4}, {0, 3, 4, 0, 3, 4, 0, 3},
  {1, 3, 4, 1, 3, 4, 1, 3}, {0, 1, 3, 4, 0, 1, 3, 4},
  {2, 3, 4, 2, 3, 4, 2, 3}, {0, 2, 3, 4, 0, 2, 3, 4},
  {1, 2, 3, 4, 1, 2, 3, 4}, {0, 1, 2, 3, 4, 0, 1, 2},
  {5, 5, 5, 5, 5, 5, 5, 5}, {0, 5, 0, 5, 0, 5, 0, 5},
  {1, 5, 1, 5, 1, 5, 1, 5}, {0, 1, 5, 0, 1, 5, 0, 1},
  {2, 5, 2, 5, 2, 5, 2, 5}, {0, 2, 5, 0, 2, 5, 0, 2},
  {1, 2, 5, 1, 2, 5, 1, 2}, {0, 1, 2, 5, 0, 1, 2, 5},
  {3, 5, 3, 5, 3, 5, 3, 5}, {0, 3, 5, 0, 3, 5, 0, 3},
  {1, 3, 5, 1, 3, 5, 1, 3}, {0, 1, 3, 5, 0, 1, 3, 5},
  {2, 3, 5, 2, 3, 5, 2, 3}, {0, 2, 3, 5, 0, 2, 3, 5},
  {1, 2, 3, 5, 1, 2, 3, 5}, {0, 1, 2, 3, 5, 0, 1, 2},
  {4, 5, 4, 5, 4, 5, 4, 5}, {0, 4, 5, 0, 4, 5, 0, 4},
  {1, 4, 5, 1, 4, 5, 1, 4}, {0, 1, 4, 5, 0, 1, 4, 5},
  {2, 4, 5, 2, 4, 5, 2, 4}, {0, 2, 4, 5, 0, 2, 4, 5},
  {1, 2, 4, 5, 1, 2, 4, 5}, {0, 1, 2, 4, 5, 0, 1, 2},
  {3, 4, 5, 3, 4, 5, 3, 4}, {0, 3, 4, 5, 0, 3, 4, 5},
  {1, 3, 4, 5, 1, 3, 4, 5}, {0, 1, 3, 4, 5, 0, 1, 3},
  {2, 3, 4, 5, 2, 3, 4, 5}, {0, 2, 3, 4, 5, 0, 2, 3},
  {1, 2, 3, 4, 5, 1, 2, 3}, {0, 1, 2, 3, 4, 5, 0, 1},
  {6, 6, 6, 6, 6, 6, 6, 6}, {0, 6, 0, 6, 0, 6, 0, 6},
  {1, 6, 1, 6, 1, 6, 1, 6}, {0, 1, 6, 0, 1, 6, 0, 1},
  {2, 6, 2, 6, 2, 6, 2, 6}, {0, 2, 6, 0, 2, 6, 0, 2},
  {1, 2, 6, 1, 2, 6, 1, 2}, {0, 1, 2, 6, 0, 1, 2, 6},
  {3, 6, 3, 6, 3, 6, 3, 6}, {0, 3, 6, 0, 3, 6, 0, 3},
  {1, 3, 6, 1, 3, 6, 1, 3}, {0, 1, 3, 6, 0, 1, 3, 6},
  {2, 3, 6, 2, 3, 6, 2, 3}, {0, 2, 3, 6, 0, 2, 3, 6},
  {1, 2, 3, 6, 1, 2, 3, 6}, {0, 1, 2, 3, 6, 0, 1, 2},
  {4, 6, 4, 6, 4, 6, 4, 6}, {0, 4, 6, 0, 4, 6, 0, 4},
  {1, 4, 6, 1, 4, 6, 1, 4}, {0, 1, 4, 6, 0, 1, 4, 6},
  {2, 4, 6, 2, 4, 6, 2, 4}, {0, 2, 4, 6, 0, 2, 4, 6},
  {1, 2, 4, 6, 1, 2, 4, 6}, {0, 1, 2, 4, 6, 0, 1, 2},
  {3, 4, 6, 3, 4, 6, 3, 4}, {0, 3, 4, 6, 0, 3, 4, 6},
  {1, 3, 4, 6, 1, 3, 4, 6}, {0, 1, 3, 4, 6, 0, 1, 3},
  {2, 3, 4, 6, 2, 3, 4, 6}, {0, 2, 3, 4, 6, 0, 2, 3},
  {1, 2, 3, 4, 6, 1, 2, 3}, {0, 1, 2, 3, 4, 6, 0, 1},
  {5, 6, 5, 6, 5, 6, 5, 6}, {0, 5, 6, 0, 5, 6, 0, 5},
  {1, 5, 6, 1, 5, 6, 1, 5}, {0, 1, 5, 6, 0, 1, 5, 6},
  {2, 5, 6, 2, 5, 6, 2, 5}, {0, 2, 5, 6, 0, 2, 5, 6},
  {1, 2, 5, 6, 1, 2, 5, 6}, {0, 1, 2, 5, 6, 0, 1, 2},
  {3, 5, 6, 3, 5, 6, 3, 5}, {0, 3, 5, 6, 0, 3, 5, 6},
  {1, 3, 5, 6, 1, 3, 5, 6}, {0, 1, 3, 5, 6, 0, 1, 3},
  {2, 3, 5, 6, 2, 3, 5, 6}, {0, 2, 3, 5, 6, 0, 2, 3},
  {1, 2, 3, 5, 6, 1, 2, 3}, {0, 1, 2, 3, 5, 6, 0, 1},
  {4, 5, 6, 4, 5, 6, 4, 5}, {0, 4, 5, 6, 0, 4, 5, 6},
  {1, 4, 5, 6, 1, 4, 5, 6}, {0, 1, 4, 5, 6, 0, 1, 4},
  {2, 4, 5, 6, 2, 4, 5, 6}, {0, 2, 4, 5, 6, 0, 2, 4},
  {1, 2, 4, 5, 6, 1, 2, 4}, {0, 1, 2, 4, 5, 6, 0, 1},
  {3, 4, 5, 6, 3, 4, 5, 6}, {0, 3, 4, 5, 6, 0, 3, 4},
  {1, 3, 4, 5, 6, 1, 3, 4}, {0, 1, 3, 4, 5, 6, 0, 1},
  {2, 3, 4, 5, 6, 2, 3, 4}, {0, 2, 3, 4, 5, 6, 0, 2},
  {1, 2, 3, 4, 5, 6, 1, 2}, {0, 1, 2, 3, 4, 5, 6, 0},
  {7, 7, 7, 7, 7, 7, 7, 7}, {0, 7, 0, 7, 0, 7, 0, 7},
  {1, 7, 1, 7, 1, 7, 1, 7}, {0, 1, 7, 0, 1, 7, 0, 1},
  {2, 7, 2, 7, 2, 7, 2, 7}, {0, 2, 7, 0, 2, 7, 0, 2},
  {1, 2, 7, 1, 2, 7, 1, 2}, {0, 1, 2, 7, 0, 1, 2, 7},
  {3, 7, 3, 7, 3, 7, 3, 7}, {0, 3, 7, 0, 3, 7, 0, 3},
  {1, 3, 7, 1, 3, 7, 1, 3}, {0, 1, 3, 7, 0, 1, 3, 7},
  {2, 3, 7, 2, 3, 7, 2, 3}, {0, 2, 3, 7, 0, 2, 3, 7},
  {1, 2, 3, 7, 1, 2, 3, 7}, {0, 1, 2, 3, 7, 0, 1, 2},
  {4, 7, 4, 7, 4, 7, 4, 7}, {0, 4, 7, 0, 4, 7, 0, 4},
  {1, 4, 7, 1, 4, 7, 1, 4}, {0, 1, 4, 7, 0, 1, 4, 7},
  {2, 4, 7, 2, 4, 7, 2, 4}, {0, 2, 4, 7, 0, 2, 4, 7},
  {1, 2, 4, 7, 1, 2, 4, 7}, {0, 1, 2, 4, 7, 0, 1, 2},
  {3, 4, 7, 3, 4, 7, 3, 4}, {0, 3, 4, 7, 0, 3, 4, 7},
  {1, 3, 4, 7, 1, 3, 4, 7}, {0, 1, 3, 4, 7, 0, 1, 3},
  {2, 3, 4, 7, 2, 3, 4, 7}, {0, 2, 3, 4, 7, 0, 2, 3},
  {1, 2, 3, 4, 7, 1, 2, 3}, {0, 1, 2, 3, 4, 7, 0, 1},
  {5, 7, 5, 7, 5, 7, 5, 7}, {0, 5, 7, 0, 5, 7, 0, 5},
  {1, 5, 7, 1, 5, 7, 1, 5}, {0, 1, 5, 7, 0, 1, 5, 7},
  {2, 5, 7, 2, 5, 7, 2, 5}, {0, 2, 5, 7, 0, 2, 5, 7},
  {1, 2, 5, 7, 1, 2, 5, 7}, {0, 1, 2, 5, 7, 0, 1, 2},
  {3, 5, 7, 3, 5, 7, 3, 5}, {0, 3, 5, 7, 0, 3, 5, 7},
  {1, 3, 5, 7, 1, 3, 5, 7}, {0, 1, 3, 5, 7, 0, 1, 3},
  {2, 3, 5, 7, 2, 3, 5, 7}, {0, 2, 3, 5, 7, 0, 2, 3},
  {1, 2, 3, 5, 7, 1, 2, 3}, {0, 1, 2, 3, 5, 7, 0, 1},
  {4, 5, 7, 4, 5, 7, 4, 5}, {0, 4, 5, 7, 0, 4, 5, 7},
  {1, 4, 5, 7, 1, 4, 5, 7}, {0, 1, 4, 5, 7, 0, 1, 4},
  {2, 4, 5, 7, 2, 4, 5, 7}, {0, 2, 4, 5, 7, 0, 2, 4},
  {1, 2, 4, 5, 7, 1, 2, 4}, {0, 1, 2, 4, 5, 7, 0, 1},
  {3, 4, 5, 7, 3, 4, 5, 7}, {0, 3, 4, 5, 7, 0, 3, 4},
  {1, 3, 4, 5, 7, 1, 3, 4}, {0, 1, 3, 4, 5, 7, 0, 1},
  {2, 3, 4, 5, 7, 2, 3, 4}, {0, 2, 3, 4, 5, 7, 0, 2},
  {1, 2, 3, 4, 5, 7, 1, 2}, {0, 1, 2, 3, 4, 5, 7, 0},
  {6, 7, 6, 7, 6, 7, 6, 7}, {0, 6, 7, 0, 6, 7, 0, 6},
  {1, 6, 7, 1, 6, 7, 1, 6}, {0, 1, 6, 7, 0, 1, 6, 7},
  {2, 6, 7, 2, 6, 7, 2, 6}, {0, 2, 6, 7, 0, 2, 6, 7},
  {1, 2, 6, 7, 1, 2, 6, 7}, {0, 1, 2, 6, 7, 0, 1, 2},
  {3, 6, 7, 3, 6, 7, 3, 6}, {0, 3, 6, 7, 0, 3, 6, 7},
  {1, 3, 6, 7, 1, 3, 6, 7}, {0, 1, 3, 6, 7, 0, 1, 3},
  {2, 3, 6, 7, 2, 3, 6, 7}, {0, 2, 3, 6, 7, 0, 2, 3},
  {1, 2, 3, 6, 7, 1, 2, 3}, {0, 1, 2, 3, 6, 7, 0, 1},
  {4, 6, 7, 4, 6, 7, 4, 6}, {0, 4, 6, 7, 0, 4, 6, 7},
  {1, 4, 6, 7, 1, 4, 6, 7}, {0, 1, 4, 6, 7, 0, 1, 4},
  {2, 4, 6, 7, 2, 4, 6, 7}, {0, 2, 4, 6, 7, 0, 2, 4},
  {1, 2, 4, 6, 7, 1, 2, 4}, {0, 1, 2, 4, 6, 7, 0, 1},
  {3, 4, 6, 7, 3, 4, 6, 7}, {0, 3, 4, 6, 7, 0, 3, 4},
  {1, 3, 4, 6, 7, 1, 3, 4}, {0, 1, 3, 4, 6, 7, 0, 1},
  {2, 3, 4, 6, 7, 2, 3, 4}, {0, 2, 3, 4, 6, 7, 0, 2},
  {1, 2, 3, 4, 6, 7, 1, 2}, {0, 1, 2, 3, 4, 6, 7, 0},
  {5, 6, 7, 5, 6, 7, 5, 6}, {0, 5, 6, 7, 0, 5, 6, 7},
  {1, 5, 6, 7, 1, 5, 6, 7}, {0, 1, 5, 6, 7, 0, 1, 5},
  {2, 5, 6, 7, 2, 5, 6, 7}, {0, 2, 5, 6, 7, 0, 2, 5},
  {1, 2, 5, 6, 7, 1, 2, 5}, {0, 1, 2, 5, 6, 7, 0, 1},
  {3, 5, 6, 7, 3, 5, 6, 7}, {0, 3, 5, 6, 7, 0, 3, 5},
  {1, 3, 5, 6, 7, 1, 3, 5}, {0, 1, 3, 5, 6, 7, 0, 1},
  {2, 3, 5, 6, 7, 2, 3, 5}, {0, 2, 3, 5, 6, 7, 0, 2},
  {1, 2, 3, 5, 6, 7, 1, 2}, {0, 1, 2, 3, 5, 6, 7, 0},
  {4, 5, 6, 7, 4, 5, 6, 7}, {0, 4, 5, 6, 7, 0, 4, 5},
  {1, 4, 5, 6, 7, 1, 4, 5}, {0, 1, 4, 5, 6, 7, 0, 1},
  {2, 4, 5, 6, 7, 2, 4, 5}, {0, 2, 4, 5, 6, 7, 0, 2},
  {1, 2, 4, 5, 6, 7, 1, 2}, {0, 1, 2, 4, 5, 6, 7, 0},
  {3, 4, 5, 6, 7, 3, 4, 5}, {0, 3, 4, 5, 6, 7, 0, 3},
  {1, 3, 4, 5, 6, 7, 1, 3}, {0, 1, 3, 4, 5, 6, 7, 0},
  {2, 3, 4, 5, 6, 7, 2, 3}, {0, 2, 3, 4, 5, 6, 7, 0},
  {1, 2, 3, 4, 5, 6, 7, 1}, {0, 1, 2, 3, 4, 5, 6, 7},
};

static inline int find_random_set_bit(W32 v, int randsource) {
  return bit_indices_set_8bits[v & 0xff][randsource & 0x7];
}

//
// This function locates the source operands for a uop and prepares to add the
// uop to its cluster's issue queue.
//
// If an operand is already ready at dispatch time, the issue queue associative
// array slot for that operand is marked as unused; otherwise it is marked
// as valid so the operand's ROB index can be matched when broadcast.
//
// returns: 1 iff all operands were ready at dispatch time
//
bool ReorderBufferEntry::find_sources() {
  int operands_still_needed = 0;

  issueq_tag_t uopids[MAX_OPERANDS];
  issueq_tag_t preready[MAX_OPERANDS];

  //
  // Add dependency on memory fence (if any) to help avoid unneeded replays
  //
  if unlikely (isload(uop.opcode) | isstore(uop.opcode)) {
    LoadStoreQueueEntry* fence = find_nearest_memory_fence();
    if unlikely (fence) {
      operands[RS] = fence->rob->physreg;
      operands[RS]->addref(*this, threadid);
      assert(operands[RS]->state != PHYSREG_FREE);
    }
  }

  foreach (operand, MAX_OPERANDS) {
    PhysicalRegister& source_physreg = *operands[operand];
    ReorderBufferEntry& source_rob = *source_physreg.rob;

    if likely (source_physreg.state == PHYSREG_WAITING) {
      uopids[operand] = source_rob.get_tag();
      preready[operand] = 0;
      operands_still_needed++;
    } else {
      // No need to wait for it
      uopids[operand] = 0;
      preready[operand] = 1;
    }

    if likely (source_physreg.nonnull()) {
      per_physregfile_stats_update(stats.ooocore.dispatch.source, source_physreg.rfid, [source_physreg.state]++);
    }
  }

  //
  // Stores are special: we can issue a store even if its rc operand (the value
  // to store) is not yet ready. In this case the store uop just checks for
  // exceptions, establishes an STQ entry and gets replayed as a second phase
  // store (this time around with the rc dependency required)
  //
  if unlikely (isstore(uop.opcode) && !load_store_second_phase) {
    preready[RC] = 1;
  }

  bool ok;

  issueq_operation_on_cluster_with_result(getcore(), cluster, ok, insert(get_tag(), uopids, preready));

  ThreadContext& thread = getthread();
  thread.issueq_count++;

  assert(ok);

  return operands_still_needed;
}

int ReorderBufferEntry::select_cluster() {
  OutOfOrderCoreEvent* event;

  if (MAX_CLUSTERS == 1) {
    int cluster_issue_queue_avail_count[MAX_CLUSTERS];
    getcore().sched_get_all_issueq_free_slots(cluster_issue_queue_avail_count);
    return (cluster_issue_queue_avail_count[0] > 0) ? 0 : -1;
  }

  W32 executable_on_cluster = executable_on_cluster_mask;

  int cluster_operand_tally[MAX_CLUSTERS];
  foreach (i, MAX_CLUSTERS) { cluster_operand_tally[i] = 0; }
  foreach (i, MAX_OPERANDS) {
    PhysicalRegister& r = *operands[i];
    if ((&r) && ((r.state == PHYSREG_WAITING) || (r.state == PHYSREG_BYPASS)) && (r.rob->cluster >= 0)) cluster_operand_tally[r.rob->cluster]++;
  }

  assert(executable_on_cluster);

  // If a given cluster's issue queue is full, try another cluster:
  int cluster_issue_queue_avail_count[MAX_CLUSTERS];
  W32 cluster_issue_queue_avail_mask = 0;

  getcore().sched_get_all_issueq_free_slots(cluster_issue_queue_avail_count);

  foreach (i, MAX_CLUSTERS) {
    cluster_issue_queue_avail_mask |= ((cluster_issue_queue_avail_count[i] > 0) << i);
  }

  executable_on_cluster &= cluster_issue_queue_avail_mask;

  if unlikely (config.event_log_enabled) {
    event = getcore().eventlog.add(EVENT_CLUSTER_OK, this);
    event->select_cluster.allowed_clusters = executable_on_cluster_mask;
    foreach (i, MAX_CLUSTERS) event->select_cluster.iq_avail[i] = cluster_issue_queue_avail_count[i];
  }

  if unlikely (!executable_on_cluster) {
    if unlikely (config.event_log_enabled) event->type = EVENT_CLUSTER_NO_CLUSTER;
    return -1;
  }

  int n = 0;
  int cluster = find_random_set_bit(executable_on_cluster, sim_cycle);

  foreach (i, MAX_CLUSTERS) {
    if ((cluster_operand_tally[i] > n) && bit(executable_on_cluster, i)) {
      n = cluster_operand_tally[i];
      cluster = i;
    }
  }

  per_context_ooocore_stats_update(threadid, dispatch.cluster[cluster]++);

  if unlikely (config.event_log_enabled) event->cluster = cluster;

  return cluster;
}

//
// Dispatch any uops in the rob_ready_to_dispatch_list by locating
// their source operands and adding entries to the issue queues.
//

int ThreadContext::dispatch() {
  OutOfOrderCoreEvent* event;
  ReorderBufferEntry* rob;
  foreach_list_mutable(rob_ready_to_dispatch_list, rob, entry, nextentry) {
    if unlikely (core.dispatchcount >= DISPATCH_WIDTH) break;

    // All operands start out as valid, then get put on wait queues if they are not actually ready.

    rob->cluster = rob->select_cluster();

    //
    // An available cluster could not be found. This only happens
    // when all applicable cluster issue queues are full. Since
    // we are still processing instructions in order at this point,
    // abort dispatching for this cycle.
    //
    if unlikely (rob->cluster < 0) {
      if unlikely (config.event_log_enabled) {
        event = core.eventlog.add(EVENT_DISPATCH_NO_CLUSTER, rob);
        foreach (i, MAX_OPERANDS) rob->operands[i]->fill_operand_info(event->dispatch.opinfo[i]);
      }
#if 0
#ifdef MULTI_IQ
      continue; // try the next uop to avoid deadlock on re-dispatches
#else
      break;
#endif
#endif
      break;
    }

#ifndef MULTI_IQ
    if unlikely (core.threadcount > 1) {
      // check if we can use this cluster:
      if (issueq_count >= core.reserved_iq_entries) {
        bool empty = false;
        issueq_operation_on_cluster_with_result(core, cluster, empty, shared_empty());
        if (empty) {
          // no shared entries left, stop dispatch
          break;
        } else {
          // one or more shared entries left, continue dispatch
          issueq_operation_on_cluster(core, cluster, alloc_reserved_entry());
        }
      } else {
        // still have reserved entries left, continue dispatch
      }
    }
#endif

    int operands_still_needed = rob->find_sources();

    if likely (operands_still_needed) {
      rob->changestate(rob_dispatched_list[rob->cluster]);
    } else {
      rob->changestate(rob->get_ready_to_issue_list());
    }

    if unlikely (config.event_log_enabled) {
      event = core.eventlog.add(EVENT_DISPATCH_OK, rob);
      foreach (i, MAX_OPERANDS) rob->operands[i]->fill_operand_info(event->dispatch.opinfo[i]);
    }

    core.dispatchcount++;
  }

  assert(core.dispatchcount < lengthof(stats.ooocore.dispatch.width));
  stats.ooocore.dispatch.width[core.dispatchcount]++;

  if likely (core.dispatchcount) {
    dispatch_deadlock_countdown = DISPATCH_DEADLOCK_COUNTDOWN_CYCLES;
  } else if unlikely (!rob_ready_to_dispatch_list.empty()) {
    dispatch_deadlock_countdown--;

    /* SD: Give outstanding cache and tlb-misses a chance to tickle in first and
     * commit everything that is ready to do so! */
    if ( !dispatch_deadlock_countdown &&
         (rob_cache_miss_list.count || rob_tlb_miss_list.count ||
          ( rob_ready_to_commit_queue.count && ROB.peekhead()->ready_to_commit())) )
      dispatch_deadlock_countdown = DISPATCH_DEADLOCK_COUNTDOWN_CYCLES;

    if (!dispatch_deadlock_countdown) {
      redispatch_deadlock_recovery();
      dispatch_deadlock_countdown = DISPATCH_DEADLOCK_COUNTDOWN_CYCLES;
      return -1;
    }

  }

  return core.dispatchcount;
}

//
// Issue Stage
// (see oooexec.cpp for issue stages)
//

//
// Complete Stage
//
// Process any ROB entries that just finished producing a result, forwarding
// data within the same cluster directly to the waiting instructions.
//
// Note that we use the target physical register as a temporary repository
// for the data. In a modern hardware implementation, this data would exist
// only "on the wire" such that back to back ALU operations within a cluster
// can occur using local forwarding.
//

int ThreadContext::complete(int cluster) {
  int completecount = 0;
  ReorderBufferEntry* rob;

  //
  // Check the list of issued ROBs. If a given ROB is complete (i.e., is ready
  // for writeback and forwarding), move it to rob_completed_list.
  //
  foreach_list_mutable(rob_issued_list[cluster], rob, entry, nextentry) {
    rob->cycles_left--;

    if unlikely (rob->cycles_left <= 0) {
      if unlikely (config.event_log_enabled) core.eventlog.add(EVENT_COMPLETE, rob);
      rob->changestate(rob_completed_list[cluster]);
      rob->physreg->complete();
      rob->forward_cycle = 0;
      rob->fu = 0;
      completecount++;
    }
  }

  return 0;
}

//
// Transfer Stage
//
// Process ROBs in flight between completion and global forwarding/writeback.
//

int ThreadContext::transfer(int cluster) {
  int wakeupcount = 0;
  ReorderBufferEntry* rob;
  foreach_list_mutable(rob_completed_list[cluster], rob, entry, nextentry) {
    rob->forward();
    rob->forward_cycle++;
    if unlikely (rob->forward_cycle > MAX_FORWARDING_LATENCY) {
      rob->forward_cycle = MAX_FORWARDING_LATENCY;
      rob->changestate(rob_ready_to_writeback_list[rob->cluster]);
    }
  }

  return 0;
}

//
// Writeback Stage
//
// Writeback at most WRITEBACK_WIDTH ROBs on rob_ready_to_writeback_list.
//

int ThreadContext::writeback(int cluster) {
  //  int writecount = 0;
  int wakeupcount = 0;
  ReorderBufferEntry* rob;
  foreach_list_mutable(rob_ready_to_writeback_list[cluster], rob, entry, nextentry) {
    if unlikely (core.writecount >= WRITEBACK_WIDTH) break;

    //
    // Gather statistics
    //
    bool transient = 0;

#ifdef ENABLE_TRANSIENT_VALUE_TRACKING
    if likely (!isclass(rob->uop.opcode, OPCLASS_STORE|OPCLASS_BRANCH)) {
      transient =
        (rob->dest_renamed_before_writeback) &&
        (rob->consumer_count <= 1) &&
        (rob->physreg->all_consumers_sourced_from_bypass) &&
        (rob->no_branches_between_renamings);

      writeback_transient += transient;
      writeback_persistent += (!transient);
    }

    rob->transient = transient;
#endif

    if likely (!isclass(rob->uop.opcode, OPCLASS_STORE|OPCLASS_BRANCH)) {
      if unlikely (config.event_log_enabled) {
        OutOfOrderCoreEvent* event = core.eventlog.add(EVENT_WRITEBACK, rob);
        event->writeback.data = rob->physreg->data;
        event->writeback.flags = rob->physreg->flags;
        event->writeback.consumer_count = rob->consumer_count;
        event->writeback.transient = transient;
        event->writeback.all_consumers_sourced_from_bypass = rob->physreg->all_consumers_sourced_from_bypass;
        event->writeback.no_branches_between_renamings = rob->no_branches_between_renamings;
        event->writeback.dest_renamed_before_writeback = rob->dest_renamed_before_writeback;
      }
    }

    //
    // Catch corner case where dependent uop was scheduled
    // while producer waited in ready_to_writeback state:
    //
    wakeupcount += rob->forward();

    core.writecount++;

    //
    // For simulation purposes, final value is already in rob->physreg,
    // so we don't need to actually write anything back here.
    //

    per_context_ooocore_stats_update(threadid, writeback.writebacks[rob->physreg->rfid]++);
    rob->physreg->writeback();
    rob->cycles_left = -1;
    rob->changestate(rob_ready_to_commit_queue);
  }

  per_cluster_stats_update(stats.ooocore.writeback.width, cluster, [core.writecount]++);

  return core.writecount;
}

//
// Commit Stage
//
// Commit at most COMMIT_WIDTH ready to commit instructions from ROB queue,
// and commits any stores by writing to the L1 cache with write through.
//
// Returns:
//    -1 if we are supposed to abort the simulation
//  >= 0 for the number of instructions actually committed
//
// Physical Register Recycling Complications
//
// Consider the following scenario:
//
// - uop U3 is renamed and found to depend on physical register R from an earlier uop U1.
// - U1 commits to architectural register A and moves R to the arch state
// - U2, which updates the same architectural register A as U1, also commits. Since the
//   mapping of A is being logically overwritten by U2, U1's physical register R is freed.
// - U3 finally issues, but finds that operand physical register R for U1 no longer exists.
//
// Additionally, in x86 processors the flags attached to a given physical register may
// be referenced by three additional rename table entries (for ZAPS, CF, OF) so simply
// freeing the old physical register mapping when the RRT is updated doesn't work.
//
// For these reasons, we need to prevent U2's register from being freed if it is still
// referenced by anything still in the pipeline; the normal reorder buffer mechanism
// cannot always handle this situation in a very long pipeline.
//
// The solution is to give each physical register a reference counter. As each uop operand
// is renamed, the counter for the corresponding physical register is incremented. As each
// uop commits, the counter for each of its operands is decremented, but the counter for
// the target physical register itself is incremented before that register is moved to
// the arch state during commitment (since the committed state now owns that register).
//
// As we update the committed RRT during the commit stage, the old register R mapped
// to the destination architectural register A of the uop being committed is examined.
// The register R is only moved to the free state iff its reference counter is zero.
// Otherwise, it is moved to the pendingfree state. The hardware examines all counters
// every cycle and moves physical registers to the free state only when their counters
// become zero and they are in the pendingfree state.
//
// An additional complication arises for x86 since we maintain three separate rename
// table entries for the ZAPS, CF, OF flags in addition to the register rename table
// entry. Therefore, each speculative RRT and commit RRT entry adds to the refcount.
//
// Hardware Implementation
//
// The hardware implementation of this scheme is straightforward and low complexity.
// The counters can have a very small number of bits since it is very unlikely a given
// physical register would be referenced by all 100+ uops in the ROB; 3 bits should be
// enough to handle the typical maximum of < 8 uops sharing a given operand. Counter
// overflows can simply stall renaming or flush the pipeline since they are so rare.
//
// The counter table can be updated in bulk each cycle by adding/subtracting the
// appropriate sum or just adding zero if the corresponding register wasn't used.
// Since there are several stages between renaming and commit, the same counter is never
// both incremented and decremented in the same cycle, so race conditions are not an
// issue.
//
// In real processors, the Pentium 4 uses a scheme similar to this one but uses bit
// vectors instead. For smaller physical register files, this may be a better solution.
// Each physical register has a bit vector with one bit per ROB entry. If a given
// physical register P is still used by ROB entry E in the pipeline, P's bit vector
// bit R is set. Register P cannot be freed until all bits in its vector are zero.
//

int ThreadContext::commit() {
  //
  // Recycle physical registers for which all references have been dropped
  //
  foreach (rfid, PHYS_REG_FILE_COUNT) {
    StateList& statelist = core.physregfiles[rfid].states[PHYSREG_PENDINGFREE];
    PhysicalRegister* physreg;
    foreach_list_mutable(statelist, physreg, entry, nextentry) {
      if unlikely (!physreg->referenced()) {
        if unlikely (config.event_log_enabled) {
          OutOfOrderCoreEvent* event = core.eventlog.add(EVENT_RECLAIM_PHYSREG);
          event->physreg = physreg->index();
          event->threadid = physreg->threadid;
        }
        physreg->free();
        stats.ooocore.commit.free_regs_recycled++;
      }
    }
  }

  //
  // Commit ROB entries *in program order*, stopping at the first ROB that is
  // not ready to commit or has an exception.
  //
  int rc = COMMIT_RESULT_OK;

  foreach_forward(ROB, i) {
    ReorderBufferEntry& rob = ROB[i];

    if unlikely (core.commitcount >= COMMIT_WIDTH) break;
    rc = rob.commit();
    if likely (rc == COMMIT_RESULT_OK) {
      core.commitcount++;
      last_commit_at_cycle = sim_cycle;
    } else {
      break;
    }
  }

  assert(core.commitcount < lengthof(stats.ooocore.commit.width));
  stats.ooocore.commit.width[core.commitcount]++;

  return rc;
}

void ThreadContext::flush_mem_lock_release_list(int start) {
  for (int i = start; i < queued_mem_lock_release_count; i++) {
    W64 lockaddr = queued_mem_lock_release_list[i];

    MemoryInterlockEntry* lock = interlocks.probe(lockaddr);

    if (!lock) {
      logfile << "ERROR: thread ", ctx.vcpuid, ": attempted to release queued lock #", i, " for physaddr ", (void*)lockaddr, ": lock was ", lock, endl;
      assert(false);
    }

    if (lock->vcpuid != ctx.vcpuid) {
      logfile << "ERROR: thread ", ctx.vcpuid, ": attempted to release queued lock #", i, " for physaddr ", (void*)lockaddr, ": lock vcpuid was ", lock->vcpuid, endl;
      assert(false);
    }

    if unlikely (config.event_log_enabled) {
      OutOfOrderCoreEvent* event = core.eventlog.add(EVENT_RELEASE_MEM_LOCK);
      event->threadid = ctx.vcpuid;
      event->loadstore.sfr.physaddr = lockaddr >> 3;
    }

    interlocks.invalidate(lockaddr);
  }

  queued_mem_lock_release_count = start;
}

#ifdef PTLSIM_HYPERVISOR
//
// For debugging purposes only
//
#if 0
bool rip_is_in_spinlock(W64 rip) {
  bool inside_spinlock_now =
    inrange(rip, 0xffffffff803d3fbcULL, 0xffffffff803d404fULL) | // .text.lock.spinlock
    inrange(rip, 0xffffffff803d2c82ULL, 0xffffffff803d2ccfULL) | // .text.lock.mutex
    inrange(rip, 0xffffffff80135f50ULL, 0xffffffff80135f8fULL) | // current_fs_time
    inrange(rip, 0xffffffff801499b6ULL, 0xffffffff80149a22ULL);  // hrtimer_run_queues

  return inside_spinlock_now;
}
#endif
#endif

int ReorderBufferEntry::commit() {
  OutOfOrderCore& core = getcore();
  ThreadContext& thread = getthread();
  Context& ctx = thread.ctx;
  bool all_ready_to_commit = true;
  bool macro_op_has_exceptions = false;

  //
  // Create an event log entry
  //
  OutOfOrderCoreEvent* event;

  //
  // If the uop currently at the head of the ROB is a memory fence,
  // "issue" it at commit time, to let dependent uops (in the same
  // macro-op or future macro-ops, assuming no intervening fences)
  // wake up and complete.
  //
  // Additionally, if the fence is marked as non-internal (i.e.
  // it's the last memory-related uop in the macro-op), release
  // all pending locks queued by ld.acq uops.
  //

  //
  // Check the head of the ROB to see if it's a memory fence.
  // If so, it's now safe to "wake up" the mf uop at commit
  // time (rather than issue time), thereby allowing loads
  // and/or stores after the fence to successfully issue.
  //
  // Notice that this happens in program order even if some
  // uops in the macro-op have not yet completed. This is
  // required to avoid deadlock in the case where the mf
  // uop is the first uop in the macro-op. In this case,
  // its P (internal) bit must be set.
  //
  // Note that in order to have a flush, this must be the
  // fence immediately after an locked RMW instruction,
  // as the lock is just added to the flush list at the
  // commit of the load (the R part), which will definitely
  // happen after the commit of the preceeding fence.
  //

  if unlikely ((uop.opcode == OP_mf) && ready_to_commit() && (!load_store_second_phase)) {
    fencewakeup();
    thread.flush_mem_lock_release_list();
  }

  //
  // Each x86 instruction may be composed of multiple uops; none of the uops
  // may commit until ALL uops are ready to commit (either correctly or
  // if one or more uops have exceptions).
  //
  // This is accomplished by checking if the uop at the head of the ROB (next
  // to commit) has its SOM (start of macro-op) bit set. If so, the ROB is
  // scanned forwards from the SOM uop to the EOM (end of macro-op) uop. If
  // all uops in this range are ready to commit and are exception-free, the
  // SOM uop allowed to commit.
  //
  // Any exceptions in the macro-op uop range immediately signals an exception
  // to the user code, and no part of the uop is committed. In any case,
  // asynchronous interrupts are only taken after committing or excepting the
  // EOM uop in a macro-op.
  //

  bool found_eom = 0;

  foreach_forward_from(thread.ROB, this, j) {
    ReorderBufferEntry& subrob = thread.ROB[j];

    found_eom |= subrob.uop.eom;

    if unlikely (!subrob.ready_to_commit()) {
      all_ready_to_commit = false;
    }

#ifdef PTLSIM_HYPERVISOR
    bool force_fp_unavailable = (subrob.uop.is_sse|subrob.uop.is_x87) && (ctx.cr0.ts | (subrob.uop.is_x87 & ctx.cr0.em));
#else
    bool force_fp_unavailable = (subrob.uop.is_sse&ctx.no_sse)|(subrob.uop.is_x87&ctx.no_x87);
#endif
    if unlikely (force_fp_unavailable) {
      subrob.physreg->data = EXCEPTION_FloatingPointNotAvailable;
      subrob.physreg->flags = FLAG_INV;
      if unlikely (subrob.lsq) subrob.lsq->invalid = 1;
    }

    if unlikely (subrob.physreg->flags & FLAG_INV) {
      //
      // The exception is definitely going to happen, since the
      // excepting instruction is at the head of the ROB. However,
      // we don't know which uop within the instruction actually
      // had the problem, e.g. if it's a load-alu-store insn, the
      // load is OK but the store has PageFaultOnWrite. We take
      // the first exception in uop order.
      //
      ctx.exception = LO32(subrob.physreg->data);
      ctx.error_code = HI32(subrob.physreg->data);

      // Capture the faulting virtual address for page faults
      if ((ctx.exception == EXCEPTION_PageFaultOnRead) |
          (ctx.exception == EXCEPTION_PageFaultOnWrite)) {
        ctx.cr2 = subrob.origvirt;
      }

      if unlikely (config.event_log_enabled) core.eventlog.add_commit(EVENT_COMMIT_EXCEPTION_DETECTED, &subrob);

      macro_op_has_exceptions = true;
      all_ready_to_commit = true;
      found_eom = true;
      break;
    }

    if likely (subrob.uop.eom) break;
  }

  //
  // Protect against the extremely rare case where only one x86
  // instruction is in flight and its EOM uop has not even made
  // it into the ROB by the time the first uop is ready to commit.
  //

  all_ready_to_commit &= found_eom;

  if unlikely (!all_ready_to_commit) {
    per_context_ooocore_stats_update(threadid, commit.result.none++);
    return COMMIT_RESULT_NONE;
  }

  /*
   * SMC: check if any previous instruction has dirtied page(s) on which the next macroop
   * to execute resides, if so we do not execute it but invalidate all bb caches immediately
   * because the store has happened before the macroop started execution and thus needs to be retranslated.
   */
  const bool page_crossing = ((lowbits(uop.rip.rip, 12) + (uop.bytes-1)) >> 12);

  if unlikely (uop.som && (smc_isdirty(uop.rip.mfnlo) | (page_crossing && smc_isdirty(uop.rip.mfnhi)))) {
    /* If we're at the start of a macroop and the macroop has already been invalidated
     * aport execution immediately, to make effects visible
     */
    printf("TEST: Speculative execution shoot down due to SOM invalidated before execution!\n");
    if unlikely (config.event_log_enabled) {
      core.eventlog.add_commit(EVENT_COMMIT_SMC_DETECTED, this);
    }

    thread.smc_invalidate_pending = 1;
    thread.smc_invalidate_rvp = uop.rip;

    return COMMIT_RESULT_SMC;
  }

  PhysicalRegister* oldphysreg = thread.commitrrt[uop.rd];

  const bool ld = isload(uop.opcode);
  const bool st = isstore(uop.opcode);
  const bool br = isbranch(uop.opcode);

  per_context_ooocore_stats_update(threadid, commit.opclass[opclassof(uop.opcode)]++);

  if unlikely (macro_op_has_exceptions) {
    if unlikely (config.event_log_enabled) event = core.eventlog.add_commit(EVENT_COMMIT_EXCEPTION_ACKNOWLEDGED, this);

    // See notes in handle_exception():
    if likely (isclass(uop.opcode, OPCLASS_CHECK) & (ctx.exception == EXCEPTION_SkipBlock)) {
      thread.chk_recovery_rip = ctx.commitarf[REG_rip] + uop.bytes;
      if unlikely (config.event_log_enabled) event->type = EVENT_COMMIT_SKIPBLOCK;
      per_context_ooocore_stats_update(threadid, commit.result.skipblock++);
    } else {
      per_context_ooocore_stats_update(threadid, commit.result.exception++);
    }

    return COMMIT_RESULT_EXCEPTION;
  }

  //
  // Check for self modifying code (SMC) by checking if any previous
  // instruction has dirtied the page(s) on which the current instruction
  // resides. The SMC check is done first since it's perfectly legal for a
  // store to overwrite its own instruction bytes, but this update only
  // becomes visible after the store has committed.
  //
  if unlikely (uop.eom && (smc_isdirty(uop.rip.mfnlo) | (page_crossing && smc_isdirty(uop.rip.mfnhi)))) {
    if unlikely (config.event_log_enabled) core.eventlog.add_commit(EVENT_COMMIT_SMC_DETECTED, this);
    //
    // Invalidate the pages only after the pipeline is flushed: we may still
    // hold refs to the affected basic blocks in the pipeline. Queue the
    // updates for later.
    //
    thread.smc_invalidate_pending = 1;
    thread.smc_invalidate_rvp = uop.rip;

    per_context_ooocore_stats_update(threadid, commit.result.smc++);
    // Let this uop commit to prevent livelock!
  }

  assert(ready_to_commit());

  //
  // If this is a store uop, we must check for an outstanding lock
  // on the target address held by some other thread (local locks
  // are ignored), and if a lock is found, we block commit until
  // the lock is released.
  //
  // Without this check, we could have the following scenario:
  // - Thread 0 issues non-locked store. It checks for locks at
  //   issue time, but none are found, so it proceeds
  // - Thread 1 issues a locked load, modify and locked store
  // - Thread 0 non-locked store commits
  // - Thread 1 locked store commits
  //
  // Notice that thread 0's store is lost, since it's overwritten
  // by thread 1's store. If thread 0 is doing a store to release
  // a spinlock (which is perfectly safe without the LOCK prefix),
  // but thread 1's store attempts to acquire the spinlock, the
  // release will never appear, and thread 1 will spin forever.
  //

  if unlikely (uop.opcode == OP_st || uop.opcode == OP_st_a16) {
    W64 lockaddr = lsq->physaddr << 3;
    MemoryInterlockEntry* lock = interlocks.probe(lockaddr);

    if unlikely (lock && (lock->vcpuid != thread.ctx.vcpuid)) {
      if unlikely (config.event_log_enabled) core.eventlog.add_commit(EVENT_COMMIT_MEM_LOCKED, this);

      per_context_ooocore_stats_update(threadid, commit.result.memlocked++);
      return COMMIT_RESULT_NONE;
    }
  }

  //
  // Update architectural state:
  // (this is the point of no return)
  //

  //
  // Once we're satisfied that all uops in the current x86 instruction
  // are complete and can commit, enqueue a memory lock release for
  // any ld.acq uops that have not already released their lock.
  //
  // This actually unlocks the chunk(s) ONLY after ALL uops in the
  // current macro-op have committed. This is required since the
  // other threads know nothing about remote store queues: unless
  // the value is committed to the cache (where cache coherency can
  // control its use), other loads in other threads could slip in
  // and get incorrect values.
  //

  release_mem_lock();

#ifdef PTLSIM_HYPERVISOR
  //
  // For debugging purposes, check the list of address ranges specified
  // with the -deadlock-debug-range 0xAA-0xBB,0xCC-0xDD,... option. If
  // the commit rip has been within one of these ranges on this vcpu for
  // more than (value of -deadlock-debug-limit) commits, dump all state,
  // dump the event log and abort the simulation.
  //
#if 0
  {
    W64 rip = uop.rip.rip;
    bool inside_spinlock_now = rip_is_in_spinlock(rip);
    bool thread0_stuck_in_spinlock = rip_is_in_spinlock(core.thread[0]->ctx.commitarf[REG_rip]);
    bool thread1_stuck_in_spinlock = rip_is_in_spinlock(core.thread[1]->ctx.commitarf[REG_rip]);

    if unlikely (inside_spinlock_now)
                  thread.consecutive_commits_inside_spinlock++;
    else thread.consecutive_commits_inside_spinlock = 0;

    if (thread.consecutive_commits_inside_spinlock >= 512) {
      logfile << "WARNING: at cycle ", sim_cycle, ": vcpu ", thread.ctx.vcpuid, " potentially deadlocked inside spinlock (commit rip ", (void*)ctx.commitarf[REG_rip],
        ", count ", thread.consecutive_commits_inside_spinlock, ", int mask ", sshinfo.vcpu_info[thread.ctx.vcpuid].evtchn_upcall_mask, endl, flush;
      logfile << "Thread 0 rip ", (void*)core.thread[0]->ctx.commitarf[REG_rip], endl;
      logfile << "Thread 1 rip ", (void*)core.thread[1]->ctx.commitarf[REG_rip], endl;

      thread.consecutive_commits_inside_spinlock = 0;

      if (thread0_stuck_in_spinlock && thread1_stuck_in_spinlock) {
        logfile << "Both threads stuck in spinlock", endl;
        //core.machine.dump_state(logfile); // This is implied by assert().
        assert(false);
      }
    }
  }
#endif
#endif

  if (st) assert(lsq->addrvalid && lsq->datavalid);

  W64 result = physreg->data;

  assert(ctx.commitarf[REG_rip] == uop.rip);

  if likely (uop.som) assert(ctx.commitarf[REG_rip] == uop.rip);

  //
  // The commit of all uops in the x86 macro-op is guaranteed to happen after this point
  //
  if unlikely (config.event_log_enabled) event = core.eventlog.add_commit(EVENT_COMMIT_OK, this);

  if unlikely (config.event_log_enabled) {
    if unlikely ((uop.rip.rip == config.log_backwards_from_trigger_rip) && (uop.som)) {
      logfile << "Hit trigger rip ", (void*)(Waddr)config.log_backwards_from_trigger_rip, "; printing event ring buffer:", endl, flush;
      core.eventlog.print(logfile);
      logfile << "End of triggered event dump", endl, flush;
    }
  }

  if likely (archdest_can_commit[uop.rd]) {
    thread.commitrrt[uop.rd]->uncommitref(uop.rd, thread.threadid);
    thread.commitrrt[uop.rd] = physreg;
    thread.commitrrt[uop.rd]->addcommitref(uop.rd, thread.threadid);

    if likely (uop.rd < ARCHREG_COUNT) ctx.commitarf[uop.rd] = physreg->data;

    physreg->rob = null;
  }

  if likely (uop.eom) {
    if unlikely (uop.rd == REG_rip) {
      assert(isbranch(uop.opcode));
      ctx.commitarf[REG_rip] = physreg->data;
    } else {
      assert(!isbranch(uop.opcode));
      ctx.commitarf[REG_rip] += uop.bytes;
    }
    if unlikely (config.event_log_enabled) event->commit.target_rip = ctx.commitarf[REG_rip];
  }

  if likely ((!ld) & (!st) & (!uop.nouserflags)) {
    W64 flagmask = setflags_to_x86_flags[uop.setflags];
    ctx.commitarf[REG_flags] = (ctx.commitarf[REG_flags] & ~flagmask) | (physreg->flags & flagmask);

    per_context_ooocore_stats_update(threadid, commit.setflags.no += (uop.setflags == 0));
    per_context_ooocore_stats_update(threadid, commit.setflags.yes += (uop.setflags != 0));

    if unlikely (config.event_log_enabled) event->commit.state.reg.rdflags = ctx.commitarf[REG_flags];

    if likely (uop.setflags & SETFLAG_ZF) {
      thread.commitrrt[REG_zf]->uncommitref(REG_zf, thread.threadid);
      thread.commitrrt[REG_zf] = physreg;
      thread.commitrrt[REG_zf]->addcommitref(REG_zf, thread.threadid);
    }
    if likely (uop.setflags & SETFLAG_CF) {
      thread.commitrrt[REG_cf]->uncommitref(REG_cf, thread.threadid);
      thread.commitrrt[REG_cf] = physreg;
      thread.commitrrt[REG_cf]->addcommitref(REG_cf, thread.threadid);
    }
    if likely (uop.setflags & SETFLAG_OF) {
      thread.commitrrt[REG_of]->uncommitref(REG_of, thread.threadid);
      thread.commitrrt[REG_of] = physreg;
      thread.commitrrt[REG_of]->addcommitref(REG_of, thread.threadid);
    }
  }

  if unlikely (uop.opcode == OP_st || uop.opcode == OP_st_a16) {
    /* lsq->physaddr is the fully computed memory pointer not the
     * actual physical address like the name would make one think,
     * For SMC detection we need the physical address that has been passed
     * along in the appropiate format for smc_setdirty
     */
    smc_setdirty(lsq->smc_mfn);

    if (lsq->bytemask) assert(core.caches.commitstore(*lsq, thread.threadid) == 0);
  }

  if unlikely (pteupdate) {
    ctx.update_pte_acc_dirty(virtpage, pteupdate);
  }

  //
  // Free physical registers, load/store queue entries, etc.
  //
  if unlikely (ld|st) {
    thread.loads_in_flight -= (lsq->store == 0);
    thread.stores_in_flight -= (lsq->store == 1);
    lsq->reset();
    thread.LSQ.commit(lsq);
    core.set_unaligned_hint(uop.rip, uop.ld_st_truly_unaligned);
  }

  assert(archdest_can_commit[uop.rd]);
  assert(oldphysreg->state == PHYSREG_ARCH);

  if unlikely (config.event_log_enabled) event->commit.oldphysreg = -1;
  if likely (oldphysreg->nonnull()) {
    if unlikely (config.event_log_enabled) {
      event->commit.oldphysreg = oldphysreg->index();
      event->commit.oldphysreg_refcount = oldphysreg->refcount;
    }

    if unlikely (oldphysreg->referenced()) {
      oldphysreg->changestate(PHYSREG_PENDINGFREE);
      stats.ooocore.commit.freereg.pending++;
    } else  {
      oldphysreg->free();
      stats.ooocore.commit.freereg.free++;
    }
  }

  if likely (!(br|st)) {
    int k = clipto((int)consumer_count, 0, (int)lengthof(stats.ooocore.total.frontend.consumer_count) - 1);
    per_context_ooocore_stats_update(threadid, frontend.consumer_count[k]++);
  }

  physreg->changestate(PHYSREG_ARCH);

  //
  // Unlock operand physregs since we no longer need to worry about speculation recovery
  // Technically this can be done after the issue queue entry is released, but we do it
  // here for simplicity.
  //
  foreach (i, MAX_OPERANDS) {
    operands[i]->unref(*this, thread.threadid);
  }

  //
  // Update branch prediction
  //
  if unlikely (isclass(uop.opcode, OPCLASS_BRANCH)) {
    assert(uop.eom);
    //
    // NOTE: Technically the "branch address" refers to the rip of the *next*
    // x86 instruction after the branch; we use this consistently since x86
    // instructions vary in length and we cannot easily calculate the next
    // instruction in sequence from within the branch predictor logic.
    //
    W64 end_of_branch_x86_insn = uop.rip + uop.bytes;
    bool taken = (ctx.commitarf[REG_rip] != end_of_branch_x86_insn);
    bool predtaken = (uop.riptaken != end_of_branch_x86_insn);

    if unlikely (config.event_log_enabled) {
      event->commit.taken = taken;
      event->commit.predtaken = predtaken;
    }

    thread.branchpred.update(uop.predinfo, end_of_branch_x86_insn, ctx.commitarf[REG_rip]);
    per_context_ooocore_stats_update(threadid, branchpred.updates++);
  }

  if likely (uop.eom) {
    total_user_insns_committed++;
    per_context_ooocore_stats_update(threadid, commit.insns++);
    thread.total_insns_committed++;

    stats.summary.insns++;
  }

  stats.summary.uops++;
  total_uops_committed++;
  per_context_ooocore_stats_update(threadid, commit.uops++);
  thread.total_uops_committed++;

  bool uop_is_eom = uop.eom;
  bool uop_is_barrier = isclass(uop.opcode, OPCLASS_BARRIER);
  bool uop_is_fence = (uop.opcode == OP_mf);
  changestate(thread.rob_free_list);
  reset();
  thread.ROB.commit(*this);

  if unlikely (thread.smc_invalidate_pending)
    return COMMIT_RESULT_SMC;

  if unlikely (uop_is_barrier) {
    if unlikely (config.event_log_enabled) core.eventlog.add(EVENT_COMMIT_ASSIST, RIPVirtPhys(ctx.commitarf[REG_rip]))->threadid = thread.threadid;
    per_context_ooocore_stats_update(threadid, commit.result.barrier++);
    return COMMIT_RESULT_BARRIER;
  }

  if unlikely (uop_is_eom & thread.stop_at_next_eom) {
    logfile << "[vcpu ", thread.ctx.vcpuid, "] Stopping at cycle ", sim_cycle, " (", total_user_insns_committed, " commits)", endl;
    return COMMIT_RESULT_STOP;
  }

  if unlikely (uop_is_eom & thread.handle_interrupt_at_next_eom) {
    thread.handle_interrupt_at_next_eom = 0;
    return COMMIT_RESULT_INTERRUPT;
  }

  per_context_ooocore_stats_update(threadid, commit.result.ok++);
  return COMMIT_RESULT_OK;
}

namespace OutOfOrderModel {
  const byte archdest_is_visible[TRANSREG_COUNT] = {
    // Integer registers
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    // SSE registers, low 64 bits
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    // SSE registers, high 64 bits
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    // x87 FP / MMX / special
    1, 1, 1, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    // The following are ONLY used during the translation and renaming process:
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
  };

  const byte archdest_can_commit[TRANSREG_COUNT] = {
    // Integer registers
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    // SSE registers, low 64 bits
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    // SSE registers, high 64 bits
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    // x87 FP / MMX / special
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 0,
    // The following are ONLY used during the translation and renaming process:
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
  };
};
