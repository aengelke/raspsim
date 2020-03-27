// -*- c++ -*-
//
// PTLsim: Cycle Accurate x86-64 Simulator
// Generic interface required by simulator
//
// Copyright 2020-2020 Alexis Engelke <engelke@in.tum.de>
//

#ifndef _PTLSIM_API_H_
#define _PTLSIM_API_H_

#include <globals.h>
#include <ptlhwdef.h>

// From globals.h
// W64 get_core_freq_hz();

// From ptlhwdef.h
// void Context::propagate_x86_exception(byte exception, W32 errorcode, Waddr virtaddr);
// int Context::copy_from_user(void* target, Waddr addr, int bytes, PageFaultErrorCode& pfec, Waddr& faultaddr, bool forexec, Level1PTE& ptelo, Level1PTE& ptehi);
// int Context::copy_to_user(Waddr target, void* source, int bytes, PageFaultErrorCode& pfec, Waddr& faultaddr);
// int Context::write_segreg(unsigned int segid, W16 selector);
// Waddr Context::check_and_translate(Waddr virtaddr, int sizeshift, bool store, bool internal, int& exception, PageFaultErrorCode& pfec, PTEUpdate& pteupdate, Level1PTE& pteused);
// RIPVirtPhys& RIPVirtPhys::update(Context& ctx, int bytes);

// From ptlsim.h
// bool check_for_async_sim_break();
// void print_sysinfo(ostream& os);
// int inject_events();

// void assist_ptlcall(Context& ctx);

extern bool asp_check_exec(void* addr);

extern bool smc_isdirty(Waddr mfn);
extern void smc_setdirty(Waddr mfn);
extern void smc_cleardirty(Waddr mfn);

extern Context& contextof(int vcpu);

#define contextcount (1)
#define MAX_CONTEXTS 1

static const Waddr INVALID_PHYSADDR = 0;

extern W64 loadphys(Waddr addr);
extern W64 storemask(Waddr addr, W64 data, byte bytemask);

//
// System calls
//
enum { SYSCALL_SEMANTICS_INT80, SYSCALL_SEMANTICS_SYSCALL, SYSCALL_SEMANTICS_SYSENTER };

void handle_syscall_32bit(int semantics);

// x86-64 mode has only one type of system call (the syscall instruction)
void handle_syscall_64bit();

//
// This is set if we are running within the target process address space;
// it controls the way PTLsim behaves on startup. If not set, PTLsim is
// acting as a regular program, typically to inject itself into another
// process (which will then have inside_ptlsim set) or to print help info.
//
// TODO(AE): remove requirement from mm.cpp
extern bool inside_ptlsim;

// Used to determine whether to exit emulation.
extern bool requested_switch_to_native;

#endif // _PTLSIM_API_H_
