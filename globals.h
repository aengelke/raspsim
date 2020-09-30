// -*- c++ -*-
//
// Copyright 1997-2008 Matt T. Yourst <yourst@yourst.com>
//
// This program is free software; it is licensed under the
// GNU General Public License, Version 2.
//

#ifndef _GLOBALS_H_
#define _GLOBALS_H_

#include <assert.h>
#include <cmath>
#include <cstddef>
extern "C" {
#include <sys/ptrace.h>
}

typedef __SIZE_TYPE__ size_t;
typedef unsigned long long W64;
typedef signed long long W64s;
typedef unsigned int W32;
typedef signed int W32s;
typedef unsigned short W16;
typedef signed short W16s;
typedef unsigned char byte;
typedef unsigned char W8;
typedef signed char W8s;
#define null NULL

#ifdef __x86_64__
typedef W64 Waddr;
#else
typedef W32 Waddr;
#endif

#ifdef __cplusplus

#include <math.h>
#include <float.h>

#define __stringify_1(x) #x
#define stringify(x) __stringify_1(x)

#define alignto(x) __attribute__ ((aligned (x)))
#define insection(x) __attribute__ ((section (x)))
#define packedstruct __attribute__ ((packed))
#define noinline __attribute__((noinline))

#define unlikely(x) (__builtin_expect(!!(x), 0))
#define likely(x) (__builtin_expect(!!(x), 1))
#define isconst(x) (__builtin_constant_p(x))
#define getcaller() (__builtin_return_address(0))
#define asmlinkage extern "C"

//
// Asserts
//
#if defined __cplusplus
#  define __ASSERT_VOID_CAST static_cast<void>
#else
#  define __ASSERT_VOID_CAST (void)
#endif

asmlinkage void assert_fail(const char *__assertion, const char *__file, unsigned int __line, const char *__function) __attribute__ ((__noreturn__));

// For embedded debugging use only:
static inline void assert_fail_trap(const char *__assertion, const char *__file, unsigned int __line, const char *__function) {
  asm("ud2a" : : "a" (__assertion), "b" (__file), "c" (__line), "d" (__function));
}

#define __CONCAT(x,y)	x ## y
#define __STRING(x)	#x

#define nan NAN
#define inf INFINITY

template <typename T> struct limits { static const T min = 0; static const T max = 0; };
#define MakeLimits(T, __min, __max) template <> struct limits<T> { static const T min = (__min); static const T max = (__max); };
MakeLimits(W8, 0, 0xff);
MakeLimits(W16, 0, 0xffff);
MakeLimits(W32, 0, 0xffffffff);
MakeLimits(W64, 0, 0xffffffffffffffffULL);
MakeLimits(W8s, 0x80, 0x7f);
MakeLimits(W16s, 0x8000, 0x7fff);
MakeLimits(W32s, 0x80000000, 0x7fffffff);
MakeLimits(W64s, 0x8000000000000000LL, 0x7fffffffffffffffLL);
#ifdef __x86_64__
MakeLimits(signed long, 0x8000000000000000LL, 0x7fffffffffffffffLL);
MakeLimits(unsigned long, 0x0000000000000000LL, 0xffffffffffffffffLL);
#else
MakeLimits(signed long, 0x80000000, 0x7fffffff);
MakeLimits(unsigned long, 0, 0xffffffff);
#endif
#undef MakeLimits

template <typename T> struct isprimitive_t { static const bool primitive = 0; };
#define MakePrimitive(T) template <> struct isprimitive_t<T> { static const bool primitive = 1; }
MakePrimitive(signed char);
MakePrimitive(unsigned char);
MakePrimitive(signed short);
MakePrimitive(unsigned short);
MakePrimitive(signed int);
MakePrimitive(unsigned int);
MakePrimitive(signed long);
MakePrimitive(unsigned long);
MakePrimitive(signed long long);
MakePrimitive(unsigned long long);
MakePrimitive(float);
MakePrimitive(double);
MakePrimitive(bool);

template<typename T> struct ispointer_t { static const bool pointer = 0; };
template <typename T> struct ispointer_t<T*> { static const bool pointer = 1; };
#define ispointer(T) (ispointer_t<T>::pointer)
#define isprimitive(T) (isprimitive_t<T>::primitive)

// Null pointer to the specified object type, for computing field offsets
#define offsetof_(T, field) ((Waddr)(&(reinterpret_cast<T*>(NULL)->field)) - ((Waddr)reinterpret_cast<T*>(NULL)))
#define baseof(T, field, ptr) ((T*)(((byte*)(ptr)) - offsetof_(T, field)))
// Restricted (non-aliased) pointers:
#define noalias __restrict__

// Default placement versions of operator new.
inline void* operator new(size_t, void* p) { return p; }
inline void* operator new[](size_t, void* p) { return p; }
inline void operator delete(void*, void*) { }
inline void operator delete[](void*, void*) { }

// Add raw data auto-casts to a structured or bitfield type
#define RawDataAccessors(structtype, rawtype) \
  structtype() { } \
  structtype(rawtype rawbits) { *((rawtype*)this) = rawbits; } \
  operator rawtype() const { return *((rawtype*)this); }

// Typecasts in bizarre ways required for binary form access
union W32orFloat { W32 w; float f; };
union W64orDouble {
  W64 w;
  double d;
  struct { W32 lo; W32s hi; } hilo;
  struct { W64 mantissa:52, exponent:11, negative:1; } ieee;
  // This format makes it easier to see if a NaN is a signalling NaN.
  struct { W64 mantissa:51, qnan:1, exponent:11, negative:1; } ieeenan;
};

static inline const float W32toFloat(W32 x) { union W32orFloat c; c.w = x; return c.f; }
static inline const W32 FloatToW32(float x) { union W32orFloat c; c.f = x; return c.w; }
static inline const double W64toDouble(W64 x) { union W64orDouble c; c.w = x; return c.d; }
static inline const W64 DoubleToW64(double x) { union W64orDouble c; c.d = x; return c.w; }

//
// Functional constructor
//

template <typename T> static inline T min(const T& a, const T& b) { typeof (a) _a = a; typeof (b) _b = b; return _a > _b ? _b : _a; }
template <typename T> static inline T max(const T& a, const T& b) { typeof (a) _a = a; typeof (b) _b = b; return _a > _b ? _a : _b; }
template <typename T> static inline T clipto(const T& v, const T& minv, const T& maxv) { return min(max(v, minv), maxv); }
template <typename T> static inline bool inrange(const T& v, const T& minv, const T& maxv) { typeof (v) _v = v; return ((_v >= minv) & (_v <= maxv)); }
template <typename T> static inline T abs(T x) { typeof (x) _x = x; return (_x < 0) ? -_x : _x; } // (built-in for gcc)

// Bit fitting
static inline bool fits_in_signed_nbit(W64s v, int b) {
  return inrange(v, W64s(-(1ULL<< (b-1))), W64s(+(1ULL << (b-1))-1));
}

static inline bool fits_in_signed_nbit_tagged(W64s v, int b) {
  return inrange(v, W64s(-(1ULL<< (b-1))+1), W64s(+(1ULL << (b-1))-1));
}

static inline bool fits_in_signed_8bit(W64s v) { return fits_in_signed_nbit(v, 8); }
static inline bool fits_in_signed_16bit(W64s v) { return fits_in_signed_nbit(v, 16); }
static inline bool fits_in_signed_32bit(W64s v) { return fits_in_signed_nbit(v, 32); }

#define sqr(x) ((x)*(x))
#define cube(x) ((x)*(x)*(x))
#define bit(x, n) (((x) >> (n)) & 1)

#define bitmask(l) (((l) == 64) ? (W64)(-1LL) : ((1LL << (l))-1LL))
#define bits(x, i, l) (((x) >> (i)) & bitmask(l))
#define lowbits(x, l) bits(x, 0, l)
#define setbit(x,i) ((x) |= (1LL << (i)))
#define clearbit(x, i) ((x) &= (W64)(~(1LL << (i))))
#define assignbit(x, i, v) ((x) = (((x) &= (W64)(~(1LL << (i)))) | (((W64)((bool)(v))) << i)));

#define foreach(i, n) for (size_t i = 0; i < (n); i++)

static inline W64s signext64(W64s x, const int i) { return (x << (64-i)) >> (64-i); }
static inline W32s signext32(W32s x, const int i) { return (x << (32-i)) >> (32-i); }
static inline W16s signext16(W16s x, const int i) { return (x << (16-i)) >> (16-i); }

static inline W64s bitsext64(W64s x, const int i, const int l) { return signext64(bits(x, i, l), l); }
static inline W32s bitsext32(W32s x, const int i, const int l) { return signext32(bits(x, i, l), l); }
static inline W16s bitsext16(W16s x, const int i, const int l) { return signext16(bits(x, i, l), l); }

typedef byte v16qi __attribute__ ((vector_size(16)));
typedef v16qi vec16b;
typedef W16 v8hi __attribute__ ((vector_size(16)));
typedef v8hi vec8w;
typedef float v4sf __attribute__ ((vector_size(16)));
typedef v4sf vec4f;
typedef W32 v4si __attribute__ ((vector_size(16)));
typedef v4si vec4i;
typedef float v2df __attribute__ ((vector_size(16)));
typedef v2df vec2d;

inline vec16b x86_sse_pcmpeqb(vec16b a, vec16b b) { asm("pcmpeqb %[b],%[a]" : [a] "+x" (a) : [b] "xg" (b)); return a; }
inline vec8w x86_sse_pcmpeqw(vec8w a, vec8w b) { asm("pcmpeqw %[b],%[a]" : [a] "+x" (a) : [b] "xg" (b)); return a; }
inline vec4i x86_sse_pcmpeqd(vec4i a, vec4i b) { asm("pcmpeqd %[b],%[a]" : [a] "+x" (a) : [b] "xg" (b)); return a; }
inline vec16b x86_sse_psubusb(vec16b a, vec16b b) { asm("psubusb %[b],%[a]" : [a] "+x" (a) : [b] "xg" (b)); return a; }
inline vec16b x86_sse_paddusb(vec16b a, vec16b b) { asm("paddusb %[b],%[a]" : [a] "+x" (a) : [b] "xg" (b)); return a; }
inline vec16b x86_sse_pandb(vec16b a, vec16b b) { asm("pand %[b],%[a]" : [a] "+x" (a) : [b] "xg" (b)); return a; }
inline vec8w x86_sse_psubusw(vec8w a, vec8w b) { asm("psubusb %[b],%[a]" : [a] "+x" (a) : [b] "xg" (b)); return a; }
inline vec8w x86_sse_paddusw(vec8w a, vec8w b) { asm("paddsub %[b],%[a]" : [a] "+x" (a) : [b] "xg" (b)); return a; }
inline vec8w x86_sse_pandw(vec8w a, vec8w b) { asm("pand %[b],%[a]" : [a] "+x" (a) : [b] "xg" (b)); return a; }
inline vec16b x86_sse_packsswb(vec8w a, vec8w b) { asm("packsswb %[b],%[a]" : [a] "+x" (a) : [b] "xg" (b)); return (vec16b)a; }
inline W32 x86_sse_pmovmskb(vec16b vec) { W32 mask; asm("pmovmskb %[vec],%[mask]" : [mask] "=r" (mask) : [vec] "x" (vec)); return mask; }
inline W32 x86_sse_pmovmskw(vec8w vec) { return x86_sse_pmovmskb(x86_sse_packsswb(vec, vec)) & 0xff; }
inline vec16b x86_sse_psadbw(vec16b a, vec16b b) { asm("psadbw %[b],%[a]" : [a] "+x" (a) : [b] "xg" (b)); return a; }
template <int i> inline W16 x86_sse_pextrw(vec16b a) { W32 rd; asm("pextrw %[i],%[a],%[rd]" : [rd] "=r" (rd) : [a] "x" (a), [i] "N" (i)); return rd; }

inline vec16b x86_sse_ldvbu(const vec16b* m) { vec16b rd; asm("movdqu %[m],%[rd]" : [rd] "=x" (rd) : [m] "xm" (*m)); return rd; }
inline void x86_sse_stvbu(vec16b* m, const vec16b ra) { asm("movdqu %[ra],%[m]" : [m] "=m" (*m) : [ra] "x" (ra) : "memory"); }
inline vec8w x86_sse_ldvwu(const vec8w* m) { vec8w rd; asm("movdqu %[m],%[rd]" : [rd] "=x" (rd) : [m] "xm" (*m)); return rd; }
inline void x86_sse_stvwu(vec8w* m, const vec8w ra) { asm("movdqu %[ra],%[m]" : [m] "=m" (*m) : [ra] "x" (ra) : "memory"); }

inline vec16b x86_sse_zerob() { vec16b rd; asm("pxor %[rd],%[rd]" : [rd] "+x" (rd)); return rd; }
inline vec16b x86_sse_onesb() { vec16b rd; asm("pcmpeqb %[rd],%[rd]" : [rd] "+x" (rd)); return rd; }
inline vec8w x86_sse_zerow() { vec8w rd; asm("pxor %[rd],%[rd]" : [rd] "+x" (rd)); return rd; }
inline vec8w x86_sse_onesw() { vec8w rd; asm("pcmpeqw %[rd],%[rd]" : [rd] "+x" (rd)); return rd; }

// If lddqu is available (SSE3: Athlon 64 (some cores, like X2), Pentium 4 Prescott), use that instead. It may be faster.

extern const byte byte_to_vec16b[256][16];
extern const byte index_bytes_vec16b[16][16];
extern const byte index_bytes_plus1_vec16b[16][16];

inline vec16b x86_sse_dupb(const byte b) {
  return *((vec16b*)&byte_to_vec16b[b]);
}

inline vec8w x86_sse_dupw(const W16 b) {
  W32 w = (b << 16) | b;
  vec8w v;
  W32* wp = (W32*)&v;
  wp[0] = w; wp[1] = w; wp[2] = w; wp[3] = w;
  return v;
}

inline void x86_set_mxcsr(W32 value) { asm volatile("ldmxcsr %[value]" : : [value] "m" (value)); }
inline W32 x86_get_mxcsr() { W32 value; asm volatile("stmxcsr %[value]" : [value] "=m" (value)); return value; }
union MXCSR {
  struct { W32 ie:1, de:1, ze:1, oe:1, ue:1, pe:1, daz:1, im:1, dm:1, zm:1, om:1, um:1, pm:1, rc:2, fz:1; } fields;
  W32 data;

  MXCSR() { }
  MXCSR(W32 v) { data = v; }
  operator W32() const { return data; }
};
enum { MXCSR_ROUND_NEAREST, MXCSR_ROUND_DOWN, MXCSR_ROUND_UP, MXCSR_ROUND_TOWARDS_ZERO };
#define MXCSR_EXCEPTION_DISABLE_MASK 0x1f80 // OR this into mxcsr to disable all exceptions
#define MXCSR_DEFAULT 0x1f80 // default settings (no exceptions, defaults for rounding and denormals)

inline W32 x86_bsf32(W32 b) { W32 r = 0; asm("bsf %[b],%[r]" : [r] "+r" (r) : [b] "r" (b)); return r; }
inline W64 x86_bsf64(W64 b) { W64 r = 0; asm("bsf %[b],%[r]" : [r] "+r" (r) : [b] "r" (b)); return r; }
inline W32 x86_bsr32(W32 b) { W32 r = 0; asm("bsr %[b],%[r]" : [r] "+r" (r) : [b] "r" (b)); return r; }
inline W64 x86_bsr64(W64 b) { W64 r = 0; asm("bsr %[b],%[r]" : [r] "+r" (r) : [b] "r" (b)); return r; }

template <typename T> inline bool x86_bt(T r, T b) { byte c; asm("bt %[b],%[r]; setc %[c]" : [c] "=q" (c) : [r] "r" (r), [b] "r" (b)); return c; }
template <typename T> inline bool x86_btn(T r, T b) { byte c; asm("bt %[b],%[r]; setnc %[c]" : [c] "=r" (c) : [r] "r" (r), [b] "r" (b)); return c; }

// Return the updated data; ignore the old value
template <typename T> inline W64 x86_bts(T r, T b) { asm("bts %[b],%[r]" : [r] "+r" (r) : [b] "r" (b)); return r; }
template <typename T> inline W64 x86_btr(T r, T b) { asm("btr %[b],%[r]" : [r] "+r" (r) : [b] "r" (b)); return r; }
template <typename T> inline W64 x86_btc(T r, T b) { asm("btc %[b],%[r]" : [r] "+r" (r) : [b] "r" (b)); return r; }

// Return the old value of the bit, but still update the data
template <typename T> inline bool x86_test_bts(T& r, T b) { byte c; asm("bts %[b],%[r]; setc %[c]" : [c] "=r" (c), [r] "+r" (r) : [b] "r" (b)); return c; }
template <typename T> inline bool x86_test_btr(T& r, T b) { byte c; asm("btr %[b],%[r]; setc %[c]" : [c] "=r" (c), [r] "+r" (r) : [b] "r" (b)); return c; }
template <typename T> inline bool x86_test_btc(T& r, T b) { byte c; asm("btc %[b],%[r]; setc %[c]" : [c] "=r" (c), [r] "+r" (r) : [b] "r" (b)); return c; }

// Full SMP-aware locking with test-and-[set|reset|complement] in memory
template <typename T> inline bool x86_locked_bts(T& r, T b) { byte c; asm volatile("lock bts %[b],%[r]; setc %[c]" : [c] "=r" (c), [r] "+m" (r) : [b] "r" (b) : "memory"); return c; }
template <typename T> inline bool x86_locked_btr(T& r, T b) { byte c; asm volatile("lock btr %[b],%[r]; setc %[c]" : [c] "=r" (c), [r] "+m" (r) : [b] "r" (b) : "memory"); return c; }
template <typename T> inline bool x86_locked_btc(T& r, T b) { byte c; asm volatile("lock btc %[b],%[r]; setc %[c]" : [c] "=r" (c), [r] "+m" (r) : [b] "r" (b) : "memory"); return c; }

template <typename T> inline T bswap(T r) { asm("bswap %[r]" : [r] "+r" (r)); return r; }

static inline W16 x86_sse_maskeqb(const vec16b v, byte target) { return x86_sse_pmovmskb(x86_sse_pcmpeqb(v, x86_sse_dupb(target))); }

// This is a barrier for the compiler only, NOT the processor!
#define barrier() asm volatile("": : :"memory")

// Denote parallel sections for the compiler
#define parallel

template <typename T>
static inline T xchg(T& v, T newv) {
	switch (sizeof(T)) {
  case 1: asm volatile("lock xchgb %[newv],%[v]" : [v] "+m" (v), [newv] "+r" (newv) : : "memory"); break;
  case 2: asm volatile("lock xchgw %[newv],%[v]" : [v] "+m" (v), [newv] "+r" (newv) : : "memory"); break;
  case 4: asm volatile("lock xchgl %[newv],%[v]" : [v] "+m" (v), [newv] "+r" (newv) : : "memory"); break;
  case 8: asm volatile("lock xchgq %[newv],%[v]" : [v] "+m" (v), [newv] "+r" (newv) : : "memory"); break;
	}
	return newv;
}

template <typename T>
static inline T xadd(T& v, T incr) {
	switch (sizeof(T)) {
  case 1: asm volatile("lock xaddb %[incr],%[v]" : [v] "+m" (v), [incr] "+r" (incr) : : "memory"); break;
  case 2: asm volatile("lock xaddw %[incr],%[v]" : [v] "+m" (v), [incr] "+r" (incr) : : "memory"); break;
  case 4: asm volatile("lock xaddl %[incr],%[v]" : [v] "+m" (v), [incr] "+r" (incr) : : "memory"); break;
  case 8: asm volatile("lock xaddq %[incr],%[v]" : [v] "+m" (v), [incr] "+r" (incr) : : "memory"); break;
	}
  return incr;
}

template <typename T>
static inline T cmpxchg(T& mem, T newv, T cmpv) {
	switch (sizeof(T)) {
  case 1: asm volatile("lock cmpxchgb %[newv],%[mem]" : [mem] "+m" (mem), [cmpv] "+a" (cmpv), [newv] "+r" (newv) : : "memory"); break;
  case 2: asm volatile("lock cmpxchgw %[newv],%[mem]" : [mem] "+m" (mem), [cmpv] "+a" (cmpv), [newv] "+r" (newv) : : "memory"); break;
  case 4: asm volatile("lock cmpxchgl %[newv],%[mem]" : [mem] "+m" (mem), [cmpv] "+a" (cmpv), [newv] "+r" (newv) : : "memory"); break;
  case 8: asm volatile("lock cmpxchgq %[newv],%[mem]" : [mem] "+m" (mem), [cmpv] "+a" (cmpv), [newv] "+r" (newv) : : "memory"); break;
	}

  // Return the old value in the slot (so we can check if it matches newv)
  return cmpv;
}

static inline void cpu_pause() { asm volatile("pause" : : : "memory"); }

static inline void prefetch(const void* x) { asm volatile("prefetcht0 (%0)" : : "r" (x)); }

static inline void cpuid(int op, W32& eax, W32& ebx, W32& ecx, W32& edx) {
	asm("cpuid" : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx) : "0" (op));
}

static inline W64 rdtsc() {
  W32 lo, hi;
  asm volatile("rdtsc" : "=a" (lo), "=d" (hi));
  return ((W64)lo) | (((W64)hi) << 32);
}

template <typename T>
static inline T x86_ror(T r, int n) { asm("ror %%cl,%[r]" : [r] "+q" (r) : [n] "c" ((byte)n)); return r; }

template <typename T>
static inline T x86_rol(T r, int n) { asm("rol %%cl,%[r]" : [r] "+q" (r) : [n] "c" ((byte)n)); return r; }

#ifndef __x86_64__
// Need to emulate this on 32-bit x86
// Throws "explicit template specialization cannot have a storage class" in gcc 4.4.1 (probably 4.3+).
// Fix as per http://gcc.gnu.org/gcc-4.3/porting_to.html
//static inline W64 x86_ror(W64 r, int n) {
template <>
inline W64 x86_ror(W64 r, int n) {
  return (r >> n) | (r << (64 - n));
}
#endif

template <typename T>
static inline T dupb(const byte b) { return T(b) * T(0x0101010101010101ULL); }

template <int n> struct lg { static const int value = 1 + lg<n/2>::value; };
template <> struct lg<1> { static const int value = 0; };
#define log2(v) (lg<(v)>::value)

template <int n> struct lg10 { static const int value = 1 + lg10<n/10>::value; };
template <> struct lg10<1> { static const int value = 0; };
template <> struct lg10<0> { static const int value = 0; };
#define log10(v) (lg10<(v)>::value)

template <int N, typename T>
static inline T foldbits(T a) {
  if (N == 0) return 0;

  const int B = (sizeof(T) * 8);
  const int S = (B / N) + ((B % N) ? 1 : 0);

  T z = 0;
  foreach (i, S) {
    z ^= a;
    a >>= N;
  }

  return lowbits(z, N);
}


// For specifying easy to read arrays
#define _ (0)

asmlinkage {
#include <unistd.h>
#include <sys/types.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/mman.h>
#include <sys/utsname.h>
#include <sys/ptrace.h>
#include <sys/signal.h>
#include <sys/resource.h>
#include <sys/user.h>
};

#include <stdarg.h>

#include <syscalls.h>

#ifdef PAGE_SIZE
#undef PAGE_SIZE
// We're on x86 or x86-64, so pages are always 4096 bytes:
#define PAGE_SIZE 4096
#endif

/*
 * Make these math functions available even inside of member functions with the same name:
 */
static inline float fsqrt(float v) { return (float)std::sqrt(v); }

template <typename T> static inline void setzero(T& x) { memset(&x, 0, sizeof(T)); }

#define HI32(x) (W32)((x) >> 32LL)
#define LO32(x) (W32)((x) & 0xffffffffLL)
#define CONCAT64(hi, lo) ((((W64)(hi)) << 32) + (((W64)(lo)) & 0xffffffffLL))

template <typename T, typename A> static inline T floor(T x, A a) { return (T)(((T)x) & ~((T)(a-1))); }
template <typename T, typename A> static inline T trunc(T x, A a) { return (T)(((T)x) & ~((T)(a-1))); }
template <typename T, typename A> static inline T ceil(T x, A a) { return (T)((((T)x) + ((T)(a-1))) & ~((T)(a-1))); }
template <typename T, typename A> static inline T mask(T x, A a) { return (T)(((T)x) & ((T)(a-1))); }

template <typename T, typename A> static inline T* floorptr(T* x, A a) { return (T*)floor((Waddr)x, a); }
template <typename T, typename A> static inline T* ceilptr(T* x, A a) { return (T*)ceil((Waddr)x, a); }
template <typename T, typename A> static inline T* maskptr(T* x, A a) { return (T*)mask((Waddr)x, a); }
static inline W64 mux64(W64 sel, W64 v0, W64 v1) { return (sel & v1) | ((~sel) & v0); }
template <typename T> static inline T mux(T sel, T v1, T v0) { return (sel & v1) | ((~sel) & v0); }

template <typename T> void swap(T& a, T& b) { T t = a;  a = b; b = t; }

// #define noinline __attribute__((noinline))

//
// Force the compiler to use branchless forms:
//
template <typename T, typename K>
T select(K cond, T if0, T if1) {
  T z = if0;
  asm("test %[cond],%[cond]; cmovnz %[if1],%[z]" : [z] "+r" (z) : [cond] "r" (cond), [if1] "rm" (if1) : "flags");
  return z;
}

template <typename T, typename K>
void condmove(K cond, T& v, T newv) {
  asm("test %[cond],%[cond]; cmovnz %[newv],%[v]" : [v] "+r" (v) : [cond] "r" (cond), [newv] "rm" (newv) : "flags");
}

#define typeof __typeof__
#define ptralign(ptr, bytes) ((typeof(ptr))((unsigned long)(ptr) & ~((bytes)-1)))
#define ptrmask(ptr, bytes) ((typeof(ptr))((unsigned long)(ptr) & ((bytes)-1)))

template <typename T>
inline void arraycopy(T* dest, const T* source, int count) { memcpy(dest, source, count * sizeof(T)); }

template <typename T, typename V>
inline void rawcopy(T& dest, const V& source) { memcpy(&dest, &source, sizeof(T)); }

// static inline float randfloat() { return ((float)rand() / RAND_MAX); }

static inline bool aligned(W64 address, int size) {
  return ((address & (W64)(size-1)) == 0);
}

inline bool strequal(const char* a, const char* b) {
  return (strcmp(a, b) == 0);
}

template <typename T, int size> int lengthof(T (&)[size]) { return size; }

extern const byte popcountlut8bit[];
extern const byte lsbindexlut8bit[];

static inline int popcount8bit(byte x) {
  return popcountlut8bit[x];
}

static inline int lsbindex8bit(byte x) {
  return lsbindexlut8bit[x];
}

static inline int popcount(W32 x) {
  return (popcount8bit(x >> 0) + popcount8bit(x >> 8) + popcount8bit(x >> 16) + popcount8bit(x >> 24));
}

static inline int popcount64(W64 x) {
  return popcount(LO32(x)) + popcount(HI32(x));
}


extern const W64 expand_8bit_to_64bit_lut[256];

// LSB index:

// Operand must be non-zero or result is undefined:
inline unsigned int lsbindex32(W32 n) { return x86_bsf32(n); }

inline int lsbindexi32(W32 n) {
  int r = lsbindex32(n);
  return (n ? r : -1);
}

#ifdef __x86_64__
inline unsigned int lsbindex64(W64 n) { return x86_bsf64(n); }
#else
inline unsigned int lsbindex64(W64 n) {
  W32 lo = LO32(n);
  W32 hi = HI32(n);

  int ilo = lsbindex32(lo);
  int ihi = lsbindex32(hi) + 32;

  return (lo) ? ilo : ihi;
}
#endif

inline unsigned int lsbindexi64(W64 n) {
  int r = lsbindex64(n);
  return (n ? r : -1);
}

// static inline unsigned int lsbindex(W32 n) { return lsbindex32(n); }
inline unsigned int lsbindex(W64 n) { return lsbindex64(n); }

// MSB index:

// Operand must be non-zero or result is undefined:
inline unsigned int msbindex32(W32 n) { return x86_bsr32(n); }

inline int msbindexi32(W32 n) {
  int r = msbindex32(n);
  return (n ? r : -1);
}

#ifdef __x86_64__
inline unsigned int msbindex64(W64 n) { return x86_bsr64(n); }
#else
inline unsigned int msbindex64(W64 n) {
  W32 lo = LO32(n);
  W32 hi = HI32(n);

  int ilo = msbindex32(lo);
  int ihi = msbindex32(hi) + 32;

  return (hi) ? ihi : ilo;
}
#endif

inline unsigned int msbindexi64(W64 n) {
  int r = msbindex64(n);
  return (n ? r : -1);
}

// static inline unsigned int msbindex(W32 n) { return msbindex32(n); }
inline unsigned int msbindex(W64 n) { return msbindex64(n); }

#define percent(x, total) (100.0 * ((float)(x)) / ((float)(total)))

inline int add_index_modulo(int index, int increment, int bufsize) {
  // Only if power of 2: return (index + increment) & (bufsize-1);
  index += increment;
  if (index < 0) index += bufsize;
  if (index >= bufsize) index -= bufsize;
  return index;
}

#include <superstl.h>

using namespace superstl;

ostream& operator <<(ostream& os, const vec16b& v);
ostream& operator ,(ostream& os, const vec16b& v);
ostream& operator <<(ostream& os, const vec8w& v);
ostream& operator ,(ostream& os, const vec8w& v);

#endif // __cplusplus

#endif // _GLOBALS_H_
