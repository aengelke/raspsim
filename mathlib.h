// -*- c++ -*-
//
// Math Functions
//
// Copyright 2008 Matt T. Yourst <yourst@yourst.com>
// Derived from various sources (glibc, etc)
//
// This program is free software; it is licensed under the
// GNU General Public License, Version 2.
//

#ifndef __MATHLIB_H__
#define __MATHLIB_H__

#include <math.h>
#include <float.h>

/* ISO C99 defines some macros to compare number while taking care for
   unordered numbers.  Many FPUs provide special instructions to support
   these operations.  Generic support in GCC for these as builtins went
   in before 3.0.0, but not all cpus added their patterns.  We define
   versions that use the builtins here, and <bits/mathinline.h> will
   undef/redefine as appropriate for the specific GCC version in use.  */
#define isgreater(x, y)	__builtin_isgreater(x, y)
#define isgreaterequal(x, y)	__builtin_isgreaterequal(x, y)
#define isless(x, y)		__builtin_isless(x, y)
#define islessequal(x, y)	__builtin_islessequal(x, y)
#define islessgreater(x, y)	__builtin_islessgreater(x, y)
#define isunordered(u, v)	__builtin_isunordered(u, v)

namespace math {
  /*
    This is faster but may lose some precision on really big numbers:
    W32 oldmxcsr;
    MXCSR mxcsr;
    double z;
    oldmxcsr = x86_get_mxcsr();
    mxcsr.data = oldmxcsr;
    mxcsr.fields.rc = MXCSR_ROUND_NEAREST;
    x86_set_mxcsr(mxcsr.data);
    asm("cvt... %[ra],%[rd];" : [rd] "=x" (z) : [ra] "x" (a));
    x86_set_mxcsr(oldmxcsr);
    return z;
  */

  double round(double a);
  double floor(double a);
  double ceil(double a);
  double trunc(double a);

  double sin(double a);
  double cos(double a);
  double exp2(double x);

  int ilogb(double x);
  double significand(double x);

  extern double tan(double x);

  inline double sqrt(double a) {
    double z;
    asm("sqrtsd %[ra],%[rd];" : [rd] "=x" (z) : [ra] "x" (a));
    return z;
  }

  inline double fabs(double a) {
    union {
      W64 w;
      double d;
    } u;

    u.d = a;
    u.w = u.w & 0x7fffffffffffffffULL;
    return u.d;
  }

  /* All floating-point numbers can be put in one of these categories.  */

#undef isinf
  inline int isinf(double x) {
    W64orDouble u;
    u.d = x;
    u.hilo.lo |= (u.hilo.hi & 0x7fffffff) ^ 0x7ff00000;
    u.hilo.lo |= -u.hilo.lo;
    return ~(u.hilo.lo >> 31) & (u.hilo.hi >> 30);
  }

#undef isinff
  inline int isinff(float x) {
    W32orFloat u;
    u.f = x;

    W32s t = u.w & 0x7fffffff;
    t ^= 0x7f800000;
    t |= -t;
    return ~(t >> 31) & (u.w >> 30);
  }

#undef finite
	inline int finite(double x) {
    W64orDouble u;
    u.d = x;
    return (int)((W32s)((u.hilo.hi & 0x7fffffff)-0x7ff00000)>>31);
  }

#undef finitef
	inline int finitef(float x) {
    W32orFloat u;
    u.f = x;
    return (int)((W32s)((u.w & 0x7fffffff)-0x7f800000)>>31);
  }

#undef signbit
  inline int signbit(double x) {
    W64orDouble u;
    u.d = x;
    return bit(u.w, 63);
  }

#undef signbitf
  inline int signbitf(float x) {
    W32orFloat u;
    u.f = x;
    return bit(u.w, 31);
  }

#undef isnan
	inline int isnan(double x) {
    W64orDouble u;
    u.d = x;
    u.hilo.hi &= 0x7fffffff;
    u.hilo.hi |= (W32)(u.hilo.lo|(-u.hilo.lo))>>31;
    u.hilo.hi = 0x7ff00000 - u.hilo.hi;
    return (int)(((W32)u.hilo.hi)>>31);
  }

#undef isnanf
	inline int isnanf(float x) {
    W32orFloat u;
    u.f = x;
    u.w &= 0x7fffffff;
    u.w = 0x7f800000 - u.w;
    return (int)(((W32)(u.w))>>31);
  }

#undef fpclassify
  inline int fpclassify(double x) {
    W64orDouble u;
    u.d = x;

    int retval = FP_NORMAL;
    u.hilo.lo |= u.hilo.hi & 0xfffff;
    u.hilo.hi &= 0x7ff00000;
    if ((u.hilo.hi | u.hilo.lo) == 0)
      retval = FP_ZERO;
    else if (u.hilo.hi == 0)
      retval = FP_SUBNORMAL;
    else if (u.hilo.hi == 0x7ff00000)
      retval = u.hilo.lo != 0 ? FP_NAN : FP_INFINITE;

    return retval;
  }

#undef fpclassifyf
  inline int fpclassifyf(float x) {
    W32orFloat u;
    u.f = x;

    int retval = FP_NORMAL;
    
    u.w &= 0x7fffffff;
    if (u.w == 0)
      retval = FP_ZERO;
    else if (u.w < 0x800000)
      retval = FP_SUBNORMAL;
    else if (u.w >= 0x7f800000)
      retval = u.w > 0x7f800000 ? FP_NAN : FP_INFINITE;
    
    return retval;
  }

#undef isnormal
  inline bool isnormal(double x) { return (fpclassify(x) == FP_NORMAL); }
};
#endif
