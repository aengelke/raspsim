//
// Standard library functions only used in normal (non-embedded) programs
//
// Copyright 2005-2006 Matt T. Yourst <yourst@yourst.com>
//
// This program is free software; it is licensed under the
// GNU General Public License, Version 2.
//

#include <globals.h>

//
// Full featured float format function:
//
int format_float(char* buf, int bufsize, double v, int precision, int pad) {
  char format[32];
  snprintf(format, sizeof(format), "%%.%df", precision);
  snprintf(buf, bufsize, format, v);
  return strlen(buf);
}

extern "C" void assert_fail(const char *__assertion, const char *__file, unsigned int __line, const char *__function) {
  stringbuf sb;
  sb << "Assert ", __assertion, " failed in ", __file, ":", __line, " (", __function, ")", endl;

  cerr << sb;
  cerr.flush();
  cout.flush();
  abort();
}

//
// Get the processor core frequency in cycles/second:
//
W64 get_core_freq_hz() {
  W64 hz = 0;

  istream cpufreqis("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq");
  if (cpufreqis) {
    char s[256];
    cpufreqis >> readline(s, sizeof(s));

    int khz;
    int n = sscanf(s, "%d", &khz);

    if (n == 1) {
      hz = ((W64)khz) * 1000;
      return hz;
    }
  }

  istream is("/proc/cpuinfo");

  if (!is) {
    cerr << "get_core_freq_hz(): warning: cannot open /proc/cpuinfo. Is this a Linux machine?", endl;
    return hz;
  }

  while (is) {
    char s[256];
    is >> readline(s, sizeof(s));

    int mhz;
    int n = sscanf(s, "cpu MHz : %d", &mhz);
    if (n == 1) {
      hz = ((W64)mhz) * 1000000;
      return hz;
    }
  }

  // Can't read either of these procfiles: abort
  abort();
  return 0;
}
