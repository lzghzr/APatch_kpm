/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <stdarg.h>

static unsigned int hr_log_calls;
static char hr_last_log[256];
static void hr_test_log(const char* format, ...) {
  va_list args;
  va_start(args, format);
  vsnprintf(hr_last_log, sizeof(hr_last_log), format, args);
  va_end(args);
  hr_log_calls++;
}
#undef logkm
#define logkm(...) hr_test_log(__VA_ARGS__)
