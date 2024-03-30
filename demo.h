/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 lzghzr. All Rights Reserved.
 */

#include <hook.h>

static void demo_unhook(void *func)
{
  if (func && !is_bad_address(func))
  {
    unhook(func);
    func = 0;
  }
}