/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 lzghzr. All Rights Reserved.
 */

#include <compiler.h>
#include <hook.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/printk.h>
#include <linux/string.h>

#include "battchg.h"

KPM_NAME("qti_battery_charger");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("lzghzr");
KPM_DESCRIPTION("set battery_psy_get_prop value");

int (*do_init_module)(struct module *mod) = 0;
int (*battery_psy_get_prop)(struct power_supply *psy,
                            enum power_supply_property prop,
                            union power_supply_propval *pval) = 0;

char MODULE_NAME[] = "qti_battery_charger";
char MODEL_NAME[] = "SNYSCA6";

void battery_psy_get_prop_after(hook_fargs3_t *args, void *udata)
{
  enum power_supply_property prop = args->arg1;
  union power_supply_propval *pval = (typeof(pval))args->arg2;

  switch (prop)
  {
  // case POWER_SUPPLY_PROP_CYCLE_COUNT:
  //   pval->intval = 1;
  //   break;
  // case POWER_SUPPLY_PROP_CHARGE_FULL_DESIGN:
  // case POWER_SUPPLY_PROP_CHARGE_FULL:
  //   pval->intval = 5000000;
  //   break;
  case POWER_SUPPLY_PROP_CAPACITY:
    if (pval->intval < 10)
    {
      pval->intval = 10;
    }
    break;
  case POWER_SUPPLY_PROP_MODEL_NAME:
    memcpy((char *)pval->strval, MODEL_NAME, sizeof(MODEL_NAME));
    break;
  }
}

static long hook_battery_psy_get_prop()
{
  battery_psy_get_prop = (typeof(battery_psy_get_prop))kallsyms_lookup_name("battery_psy_get_prop");
  pr_info("kernel function battery_psy_get_prop addr: %llx\n", battery_psy_get_prop);
  if (!battery_psy_get_prop)
  {
    return -1;
  }

  hook_err_t err = hook_wrap3(battery_psy_get_prop, 0, battery_psy_get_prop_after, 0);
  if (err)
  {
    pr_err("hook battery_psy_get_prop after error: %d\n", err);
    return -2;
  }
  else
  {
    pr_info("hook battery_psy_get_prop after success\n");
  }
  return 0;
}

void do_init_module_after(hook_fargs1_t *args, void *udata)
{
  struct module *mod = (typeof(mod))args->arg0;
  if (unlikely(!memcmp(mod->name, MODULE_NAME, sizeof(MODULE_NAME))))
  {
    unhook(do_init_module);
    do_init_module = 0;
    hook_battery_psy_get_prop();
  }
}

static long hook_do_init_module()
{
  do_init_module = (typeof(do_init_module))kallsyms_lookup_name("do_init_module");
  pr_info("kernel function do_init_module addr: %llx\n", do_init_module);
  if (!do_init_module)
  {
    return -1;
  }

  hook_err_t err = hook_wrap1(do_init_module, 0, do_init_module_after, 0);
  if (err)
  {
    pr_err("hook do_init_module after error: %d\n", err);
    return -2;
  }
  else
  {
    pr_info("hook do_init_module after success\n");
  }
  return 0;
}

static long inline_hook_init(const char *args, const char *event, void *__user reserved)
{
  int rc;
  rc = hook_battery_psy_get_prop();
  if (rc < 0)
  {
    rc = hook_do_init_module();
    if (rc < 0)
    {
      return rc;
    }
  }
  return 0;
}

static long inline_hook_exit(void *__user reserved)
{
  if (do_init_module)
  {
    unhook(do_init_module);
    do_init_module = 0;
  }
  if (battery_psy_get_prop)
  {
    unhook(battery_psy_get_prop);
    battery_psy_get_prop = 0;
  }
}

KPM_INIT(inline_hook_init);
KPM_EXIT(inline_hook_exit);
