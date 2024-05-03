/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 * Copyright (C) 2024 lzghzr. All Rights Reserved.
 */

#pragma pack(8)

#include <hook.h>
#include <linux/cred.h>
#include <linux/sched.h>

#define bits32(n, high, low) ((uint32_t)((n) << (31u - (high))) >> (31u - (high) + (low)))
#define bit(n, st) (((n) >> (st)) & 1)
#define sign64_extend(n, len) \
    (((uint64_t)((n) << (63u - (len - 1))) >> 63u) ? ((n) | (0xFFFFFFFFFFFFFFFF << (len))) : n)

typedef uint32_t inst_type_t;
typedef uint32_t inst_mask_t;

#define INST_ADD_64 0x91000000u
#define INST_ADD_64_X0 0x91000000u
#define INST_LDR_64_ 0xF9400000u
#define INST_LDR_64_X0 0xF9400000u
#define INST_LDR_64_SP 0xF94003E0u
#define INST_LDRB 0x39400000u
#define INST_LDRH 0x79400000u
#define INST_TBZ 0x36000000u
#define INST_TBNZ 0x37000000u
#define INST_TBNZ_5 0x37280000u

#define MASK_ADD_64 0xFF800000u
#define MASK_ADD_64_X0 0xFF8003E0u
#define MASK_LDR_64_ 0xFFC00000u
#define MASK_LDR_64_X0 0xFFC003E0u
#define MASK_LDR_64_SP 0xFFC003E0u
#define MASK_LDRB 0xFFC00000u
#define MASK_LDRH 0xFFC00000u
#define MASK_TBZ 0x7F000000u
#define MASK_TBNZ 0x7F000000u
#define MASK_TBNZ_5 0xFFF80000u

#define ARM64_RET 0xD65F03C0

#define skvar(var) skv_##var
#define skvar_def(var) (*skv_##var)
#define skvlen(var) skvl_##var
#define skvar_val(var) (*skvar(var))

#define skfunc(func) skf_##func
#define skfunc_def(func) (*skf_##func)

#define skvar_lookup_name(var) skv_##var = (typeof(skv_##var))kallsyms_lookup_name(#var)
#define skfunc_lookup_name(func) skf_##func = (typeof(skf_##func))kallsyms_lookup_name(#func)

#define skfunc_call(func, ...)     \
  if (skf_##func)                  \
  {                                \
    return skf_##func(__VA_ARGS__) \
  };

#define lookup_name(func)                                  \
  func = 0;                                                \
  func = (typeof(func))kallsyms_lookup_name(#func);        \
  pr_info("kernel function %s addr: %llx\n", #func, func); \
  if (!func)                                               \
  {                                                        \
    return -21;                                            \
  }

#define hook_func(func, argv, before, after, udata)                         \
  if (!func)                                                                \
  {                                                                         \
    return -22;                                                             \
  }                                                                         \
  hook_err_t hook_err_##func = hook_wrap(func, argv, before, after, udata); \
  if (hook_err_##func)                                                      \
  {                                                                         \
    func = 0;                                                               \
    pr_err("hook %s error: %d\n", #func, hook_err_##func);                  \
    return -23;                                                             \
  }                                                                         \
  else                                                                      \
  {                                                                         \
    pr_info("hook %s success\n", #func);                                    \
  }

#define unhook_func(func)            \
  if (func && !is_bad_address(func)) \
  {                                  \
    unhook(func);                    \
    func = 0;                        \
  }

#define task_uid(task)                                                                       \
  ({                                                                                         \
    struct cred *cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset); \
    kuid_t ___val = *(kuid_t *)((uintptr_t)cred + cred_offset.uid_offset);                   \
    ___val;                                                                                  \
  })
#define task_gid(task)                                                                       \
  ({                                                                                         \
    struct cred *cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset); \
    kgid_t ___val = *(kgid_t *)((uintptr_t)cred + cred_offset.gid_offset);                   \
    ___val;                                                                                  \
  })
#define task_euid(task)                                                                      \
  ({                                                                                         \
    struct cred *cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset); \
    kuid_t ___val = *(kuid_t *)((uintptr_t)cred + cred_offset.euid_offset);                  \
    ___val;                                                                                  \
  })
#define task_egid(task)                                                                      \
  ({                                                                                         \
    struct cred *cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset); \
    kgid_t ___val = *(kgid_t *)((uintptr_t)cred + cred_offset.egid_offset);                  \
    ___val;                                                                                  \
  })
#define task_suid(task)                                                                      \
  ({                                                                                         \
    struct cred *cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset); \
    kuid_t ___val = *(kuid_t *)((uintptr_t)cred + cred_offset.suid_offset);                  \
    ___val;                                                                                  \
  })
#define task_sgid(task)                                                                      \
  ({                                                                                         \
    struct cred *cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset); \
    kgid_t ___val = *(kgid_t *)((uintptr_t)cred + cred_offset.sgid_offset);                  \
    ___val;                                                                                  \
  })


#define ADD_ARM_NOP1 __asm__("nop")
#define ADD_ARM_NOP2 __asm__("nop");ADD_ARM_NOP1
#define ADD_ARM_NOP3 __asm__("nop");ADD_ARM_NOP2
#define ADD_ARM_NOP4 __asm__("nop");ADD_ARM_NOP3
#define ADD_ARM_NOP5 __asm__("nop");ADD_ARM_NOP4
#define ADD_ARM_NOP6 __asm__("nop");ADD_ARM_NOP5
#define ADD_ARM_NOP7 __asm__("nop");ADD_ARM_NOP6
#define ADD_ARM_NOP8 __asm__("nop");ADD_ARM_NOP7
#define ADD_ARM_NOP9 __asm__("nop");ADD_ARM_NOP8
#define ADD_ARM_NOP10 __asm__("nop");ADD_ARM_NOP9
#define ADD_ARM_NOP11 __asm__("nop");ADD_ARM_NOP10
#define ADD_ARM_NOP12 __asm__("nop");ADD_ARM_NOP11
#define ADD_ARM_NOP13 __asm__("nop");ADD_ARM_NOP12
#define ADD_ARM_NOP14 __asm__("nop");ADD_ARM_NOP13
#define ADD_ARM_NOP15 __asm__("nop");ADD_ARM_NOP14
#define ADD_ARM_NOP16 __asm__("nop");ADD_ARM_NOP15
#define ADD_ARM_NOP17 __asm__("nop");ADD_ARM_NOP16
#define ADD_ARM_NOP18 __asm__("nop");ADD_ARM_NOP17
#define ADD_ARM_NOP19 __asm__("nop");ADD_ARM_NOP18
#define ADD_ARM_NOP20 __asm__("nop");ADD_ARM_NOP19
#define ADD_ARM_NOP21 __asm__("nop");ADD_ARM_NOP20
#define ADD_ARM_NOP22 __asm__("nop");ADD_ARM_NOP21
#define ADD_ARM_NOP23 __asm__("nop");ADD_ARM_NOP22
#define ADD_ARM_NOP24 __asm__("nop");ADD_ARM_NOP23
#define ADD_ARM_NOP25 __asm__("nop");ADD_ARM_NOP24
#define ADD_ARM_NOP26 __asm__("nop");ADD_ARM_NOP25
#define ADD_ARM_NOP27 __asm__("nop");ADD_ARM_NOP26
#define ADD_ARM_NOP28 __asm__("nop");ADD_ARM_NOP27
#define ADD_ARM_NOP29 __asm__("nop");ADD_ARM_NOP28
#define ADD_ARM_NOP30 __asm__("nop");ADD_ARM_NOP29
#define ADD_ARM_NOP30	__asm__("nop");ADD_ARM_NOP29
#define ADD_ARM_NOP31	__asm__("nop");ADD_ARM_NOP30
#define ADD_ARM_NOP32	__asm__("nop");ADD_ARM_NOP31
#define ADD_ARM_NOP33	__asm__("nop");ADD_ARM_NOP32
#define ADD_ARM_NOP34	__asm__("nop");ADD_ARM_NOP33
#define ADD_ARM_NOP35	__asm__("nop");ADD_ARM_NOP34
#define ADD_ARM_NOP36	__asm__("nop");ADD_ARM_NOP35
#define ADD_ARM_NOP37	__asm__("nop");ADD_ARM_NOP36
#define ADD_ARM_NOP38	__asm__("nop");ADD_ARM_NOP37
#define ADD_ARM_NOP39	__asm__("nop");ADD_ARM_NOP38
#define ADD_ARM_NOP40	__asm__("nop");ADD_ARM_NOP39
#define ADD_ARM_NOP41	__asm__("nop");ADD_ARM_NOP40
#define ADD_ARM_NOP42	__asm__("nop");ADD_ARM_NOP41
#define ADD_ARM_NOP43	__asm__("nop");ADD_ARM_NOP42
#define ADD_ARM_NOP44	__asm__("nop");ADD_ARM_NOP43
#define ADD_ARM_NOP45	__asm__("nop");ADD_ARM_NOP44
#define ADD_ARM_NOP46	__asm__("nop");ADD_ARM_NOP45
#define ADD_ARM_NOP47	__asm__("nop");ADD_ARM_NOP46
#define ADD_ARM_NOP48	__asm__("nop");ADD_ARM_NOP47
#define ADD_ARM_NOP49	__asm__("nop");ADD_ARM_NOP48
#define ADD_ARM_NOP50	__asm__("nop");ADD_ARM_NOP49
#define ADD_ARM_NOP51	__asm__("nop");ADD_ARM_NOP50
#define ADD_ARM_NOP52	__asm__("nop");ADD_ARM_NOP51
#define ADD_ARM_NOP53	__asm__("nop");ADD_ARM_NOP52
#define ADD_ARM_NOP54	__asm__("nop");ADD_ARM_NOP53
#define ADD_ARM_NOP55	__asm__("nop");ADD_ARM_NOP54
#define ADD_ARM_NOP56	__asm__("nop");ADD_ARM_NOP55
#define ADD_ARM_NOP57	__asm__("nop");ADD_ARM_NOP56
#define ADD_ARM_NOP58	__asm__("nop");ADD_ARM_NOP57
#define ADD_ARM_NOP59	__asm__("nop");ADD_ARM_NOP58
#define ADD_ARM_NOP60	__asm__("nop");ADD_ARM_NOP59
#define ADD_ARM_NOP61	__asm__("nop");ADD_ARM_NOP60
#define ADD_ARM_NOP62	__asm__("nop");ADD_ARM_NOP61
#define ADD_ARM_NOP63	__asm__("nop");ADD_ARM_NOP62
#define ADD_ARM_NOP64	__asm__("nop");ADD_ARM_NOP63
#define ADD_ARM_NOP65	__asm__("nop");ADD_ARM_NOP64
#define ADD_ARM_NOP66	__asm__("nop");ADD_ARM_NOP65
#define ADD_ARM_NOP67	__asm__("nop");ADD_ARM_NOP66
#define ADD_ARM_NOP68	__asm__("nop");ADD_ARM_NOP67
#define ADD_ARM_NOP69	__asm__("nop");ADD_ARM_NOP68
#define ADD_ARM_NOP70	__asm__("nop");ADD_ARM_NOP69
#define ADD_ARM_NOP71	__asm__("nop");ADD_ARM_NOP70
#define ADD_ARM_NOP72	__asm__("nop");ADD_ARM_NOP71
#define ADD_ARM_NOP73	__asm__("nop");ADD_ARM_NOP72
#define ADD_ARM_NOP74	__asm__("nop");ADD_ARM_NOP73
#define ADD_ARM_NOP75	__asm__("nop");ADD_ARM_NOP74
#define ADD_ARM_NOP76	__asm__("nop");ADD_ARM_NOP75
#define ADD_ARM_NOP77	__asm__("nop");ADD_ARM_NOP76
#define ADD_ARM_NOP78	__asm__("nop");ADD_ARM_NOP77
#define ADD_ARM_NOP79	__asm__("nop");ADD_ARM_NOP78
#define ADD_ARM_NOP80	__asm__("nop");ADD_ARM_NOP79
#define ADD_ARM_NOP81	__asm__("nop");ADD_ARM_NOP80
#define ADD_ARM_NOP82	__asm__("nop");ADD_ARM_NOP81
#define ADD_ARM_NOP83	__asm__("nop");ADD_ARM_NOP82
#define ADD_ARM_NOP84	__asm__("nop");ADD_ARM_NOP83
#define ADD_ARM_NOP85	__asm__("nop");ADD_ARM_NOP84
#define ADD_ARM_NOP86	__asm__("nop");ADD_ARM_NOP85
#define ADD_ARM_NOP87	__asm__("nop");ADD_ARM_NOP86
#define ADD_ARM_NOP88	__asm__("nop");ADD_ARM_NOP87
#define ADD_ARM_NOP89	__asm__("nop");ADD_ARM_NOP88
#define ADD_ARM_NOP90	__asm__("nop");ADD_ARM_NOP89
#define ADD_ARM_NOP91	__asm__("nop");ADD_ARM_NOP90
#define ADD_ARM_NOP92	__asm__("nop");ADD_ARM_NOP91
#define ADD_ARM_NOP93	__asm__("nop");ADD_ARM_NOP92
#define ADD_ARM_NOP94	__asm__("nop");ADD_ARM_NOP93
#define ADD_ARM_NOP95	__asm__("nop");ADD_ARM_NOP94
#define ADD_ARM_NOP96	__asm__("nop");ADD_ARM_NOP95
#define ADD_ARM_NOP97	__asm__("nop");ADD_ARM_NOP96
#define ADD_ARM_NOP98	__asm__("nop");ADD_ARM_NOP97
#define ADD_ARM_NOP99	__asm__("nop");ADD_ARM_NOP98
#define ADD_ARM_NOP100	__asm__("nop");ADD_ARM_NOP99
#define ADD_ARM_NOP101	__asm__("nop");ADD_ARM_NOP100
#define ADD_ARM_NOP102	__asm__("nop");ADD_ARM_NOP101
#define ADD_ARM_NOP103	__asm__("nop");ADD_ARM_NOP102
#define ADD_ARM_NOP104	__asm__("nop");ADD_ARM_NOP103
#define ADD_ARM_NOP105	__asm__("nop");ADD_ARM_NOP104
#define ADD_ARM_NOP106	__asm__("nop");ADD_ARM_NOP105
#define ADD_ARM_NOP107	__asm__("nop");ADD_ARM_NOP106
#define ADD_ARM_NOP108	__asm__("nop");ADD_ARM_NOP107
#define ADD_ARM_NOP109	__asm__("nop");ADD_ARM_NOP108
#define ADD_ARM_NOP110	__asm__("nop");ADD_ARM_NOP109
#define ADD_ARM_NOP111	__asm__("nop");ADD_ARM_NOP110
#define ADD_ARM_NOP112	__asm__("nop");ADD_ARM_NOP111
#define ADD_ARM_NOP113	__asm__("nop");ADD_ARM_NOP112
#define ADD_ARM_NOP114	__asm__("nop");ADD_ARM_NOP113
#define ADD_ARM_NOP115	__asm__("nop");ADD_ARM_NOP114
#define ADD_ARM_NOP116	__asm__("nop");ADD_ARM_NOP115
#define ADD_ARM_NOP117	__asm__("nop");ADD_ARM_NOP116
#define ADD_ARM_NOP118	__asm__("nop");ADD_ARM_NOP117
#define ADD_ARM_NOP119	__asm__("nop");ADD_ARM_NOP118
#define ADD_ARM_NOP120	__asm__("nop");ADD_ARM_NOP119
#define ADD_ARM_NOP121	__asm__("nop");ADD_ARM_NOP120
#define ADD_ARM_NOP122	__asm__("nop");ADD_ARM_NOP121
#define ADD_ARM_NOP123	__asm__("nop");ADD_ARM_NOP122
#define ADD_ARM_NOP124	__asm__("nop");ADD_ARM_NOP123
#define ADD_ARM_NOP125	__asm__("nop");ADD_ARM_NOP124
#define ADD_ARM_NOP126	__asm__("nop");ADD_ARM_NOP125
#define ADD_ARM_NOP127	__asm__("nop");ADD_ARM_NOP126
#define ADD_ARM_NOP128	__asm__("nop");ADD_ARM_NOP127
#define ADD_ARM_NOP129	__asm__("nop");ADD_ARM_NOP128
#define ADD_ARM_NOP130	__asm__("nop");ADD_ARM_NOP129
#define ADD_ARM_NOP131	__asm__("nop");ADD_ARM_NOP130
#define ADD_ARM_NOP132	__asm__("nop");ADD_ARM_NOP131
#define ADD_ARM_NOP133	__asm__("nop");ADD_ARM_NOP132
#define ADD_ARM_NOP134	__asm__("nop");ADD_ARM_NOP133
#define ADD_ARM_NOP135	__asm__("nop");ADD_ARM_NOP134
#define ADD_ARM_NOP136	__asm__("nop");ADD_ARM_NOP135
#define ADD_ARM_NOP137	__asm__("nop");ADD_ARM_NOP136
#define ADD_ARM_NOP138	__asm__("nop");ADD_ARM_NOP137
#define ADD_ARM_NOP139	__asm__("nop");ADD_ARM_NOP138
#define ADD_ARM_NOP140	__asm__("nop");ADD_ARM_NOP139
#define ADD_ARM_NOP141	__asm__("nop");ADD_ARM_NOP140
#define ADD_ARM_NOP142	__asm__("nop");ADD_ARM_NOP141
#define ADD_ARM_NOP143	__asm__("nop");ADD_ARM_NOP142
#define ADD_ARM_NOP144	__asm__("nop");ADD_ARM_NOP143
#define ADD_ARM_NOP145	__asm__("nop");ADD_ARM_NOP144
#define ADD_ARM_NOP146	__asm__("nop");ADD_ARM_NOP145
#define ADD_ARM_NOP147	__asm__("nop");ADD_ARM_NOP146
#define ADD_ARM_NOP148	__asm__("nop");ADD_ARM_NOP147
#define ADD_ARM_NOP149	__asm__("nop");ADD_ARM_NOP148
#define ADD_ARM_NOP150	__asm__("nop");ADD_ARM_NOP149
#define ADD_ARM_NOP151	__asm__("nop");ADD_ARM_NOP150
#define ADD_ARM_NOP152	__asm__("nop");ADD_ARM_NOP151
#define ADD_ARM_NOP153	__asm__("nop");ADD_ARM_NOP152
#define ADD_ARM_NOP154	__asm__("nop");ADD_ARM_NOP153
#define ADD_ARM_NOP155	__asm__("nop");ADD_ARM_NOP154
#define ADD_ARM_NOP156	__asm__("nop");ADD_ARM_NOP155
#define ADD_ARM_NOP157	__asm__("nop");ADD_ARM_NOP156
#define ADD_ARM_NOP158	__asm__("nop");ADD_ARM_NOP157
#define ADD_ARM_NOP159	__asm__("nop");ADD_ARM_NOP158
#define ADD_ARM_NOP160	__asm__("nop");ADD_ARM_NOP159
#define ADD_ARM_NOP161	__asm__("nop");ADD_ARM_NOP160
#define ADD_ARM_NOP162	__asm__("nop");ADD_ARM_NOP161
#define ADD_ARM_NOP163	__asm__("nop");ADD_ARM_NOP162
#define ADD_ARM_NOP164	__asm__("nop");ADD_ARM_NOP163
#define ADD_ARM_NOP165	__asm__("nop");ADD_ARM_NOP164
#define ADD_ARM_NOP166	__asm__("nop");ADD_ARM_NOP165
#define ADD_ARM_NOP167	__asm__("nop");ADD_ARM_NOP166
#define ADD_ARM_NOP168	__asm__("nop");ADD_ARM_NOP167
#define ADD_ARM_NOP169	__asm__("nop");ADD_ARM_NOP168
#define ADD_ARM_NOP170	__asm__("nop");ADD_ARM_NOP169
#define ADD_ARM_NOP171	__asm__("nop");ADD_ARM_NOP170
#define ADD_ARM_NOP172	__asm__("nop");ADD_ARM_NOP171
#define ADD_ARM_NOP173	__asm__("nop");ADD_ARM_NOP172
#define ADD_ARM_NOP174	__asm__("nop");ADD_ARM_NOP173
#define ADD_ARM_NOP175	__asm__("nop");ADD_ARM_NOP174
#define ADD_ARM_NOP176	__asm__("nop");ADD_ARM_NOP175
#define ADD_ARM_NOP177	__asm__("nop");ADD_ARM_NOP176
#define ADD_ARM_NOP178	__asm__("nop");ADD_ARM_NOP177
#define ADD_ARM_NOP179	__asm__("nop");ADD_ARM_NOP178
#define ADD_ARM_NOP180	__asm__("nop");ADD_ARM_NOP179
#define ADD_ARM_NOP181	__asm__("nop");ADD_ARM_NOP180
#define ADD_ARM_NOP182	__asm__("nop");ADD_ARM_NOP181
#define ADD_ARM_NOP183	__asm__("nop");ADD_ARM_NOP182
#define ADD_ARM_NOP184	__asm__("nop");ADD_ARM_NOP183
#define ADD_ARM_NOP185	__asm__("nop");ADD_ARM_NOP184
#define ADD_ARM_NOP186	__asm__("nop");ADD_ARM_NOP185
#define ADD_ARM_NOP187	__asm__("nop");ADD_ARM_NOP186
#define ADD_ARM_NOP188	__asm__("nop");ADD_ARM_NOP187
#define ADD_ARM_NOP189	__asm__("nop");ADD_ARM_NOP188
#define ADD_ARM_NOP190	__asm__("nop");ADD_ARM_NOP189
#define ADD_ARM_NOP191	__asm__("nop");ADD_ARM_NOP190
#define ADD_ARM_NOP192	__asm__("nop");ADD_ARM_NOP191
#define ADD_ARM_NOP193	__asm__("nop");ADD_ARM_NOP192
#define ADD_ARM_NOP194	__asm__("nop");ADD_ARM_NOP193
#define ADD_ARM_NOP195	__asm__("nop");ADD_ARM_NOP194
#define ADD_ARM_NOP196	__asm__("nop");ADD_ARM_NOP195
#define ADD_ARM_NOP197	__asm__("nop");ADD_ARM_NOP196
#define ADD_ARM_NOP198	__asm__("nop");ADD_ARM_NOP197
#define ADD_ARM_NOP199	__asm__("nop");ADD_ARM_NOP198
#define ADD_ARM_NOP200	__asm__("nop");ADD_ARM_NOP199
#define ADD_ARM_NOP201	__asm__("nop");ADD_ARM_NOP200
#define ADD_ARM_NOP202	__asm__("nop");ADD_ARM_NOP201
#define ADD_ARM_NOP203	__asm__("nop");ADD_ARM_NOP202
#define ADD_ARM_NOP204	__asm__("nop");ADD_ARM_NOP203
#define ADD_ARM_NOP205	__asm__("nop");ADD_ARM_NOP204
#define ADD_ARM_NOP206	__asm__("nop");ADD_ARM_NOP205
#define ADD_ARM_NOP207	__asm__("nop");ADD_ARM_NOP206
#define ADD_ARM_NOP208	__asm__("nop");ADD_ARM_NOP207
#define ADD_ARM_NOP209	__asm__("nop");ADD_ARM_NOP208
#define ADD_ARM_NOP210	__asm__("nop");ADD_ARM_NOP209
#define ADD_ARM_NOP211	__asm__("nop");ADD_ARM_NOP210
#define ADD_ARM_NOP212	__asm__("nop");ADD_ARM_NOP211
#define ADD_ARM_NOP213	__asm__("nop");ADD_ARM_NOP212
#define ADD_ARM_NOP214	__asm__("nop");ADD_ARM_NOP213
#define ADD_ARM_NOP215	__asm__("nop");ADD_ARM_NOP214
#define ADD_ARM_NOP216	__asm__("nop");ADD_ARM_NOP215
#define ADD_ARM_NOP217	__asm__("nop");ADD_ARM_NOP216
#define ADD_ARM_NOP218	__asm__("nop");ADD_ARM_NOP217
#define ADD_ARM_NOP219	__asm__("nop");ADD_ARM_NOP218
#define ADD_ARM_NOP220	__asm__("nop");ADD_ARM_NOP219
#define ADD_ARM_NOP221	__asm__("nop");ADD_ARM_NOP220
#define ADD_ARM_NOP222	__asm__("nop");ADD_ARM_NOP221
#define ADD_ARM_NOP223	__asm__("nop");ADD_ARM_NOP222
#define ADD_ARM_NOP224	__asm__("nop");ADD_ARM_NOP223
#define ADD_ARM_NOP225	__asm__("nop");ADD_ARM_NOP224
#define ADD_ARM_NOP226	__asm__("nop");ADD_ARM_NOP225
#define ADD_ARM_NOP227	__asm__("nop");ADD_ARM_NOP226
#define ADD_ARM_NOP228	__asm__("nop");ADD_ARM_NOP227
#define ADD_ARM_NOP229	__asm__("nop");ADD_ARM_NOP228
#define ADD_ARM_NOP230	__asm__("nop");ADD_ARM_NOP229
#define ADD_ARM_NOP231	__asm__("nop");ADD_ARM_NOP230
#define ADD_ARM_NOP232	__asm__("nop");ADD_ARM_NOP231
#define ADD_ARM_NOP233	__asm__("nop");ADD_ARM_NOP232
#define ADD_ARM_NOP234	__asm__("nop");ADD_ARM_NOP233
#define ADD_ARM_NOP235	__asm__("nop");ADD_ARM_NOP234
#define ADD_ARM_NOP236	__asm__("nop");ADD_ARM_NOP235
#define ADD_ARM_NOP237	__asm__("nop");ADD_ARM_NOP236
#define ADD_ARM_NOP238	__asm__("nop");ADD_ARM_NOP237
#define ADD_ARM_NOP239	__asm__("nop");ADD_ARM_NOP238
#define ADD_ARM_NOP240	__asm__("nop");ADD_ARM_NOP239
#define ADD_ARM_NOP241	__asm__("nop");ADD_ARM_NOP240
#define ADD_ARM_NOP242	__asm__("nop");ADD_ARM_NOP241
#define ADD_ARM_NOP243	__asm__("nop");ADD_ARM_NOP242
#define ADD_ARM_NOP244	__asm__("nop");ADD_ARM_NOP243
#define ADD_ARM_NOP245	__asm__("nop");ADD_ARM_NOP244
#define ADD_ARM_NOP246	__asm__("nop");ADD_ARM_NOP245
#define ADD_ARM_NOP247	__asm__("nop");ADD_ARM_NOP246
#define ADD_ARM_NOP248	__asm__("nop");ADD_ARM_NOP247
#define ADD_ARM_NOP249	__asm__("nop");ADD_ARM_NOP248
#define ADD_ARM_NOP250	__asm__("nop");ADD_ARM_NOP249
#define ADD_ARM_NOP251	__asm__("nop");ADD_ARM_NOP250
#define ADD_ARM_NOP252	__asm__("nop");ADD_ARM_NOP251
#define ADD_ARM_NOP253	__asm__("nop");ADD_ARM_NOP252
#define ADD_ARM_NOP254	__asm__("nop");ADD_ARM_NOP253
#define ADD_ARM_NOP255	__asm__("nop");ADD_ARM_NOP254
#define ADD_ARM_NOP256	__asm__("nop");ADD_ARM_NOP255

#define JOIN(a,b)   a##b
#define ADD_ARM_NOP(n) JOIN(ADD_ARM_NOP,n)
