/* SPDX-License-Identifier: GPL-2.0-or-later */
static void check_target_unchanged(const char* prior) {
  const char* original = "/system/etc/hosts";
  struct filename path = {.name = original};
  hook_fargs3_t args = {.arg1 = (uintptr_t)&path};
  uid = 0;
  do_filp_open_before(&args, NULL);
  assert(path.name == (!strcmp(prior, "disable") ? original : hosts_target));
  do_filp_open_after(&args, NULL);
  assert(path.name == original);
}

static int check_dev062(void) {
  const struct {
    const char* name;
    const char* reason;
  } bad[] = {
      {NULL, "NULL name"},
      {"", "length=0"},
      {".", "dot name"},
      {"..", "slash or dot-dot"},
      {"../test", "slash or dot-dot"},
      {"a/b", "slash or dot-dot"},
      {"/etc/hosts", "slash or dot-dot"},
      {"/", "slash or dot-dot"},
      {"./probe", "slash or dot-dot"},
      {"a/..", "slash or dot-dot"},
      {"a//b", "slash or dot-dot"},
      {"...", "slash or dot-dot"},
      {"a..b", "slash or dot-dot"},
      {" ", "whitespace-only"},
      {"\t", "whitespace-only"},
      {"\r\n", "whitespace-only"},
      {"\v\f", "whitespace-only"},
      {" \t\r\n\v\f ", "whitespace-only"},
      {"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "length=41"},
  };
  const char* prior[] = {"probe", "disable"};
  const int capacities[] = {-1, 0, 8, 9, 64};
  unsigned int cases = 0;
  for (unsigned int p = 0; p < sizeof(prior) / sizeof(prior[0]); p++) {
    for (unsigned int n = 0; n < sizeof(bad) / sizeof(bad[0]); n++) {
      for (unsigned int c = 0; c < sizeof(capacities) / sizeof(capacities[0]); c++) {
        for (int absent = 0; absent < 2; absent++) {
          assert(set_hosts(prior[p]));
          unsigned char snapshot[64], reply[66];
          memcpy(snapshot, hosts_target, sizeof(snapshot));
          memset(reply, 0xa5, sizeof(reply));
          copy_calls = copy_len = 0;
          copy_result = -1;
          hr_log_calls = 0;
          hr_last_log[0] = 0;
          assert(inline_hook_control0(bad[n].name, absent ? NULL : (char*)reply + 1, capacities[c]) == 0);
          assert(!memcmp(snapshot, hosts_target, sizeof(snapshot)));
          assert(hr_log_calls == 1 && strstr(hr_last_log, bad[n].reason) && strstr(hr_last_log, "rule unchanged"));
          int written = !absent && capacities[c] >= 9;
          assert(copy_calls == written);
          if (written) {
            assert(copy_len == 9);
            assert(!memcmp(reply + 1, "_(x_x)_\n", 9));
          }
          for (unsigned int i = 0; i < sizeof(reply); i++)
            if (!written || i < 1 || i > 9)
              assert(reply[i] == 0xa5);
          check_target_unchanged(prior[p]);
          cases++;
        }
      }
    }
  }
  const char* good[] = {"a",       "adblock",     "hosts.txt",
                        ".hidden", "rule-name_1", "rule name",
                        "规则",    "disable",     "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"};
  for (unsigned int i = 0; i < sizeof(good) / sizeof(good[0]); i++) {
    char reply[9] = {0};
    assert(!inline_hook_control0(good[i], reply, sizeof(reply)));
    assert(!strcmp(reply, "_(._.)_\n"));
    assert(!strncmp(hosts_target, "/data/adb/hosts/", 16));
    assert(!strcmp(hosts_target + 16, good[i]) && strlen(hosts_target) == 16 + strlen(good[i]));
    check_target_unchanged(good[i]);
  }
  printf("DEV-062: %u rejected ctl0/state/buffer/log cases; %zu valid filename cases PASS\n", cases,
         sizeof(good) / sizeof(good[0]));
  return cases;
}

int main(void) {
  assert(!original_contract());
  assert(check_dev062() == 380);
  return 0;
}
