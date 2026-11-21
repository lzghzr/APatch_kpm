/* Independent fixture driver for the cgroups.json patcher.
 *
 * Functions under test: cg_find / cg_object_end / cg_field / cg_replace /
 * cg_json_patch, copied verbatim (lines 404-544) from the frozen source at
 * 91f44c8 into cg_json_extract.inc.  Nothing from Developer/tools is used and
 * every fixture below was written by the Auditor.
 *
 * Two kinds of cases:
 *   EXPECT  - a behaviour the candidate promises (report claim)
 *   LIMIT   - a behaviour the candidate does not promise; recorded so the
 *             audit can state the real envelope instead of the promised one
 */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cg_json_extract.inc"

static int fails;

static void show(const char *tag, const char *buf, int len) {
  printf("      %s (%d B): ", tag, len);
  for (int i = 0; i < len && i < 220; i++) fputc(buf[i] == '\n' ? '~' : buf[i], stdout);
  if (len > 220) printf("...");
  printf("\n");
}

/* kind: 'P'=expected patched, 'N'=expected passthrough, 'L'=limit observation */
static void run(char kind, const char *name, const char *input, const char *want_substr,
                const char *forbid_substr, const char *note) {
  char buf[CG_JSON_MAX + 32];
  int len = (int)strlen(input);
  if (len > CG_JSON_MAX) {
    printf("SKIP %-34s fixture too large\n", name);
    return;
  }
  memcpy(buf, input, len);
  char orig[CG_JSON_MAX];
  memcpy(orig, buf, len);
  int out = cg_json_patch(buf, len);
  int patched = out > 0;
  int ok = 1;
  if (kind == 'P') ok = patched && out <= CG_JSON_MAX;
  if (kind == 'N') ok = !patched && memcmp(buf, orig, len) == 0;
  if (kind == 'L') ok = 1;
  if (patched) {
    buf[out] = 0;
    if (want_substr && !strstr(buf, want_substr)) ok = 0;
    if (forbid_substr && strstr(buf, forbid_substr)) ok = 0;
  } else if (memcmp(buf, orig, len) != 0) {
    ok = 0; /* fail-open must not touch the caller buffer */
  }
  printf("%s %c %-34s in=%4d out=%4d  %s\n", ok ? "ok  " : "FAIL", kind, name, len, out, note ? note : "");
  if (!ok) {
    fails++;
    show("input", orig, len);
    if (patched) show("output", buf, out);
  } else if (patched) {
    show("output", buf, out);
  }
}

int main(void) {
  const char *cg2 = "\"Cgroups2\":{\"Path\":\"/dev/cg2_bpf\",\"Mode\":\"0600\",\"UID\":\"root\",\"GID\":\"root\"}";

  /* ---- promises -------------------------------------------------------- */
  char nokia[512];
  sprintf(nokia,
          "{\"Cgroups\":[{\"Controller\":\"cpu\",\"Path\":\"/dev/cpuctl\"},"
          "{\"Controller\":\"memory\",\"Path\":\"/dev/memcg\"}],%s}",
          cg2);
  run('P', "01_nokia_baseline", nokia, "\"Path\":\"/sys/fs/cgroup\"", "/dev/cg2_bpf", "Nokia 形态整体改写");
  {
    char buf[CG_JSON_MAX];
    int len = (int)strlen(nokia);
    memcpy(buf, nokia, len);
    int out = cg_json_patch(buf, len);
    buf[out] = 0;
    const char *expect =
        "{\"Cgroups\":[{\"Controller\":\"cpu\",\"Path\":\"/dev/cpuctl\"},"
        "{\"Controller\":\"memory\",\"Path\":\"/dev/memcg\"}],"
        "\"Cgroups2\":{\"Path\":\"/sys/fs/cgroup\",\"Mode\":\"0775\",\"UID\":\"system\",\"GID\":\"system\"}}";
    int same = out == (int)strlen(expect) && memcmp(buf, expect, out) == 0;
    printf("%s   01b_nokia_exact_bytes             out=%d\n", same ? "ok  " : "FAIL", out);
    if (!same) { fails++; show("got", buf, out); show("want", expect, (int)strlen(expect)); }
  }
  run('N', "02_already_target",
      "{\"Cgroups2\":{\"Path\":\"/sys/fs/cgroup\",\"Mode\":\"0775\",\"UID\":\"system\",\"GID\":\"system\"}}", NULL,
      NULL, "已是目标形态：不改、原样放行");
  run('N', "03_no_cgroups2", "{\"Cgroups\":[{\"Path\":\"/dev/cpuctl\"}]}", NULL, NULL, "无 Cgroups2：放行");
  run('N', "04_truncated", "{\"Cgroups2\":{\"Path\":\"/dev/cg2_bpf\",\"Mode\":\"0600\"", NULL, NULL,
      "分块/截断：放行（无日志）");
  run('P', "05_trailing_ws",
      "{\"Cgroups2\":{\"Path\":\"/dev/cg2_bpf\",\"Mode\":\"0600\",\"UID\":\"root\",\"GID\":\"root\"}}\n\r \t",
      "\"Path\":\"/sys/fs/cgroup\"", NULL, "尾部空白可跳过");
  run('P', "06_braces_in_string",
      "{\"Note\":\"a { b } c \\\" d\",\"Cgroups2\":{\"Path\":\"/dev/cg2_bpf\",\"Mode\":\"0600\",\"UID\":\"root\","
      "\"GID\":\"root\",\"Extra\":\"}}\"}}",
      "\"UID\":\"system\"", "/dev/cg2_bpf", "字符串内 { } \\\" 不影响配对");
  run('P', "07_spaces_around_colon",
      "{ \"Cgroups2\" : { \"Path\" : \"/dev/cg2_bpf\" , \"Mode\" : \"0600\" , \"UID\" : \"root\" , \"GID\" : "
      "\"root\" } }",
      "/sys/fs/cgroup", NULL, "空格/制表符可跳过");
  run('P', "08_tab_after_key",
      "{\"Cgroups2\":{\"Path\"\t:\t\"/dev/cg2_bpf\",\"Mode\":\t\"0600\",\"UID\":\t\"root\",\"GID\":\t\"root\"}}",
      "/sys/fs/cgroup", NULL, "制表符可跳过");
  run('P', "09_field_order",
      "{\"Cgroups2\":{\"GID\":\"root\",\"Mode\":\"0600\",\"UID\":\"root\",\"Path\":\"/dev/cg2_bpf\"}}",
      "\"GID\":\"system\"", NULL, "字段顺序无关");
  run('P', "10_v1_untouched",
      "{\"Cgroups2\":{\"Path\":\"/dev/cg2_bpf\",\"Mode\":\"0600\",\"UID\":\"root\",\"GID\":\"root\"},"
      "\"Cgroups\":[{\"Path\":\"/dev/cg2_bpf\",\"Mode\":\"0600\",\"UID\":\"root\",\"GID\":\"root\"}]}",
      "/dev/cg2_bpf\",\"Mode\":\"0600\",\"UID\":\"root\",\"GID\":\"root\"}]", NULL,
      "Cgroups(v1) 条目一字不动");
  run('N', "11_array_root",
      "[{\"Cgroups2\":{\"Path\":\"/dev/cg2_bpf\",\"Mode\":\"0600\",\"UID\":\"root\",\"GID\":\"root\"}}]", NULL,
      NULL, "顶层不是对象：放行");
  run('N', "12_no_closing_brace",
      "{\"Cgroups2\":{\"Path\":\"/dev/cg2_bpf\",\"Mode\":\"0600\",\"UID\":\"root\",\"GID\":\"root\"}", NULL, NULL,
      "末字节不是 }：放行");

  /* ---- envelope limits (not promised, recorded as facts) ---------------- */
  run('L', "L1_newline_before_colon",
      "{\"Cgroups2\":{\"Path\"\n:\"/dev/cg2_bpf\",\"Mode\"\n:\"0600\",\"UID\"\n:\"root\",\"GID\"\n:\"root\"}}", NULL,
      NULL, "键与冒号间换行 => 该字段静默不匹配");
  run('L', "L2_newline_after_colon",
      "{\"Cgroups2\":{\"Path\":\n\"/dev/cg2_bpf\",\"Mode\":\"0600\",\"UID\":\"root\",\"GID\":\"root\"}}", NULL,
      NULL, "冒号与值之间换行 => Path 不匹配，Mode 等仍可改");
  run('L', "L3_pretty_printed",
      "{\n  \"Cgroups2\": {\n    \"Path\":\n      \"/dev/cg2_bpf\",\n    \"Mode\":\n      \"0600\",\n    \"UID\":\n      "
      "\"root\",\n    \"GID\":\n      \"root\"\n  }\n}",
      NULL, NULL, "整份 pretty-print => 全部字段不匹配 => 静默不改");
  run('L', "L4_keyname_as_value_before",
      "{\"A\":{\"X\":1},\"B\":\"Cgroups2\",\"C\":{\"Path\":\"/dev/cg2_bpf\",\"Mode\":\"0600\",\"UID\":\"root\","
      "\"GID\":\"root\"}}",
      NULL, NULL, "值里出现 \"Cgroups2\" => 改写其后第一个对象 C");
  run('L', "L5_duplicate_path",
      "{\"Cgroups2\":{\"Path\":\"/dev/cg2_bpf\",\"Path\":\"/dev/other\",\"Mode\":\"0600\",\"UID\":\"root\","
      "\"GID\":\"root\"}}",
      NULL, NULL, "重复键：只改第一个；JSON 解析器取最后一个");
  run('L', "L6_escaped_quote_in_path",
      "{\"Cgroups2\":{\"Path\":\"/dev/cg2_bpf\\\"\",\"Mode\":\"0600\",\"UID\":\"root\",\"GID\":\"root\"}}", NULL,
      NULL, "值内转义引号：Path 不匹配，其余字段照改");
  run('L', "L7_mode_not_0600",
      "{\"Cgroups2\":{\"Path\":\"/dev/cg2_bpf\",\"Mode\":\"0700\",\"UID\":\"root\",\"GID\":\"root\"}}", NULL, NULL,
      "Mode 不是 0600：Path/UID/GID 照改，Mode 留 0700（日志仍称 0775）");
  run('L', "L8_numeric_uid",
      "{\"Cgroups2\":{\"Path\":\"/dev/cg2_bpf\",\"Mode\":\"0600\",\"UID\":0,\"GID\":0}}", NULL, NULL,
      "UID/GID 非字符串：不匹配");
  run('L', "L9_nested_path_in_cg2",
      "{\"Cgroups2\":{\"Meta\":{\"Path\":\"/dev/cg2_bpf\"},\"Path\":\"/dev/cg2_bpf\",\"Mode\":\"0600\"}}", NULL,
      NULL, "Cgroups2 内嵌对象里的 Path 先被命中");

  /* length boundary: patch needs +7 bytes of room */
  {
    const char *head = "{\"Pad\":\"";
    const char *mid2 =
        "\",\"Cgroups2\":{\"Path\":\"/dev/cg2_bpf\",\"Mode\":\"0600\",\"UID\":\"root\",\"GID\":\"root\"}}";
    char big[CG_JSON_MAX + 1];
    int pad = CG_JSON_MAX - (int)strlen(head) - (int)strlen(mid2);
    int n = 0;
    n += sprintf(big + n, "%s", head);
    memset(big + n, 'x', pad); n += pad;
    n += sprintf(big + n, "%s", mid2);
    printf("     (L10 fixture=%d patched-would-be=%d)\n", n, n + 7);
    run('L', "L10_exactly_1536", big, NULL, NULL, "1536 B + 7 > 1536 => 返回 0（静默）");
    char small[1536];
    int pad2 = 1528 - (int)strlen(head) - (int)strlen(mid2);
    int m = 0;
    m += sprintf(small + m, "%s", head);
    memset(small + m, 'x', pad2); m += pad2;
    m += sprintf(small + m, "%s", mid2);
    printf("     (L11 fixture=%d patched=%d)\n", m, m + 7);
    run('P', "L11_fits_1528", small, "/sys/fs/cgroup", NULL, "1528 B + 7 = 1535 <= 1536 => 改写");
  }

  /* zero-length */
  {
    char z[4] = {0};
    int r = cg_json_patch(z, 0);
    printf("%s L12_len0                            out=%d\n", r == 0 ? "ok  " : "FAIL", r);
    if (r) fails++;
  }

  printf("\n%d failure(s)\n", fails);
  return fails ? 1 : 0;
}
