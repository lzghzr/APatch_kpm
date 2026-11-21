#define CG_JSON_MAX 1536
#define CG_JSON_KEY "\"Cgroups2\""
#define CG_JSON_PATH "/system/etc/cgroups.json"
#define CG_JSON_PATH_OLD "/dev/cg2_bpf"
#define CG_JSON_PATH_NEW "/sys/fs/cgroup"
// struct file 的 f_path 紧跟 f_u 联合体（16 B）之后、struct path 是 {mnt, dentry}，故 dentry 在 +0x18。
// 这是**假设**，由 cg_json_bind_target() 在加载期用两条独立来源交叉验证；不成立就不装钩子。
#define FILE_PATH_DENTRY_OFFSET 0x18

static void* cg_json_dentry;  // 只做指针值比较，从不解引用；init 取得时保留引用，模块生命周期内有效。
static bool cg_json_applied;
static bool cg_json_bound;
static bool cg_json_too_big;

static int cg_find(const char* hay, int hlen, int from, const char* needle) {
  int nlen = (int)strlen(needle);
  for (int i = from; i >= 0 && i + nlen <= hlen; i++)
    if (!memcmp(hay + i, needle, nlen))
      return i;
  return -1;
}

// 从 open 位置的 '{' 起找配对的 '}'，跳过字符串内部的括号；返回 '}' 之后的位置。
static int cg_object_end(const char* buf, int len, int open) {
  int depth = 0;
  bool in_str = false;
  for (int i = open; i < len; i++) {
    char c = buf[i];
    if (in_str) {
      if (c == '\\' && i + 1 < len)
        i++;
      else if (c == '"')
        in_str = false;
      continue;
    }
    if (c == '"')
      in_str = true;
    else if (c == '{')
      depth++;
    else if (c == '}' && --depth == 0)
      return i + 1;
  }
  return -1;
}

// 在 [from,to) 找 "key" : "value"，*vlen 为值的字节长度；返回值起点，没找到返回 -1。
static int cg_field(const char* buf, int from, int to, const char* key, int* vlen) {
  char pat[16];
  int klen = (int)strlen(key);
  if (klen + 3 > (int)sizeof(pat))
    return -1;
  pat[0] = '"';
  memcpy(pat + 1, key, klen);
  pat[klen + 1] = '"';
  pat[klen + 2] = '\0';
  for (int i = cg_find(buf, to, from, pat); i >= 0; i = cg_find(buf, to, i + 1, pat)) {
    int j = i + klen + 2;
    while (j < to && (buf[j] == ' ' || buf[j] == '\t')) j++;
    if (j >= to || buf[j] != ':')
      continue;
    j++;
    while (j < to && (buf[j] == ' ' || buf[j] == '\t')) j++;
    if (j >= to || buf[j] != '"')
      continue;
    int v = ++j;
    while (j < to && buf[j] != '"') j++;
    if (j >= to)
      continue;
    *vlen = j - v;
    return v;
  }
  return -1;
}

// 把 [pos,pos+old_len) 换成 new_val（长度可变），返回新总长；超容量返回 -1。
static int cg_replace(char* buf, int len, int pos, int old_len, const char* new_val) {
  int nlen = (int)strlen(new_val);
  if (len + (nlen - old_len) > CG_JSON_MAX)
    return -1;
  memmove(buf + pos + nlen, buf + pos + old_len, len - (pos + old_len));
  memcpy(buf + pos, new_val, nlen);
  return len + nlen - old_len;
}

// 纯函数（只改 buf）：先确认这是**完整的一份 JSON**（顶层 '{' 的配对 '}' 就是最后一个非空白字节，
// 分块读必然不满足 ⇒ 放行），再把 Cgroups2 的 Path/Mode/UID/GID 改掉。
// 返回补丁后的长度；无需改动或无法安全改写时返回 0（调用方按原样放行）。
static int cg_json_patch(char* buf, int len) {
  if (len <= 0 || len > CG_JSON_MAX)
    return 0;
  int last = len - 1;
  while (last >= 0 && (buf[last] == '\n' || buf[last] == '\r' || buf[last] == ' ' || buf[last] == '\t')) last--;
  if (last < 0 || buf[last] != '}')
    return 0;
  int root = cg_find(buf, last + 1, 0, "{");
  if (root < 0 || cg_object_end(buf, last + 1, root) != last + 1)
    return 0;  // 顶层对象不完整：不是整份文件，别动

  int key = cg_find(buf, last + 1, 0, CG_JSON_KEY);
  if (key < 0)
    return 0;
  int open = cg_find(buf, last + 1, key, "{");
  if (open < 0)
    return 0;
  int end = cg_object_end(buf, last + 1, open);
  if (end < 0)
    return 0;

  bool changed = false;
  int vlen = 0;

  int p = cg_field(buf, open, end, "Path", &vlen);
  if (p > 0 && vlen == (int)sizeof(CG_JSON_PATH_OLD) - 1 && !memcmp(buf + p, CG_JSON_PATH_OLD, vlen)) {
    int n = cg_replace(buf, len, p, vlen, CG_JSON_PATH_NEW);
    if (n < 0)
      return 0;
    end += n - len;
    len = n;
    changed = true;
  }

  p = cg_field(buf, open, end, "Mode", &vlen);
  if (p > 0 && vlen == 4 && !memcmp(buf + p, "0600", 4)) {
    memcpy(buf + p, "0775", 4);
    changed = true;
  }

  const char* keys[2] = {"UID", "GID"};
  for (int i = 0; i < 2; i++) {
    p = cg_field(buf, open, end, keys[i], &vlen);
    if (p > 0 && vlen == 4 && !memcmp(buf + p, "root", 4)) {
      int n = cg_replace(buf, len, p, 4, "system");
      if (n < 0)
        return 0;
      end += n - len;
      len = n;
      changed = true;
    }
  }
  return changed ? len : 0;
}
