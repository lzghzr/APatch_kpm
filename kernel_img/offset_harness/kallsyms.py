"""Parse kallsyms dumps placed next to the images (kernel_img/<major>/<sub>/).

Two textual flavours exist in practice, both carrying addresses relative to
`_text` (i.e. byte offsets into the raw Image file):

  standard:   `0000000000000000 T _text`      (space between type and name)
  glued:      `0000000000000000 T_text`       (no space between type and name)

Optional trailing ` [module]` is stripped. Lookup mirrors kallsyms_lookup_name:
first occurrence in table order wins.
"""


class Kallsyms:
    def __init__(self):
        self.addr_by_name = {}
        self.names_by_addr = {}
        self.order = []  # (addr, type, name) in table order

    def lookup(self, name):
        return self.addr_by_name.get(name)

    @classmethod
    def parse(cls, path):
        ks = cls()
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\r\n")
                if not line:
                    continue
                parts = line.split(None, 1)
                if len(parts) != 2:
                    continue
                try:
                    addr = int(parts[0], 16)
                except ValueError:
                    continue
                rest = parts[1]
                if not rest:
                    continue
                sym_type = rest[0]
                name = rest[1:] if rest[1:2] == " " else rest[1:]
                # strip module suffix " [module]"
                br = name.find(" [")
                if br != -1:
                    name = name[:br]
                name = name.strip()
                if not name:
                    continue
                ks.order.append((addr, sym_type, name))
                # first occurrence wins, like kallsyms_lookup_name
                ks.addr_by_name.setdefault(name, addr)
                ks.names_by_addr.setdefault(addr, []).append(name)
        return ks
