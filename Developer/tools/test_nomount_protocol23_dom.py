#!/usr/bin/env python3
"""重放完整 WebUI Oracle，并检查协议兼容状态与实际生成的只读查询。"""
import re
import test_nomount_dev099_dom as oracle

original_fixture = oracle.FIXTURE
oracle.FIXTURE = original_fixture.replace('calls: [],', 'calls: [], driverVersion: "23", apiMode: "api",', 1)
oracle.FIXTURE = oracle.FIXTURE.replace("stdout='6.12.69-android16-6|||fixture|||16|||36|||2.3.0|||22|||api';",
    'stdout=`6.12.69-android16-6|||fixture|||16|||36|||2.3.0|||${fixture.driverVersion}|||${fixture.apiMode}`;')
assert oracle.FIXTURE != original_fixture
extra = r'''
  for(const version of ['22','23']) {
   fixture.driverVersion=version;fixture.apiMode='api';await loadHome();
   await waitFor(()=>getHomeElements().statusLabel.textContent.includes(version)&&getHomeElements().statusCard.classList.contains('active'));
   check(getHomeElements().modeBadge.textContent===translate('mode_connected'),'supported protocol connected');
  }
  fixture.driverVersion='24';fixture.apiMode='incompatible';await loadHome();
  await waitFor(()=>getHomeElements().statusCard.classList.contains('inactive'));
  check(getHomeElements().statusLabel.textContent.includes('24'),'actual incompatible version visible');
  check(getHomeElements().modeBadge.textContent===translate('mode_incompatible'),'incompatible reason visible');
  const queries=fixture.calls.filter(c=>c.includes('uname -r'));
  check(queries.every(c=>c.includes('nm_check_api')&&c.includes('. "$MODDIR/common.sh"')),'real generated queries use common read-only check');
  document.querySelectorAll('.view-content').forEach(e=>e.classList.remove('active'));
  document.getElementById('view-home').classList.add('active');
'''
old = oracle.TEST
marker = "  report.textContent='PASS '+checks"
assert marker in old
oracle.TEST = old.replace(marker, extra + '\n' + marker, 1)
# The complete existing text/DOM/interaction checks remain present, in order.
checks = re.findall(r'\bcheck\([^;]+;', old)
cursor = iter(re.findall(r'\bcheck\([^;]+;', oracle.TEST))
assert all(any(value == candidate for candidate in cursor) for value in checks)

if __name__ == '__main__':
    oracle.main()
