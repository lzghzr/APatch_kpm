#!/usr/bin/env python3
"""Replay WebUI Oracle, whiteout state, quoted marker actions, and Material You sources."""
import re
import test_nomount_protocol23_dom as protocol

oracle = protocol.oracle
oracle.FIXTURE = oracle.FIXTURE.replace('calls: [],', 'calls: [], moduleData: null, monet: "#ff23845c", sdk: "36",', 1)
oracle.FIXTURE = oracle.FIXTURE.replace("else if(cmd.includes('module list'))", "else if(cmd.includes('module list')&&fixture.moduleData) stdout=JSON.stringify(fixture.moduleData);\n  else if(cmd.includes('module list'))", 1)
oracle.FIXTURE = oracle.FIXTURE.replace("else if(cmd.includes('getprop persist.sys.locale'))", "else if(cmd.includes('getprop ro.build.version.sdk')) stdout=fixture.sdk;\n  else if(cmd.includes('cmd overlay lookup')) stdout=fixture.monet;\n  else if(cmd.includes('getprop persist.sys.locale'))", 1)
extra = r'''
  fixture.moduleData={mods:[{modId:'whiteout_only',realName:'纯白化模块',disable:false,skipMount:false,root:MOD_DIR+'/whiteout_only',hasInjectable:true,links:[{virtual:'/system/hidden',real:'',dir:false}]}],rules:[{virtual:'/system/hidden',real:''}]};
  await loadModules();
  check((await readModules())[0].fileCount===1,'whiteout counted');
  check(document.querySelector('#modules-list .status-active')?.textContent===translate('status_active'),'whiteout rendered active');
  check(document.querySelector('#modules-list .files-count-text')?.textContent===translate('modules_injected_files',{count:1}),'whiteout visible count');
  const special="quote' $(touch /unused) ; space";
  fixture.moduleData.mods[0].modId=special;
  const expectedQuote=s=>"'"+s.replace(/'/g,"'\\''")+"'";
  await readModules([special]);
  check(fixture.calls.at(-1)===`${NM_BIN} module list --json --only=${expectedQuote(special)}`,'module filter is one shell argument');
  await loadModules();
  let card=document.querySelector('#modules-list .module-card');
  card.querySelector('.switch-input').click();
  await waitFor(()=>!card.dataset.busy&&fixture.calls.some(c=>c===`touch ${expectedQuote(MOD_DIR+'/'+special+'/disable')}`));
  card.querySelector('.switch-input').click();
  await waitFor(()=>!card.dataset.busy&&fixture.calls.some(c=>c===`rm -f ${expectedQuote(MOD_DIR+'/'+special+'/disable')}`));
  let skip=card.querySelector('.btn-skip-action');skip.click();
  await waitFor(()=>!skip.disabled&&fixture.calls.some(c=>c===`touch ${expectedQuote(MOD_DIR+'/'+special+'/skip_mount')}`));
  fixture.moduleData.mods[0].skipMount=true;await loadModules();
  skip=document.querySelector('#modules-list .btn-skip-action');skip.click();
  await waitFor(()=>!skip.disabled&&fixture.calls.some(c=>c===`rm -f ${expectedQuote(MOD_DIR+'/'+special+'/skip_mount')}`));
  const root=document.documentElement;
  isMaterial=true;_nmSeed=null;root.style.setProperty('--primary','rgb(22, 96, 173)');
  check(getSeedColor()==='#1660ad'&&_nmSeedSource==='manager','Manager CSS seed');applyAppearance();
  check(getComputedStyle(root).getPropertyValue('--md-sys-color-primary').trim()!=='','palette applied');
  root.style.removeProperty('--primary');_nmSeed=null;cacheSeed('#8a4295');
  check(getSeedColor()==='#8a4295'&&_nmSeedSource==='cache','cached seed fallback');
  _nmSeed=null;localStorage.removeItem(NM_SEED_CACHE);
  check(getSeedColor()==='#6750a4'&&_nmSeedSource==='default','default before asynchronous system lookup');
  await waitFor(()=>_nmSeedSource==='probe');
  check(_nmSeed==='#23845c','system ARGB seed lookup');
  fixture.sdk='30';check(await tryGetMonetSeedFromSystem()===null,'pre-Monet device retains fallback');fixture.sdk='36';
  isMaterial=false;customColor='#b34567';check(getSeedColor()===customColor,'custom color remains selectable');
  isMaterial=true;activeTheme='light';applyAppearance();
  fixture.moduleData.mods[0].modId='whiteout_only';fixture.moduleData.mods[0].skipMount=false;
  await loadModules();
  switchToTab('view-modules',false);
  await new Promise(requestAnimationFrame);
  await Promise.all(document.getAnimations().map(a=>a.finished.catch(()=>{})));
  check(getComputedStyle(document.getElementById('view-modules')).opacity==='1','module view finished rendering');
'''
old = oracle.TEST
marker = "  report.textContent='PASS '+checks"
assert marker in old
oracle.TEST = old.replace(marker, extra+'\n'+marker, 1)
checks = re.findall(r'\bcheck\([^;]+;', old)
cursor = iter(re.findall(r'\bcheck\([^;]+;', oracle.TEST))
assert all(any(value == candidate for candidate in cursor) for value in checks)

if __name__ == '__main__':
    oracle.main()
