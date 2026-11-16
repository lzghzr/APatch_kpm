#!/usr/bin/env python3
"""用隔离 Chromium 和 ZIP 内实际 WebUI 验证名称文本、数据与交互；桥接仅为宿主桩。"""
import argparse
import functools
import http.server
import json
from pathlib import Path
import subprocess
import threading
import time
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = r'''
window.fixture = {calls: [], apps: [], saved: [], blocked: [], disabled: false, injected: 1, toasts: [], moduleFailure: null};
window.attackRan = 0;
window.ksu = {
 toast(msg) { fixture.toasts.push(msg); },
 listPackages() { return JSON.stringify(fixture.apps.map(a => a.packageName)); },
 getPackagesInfo() { return JSON.stringify(fixture.apps); },
 exec(cmd, unused, key) {
  fixture.calls.push(cmd);
  let stdout='', errno=0, stderr='';
  if(cmd.includes('uname -r')) stdout='6.12.69-android16-6|||fixture|||16|||36|||2.3.0|||22|||api';
  else if(cmd.includes('module list')) stdout=JSON.stringify({mods:[{modId:'example',realName:'中文模块 🧩',disable:fixture.disabled,skipMount:false,root:'/data/adb/modules/example',hasInjectable:true,links:[]}],rules:fixture.injected?[{virtual:'/system/a',real:'/data//adb/modules/example/system/a'}]:[],links:[]});
  else if(cmd.includes('module load')) {fixture.injected=1;stderr='nm_load_status=0\n';}
  else if(cmd.includes('module unload')) {fixture.injected=0;stderr='nm_unload_status=0\n';}
  else if(cmd.includes('uid list')) stdout=JSON.stringify(fixture.blocked);
  else if(cmd.includes('uid add')) fixture.blocked.push(cmd.trim().split(/\s+/).pop());
  else if(cmd.includes('uid del')) fixture.blocked=fixture.blocked.filter(uid=>uid!==cmd.trim().split(/\s+/).pop());
  else if(cmd.includes('base64 -d')) fixture.saved=JSON.parse(decodeURIComponent(escape(atob(cmd.match(/echo "([^"]+)"/)[1]))));
  else if(cmd.includes('cat')&&cmd.includes('.exclusion_list.json')) stdout=JSON.stringify(fixture.saved);
  else if(cmd.includes('pm list users')) stdout='UserInfo{0:Owner:13}';
  else if(cmd.includes('pm list packages')) stdout=fixture.apps.map(a=>'package:'+a.packageName+' uid:'+a.uid).join('\n');
  else if(cmd.includes("touch '/data/adb/modules/example/disable'")) fixture.disabled=true;
  else if(cmd.includes("rm -f '/data/adb/modules/example/disable'")) fixture.disabled=false;
  else if(cmd.includes('getprop persist.sys.locale')) stdout='zh-CN';
  if(fixture.moduleFailure&&/module (load|unload)/.test(cmd)){errno=fixture.moduleFailure.errno;stderr=fixture.moduleFailure.stderr;}
  setTimeout(()=>window[key](errno,stdout,stderr),0);
 }
};
localStorage.setItem('nm_language','zh');
'''
TEST = r'''
setTimeout(async () => {
 const report = document.createElement('pre');report.id='dev099-result';document.body.prepend(report);
 let checks=0;
 const check=(ok, message)=>{if(!ok)throw new Error(message);checks++;};
 const textOnly=(node,text)=>{check(node.textContent===text,'text round-trip');check([...node.childNodes].every(n=>n.nodeType===Node.TEXT_NODE),'text nodes only');};
 const waitFor=async fn=>{for(let i=0;i<100&&!fn();i++)await new Promise(requestAnimationFrame);check(fn(),'interaction completed');};
 try {
  const labels=['<','>','&','"',"'",'<img src=x onerror="window.attackRan++">','<script>window.attackRan++<'+ '/script>','" autofocus onfocus="window.attackRan++','中文名称','🧩😃','长'.repeat(4096)];
  for(const label of labels){
   const mod=buildModuleCard({modId:label,realName:label,disable:false,skipMount:false,fileCount:1,statusKey:'status_active'});
   document.getElementById('modules-list').replaceChildren(mod);
   textOnly(mod.querySelector('h3'),label);check(mod.dataset.moduleId===label,'module dataset');
   const exc=buildExclusionCard('10001',{label,pkg:label});
   document.getElementById('exclusions-list').replaceChildren(exc);
   textOnly(exc.querySelector('h3'),label);textOnly(exc.querySelector('p'),label);check(exc.dataset.label===label,'exclusion dataset');
   currentlyDisplayedApps=[{uid:'10001',appLabel:label,packageName:label,isSystem:true,isClone:true,userId:label}];
   appListRenderIndex=0;document.getElementById('app-list-container').replaceChildren();renderNextAppBatch();
   const card=document.querySelector('.app-item');textOnly(card.querySelector('.app-name'),label);textOnly(card.querySelector('.app-pkg'),label);
   check(card.dataset.label===label&&card.dataset.pkg===label,'app datasets');
   for(const parent of [mod,exc,card]){
    check(!parent.querySelector('script'),'no script element');
    check(parent.querySelectorAll('img').length===(parent===mod?0:1),'only intended image');
    check(![parent,...parent.querySelectorAll('*')].some(n=>[...n.attributes].some(a=>/^on/i.test(a.name))),'no event attributes');
   }
  }
  check(window.attackRan===0,'no payload execution');
  fixture.apps=labels.map((appLabel,i)=>({uid:String(10001+i),appLabel,packageName:'test.app'+i,isSystem:false}));
  await ensureAppsCache(true);
  const expected=[...labels].sort((a,b)=>a<b?-1:a>b?1:0);
  check(JSON.stringify(allAppsCache.map(a=>a.appLabel))===JSON.stringify(expected),'original label ordering');
  showSystemApps=true;renderFilteredApps();
  check(JSON.stringify([...document.querySelectorAll('.app-name')].map(n=>n.textContent))===JSON.stringify(expected),'display ordering');
  openAppSelector();
  const selected=document.querySelector('.app-item');const selectedData={uid:selected.dataset.uid,label:selected.dataset.label,pkg:selected.dataset.pkg};
  selected.click();await waitFor(()=>fixture.saved.length===1&&document.querySelector('#exclusions-list .setting-item')?.dataset.uid===selectedData.uid);
  check(JSON.stringify(fixture.saved[0])===JSON.stringify(selectedData),'selection and persisted format');
  document.querySelector('#exclusions-list .btn-delete').click();await waitFor(()=>fixture.saved.length===0&&fixture.blocked.length===0);
  await loadModules();
  let toggle=document.querySelector('#modules-list .switch-input');toggle.click();
  await waitFor(()=>fixture.disabled&&fixture.injected===0&&!document.querySelector('#modules-list [data-busy]'));
  toggle=document.querySelector('#modules-list .switch-input');toggle.click();
  await waitFor(()=>!fixture.disabled&&fixture.injected===1&&!document.querySelector('#modules-list [data-busy]'));
  check(window.attackRan===0,'no payload execution after interactions');
  for(const action of ['load','unload']) {
   const run=action==='load'?loadModule:unloadModule;
   for(const failure of [{errno:1,stderr:`nm_${action}_status=0\n`},{errno:0,stderr:`nm_${action}_status=1\n`},{errno:0,stderr:''}]) {
    fixture.moduleFailure=failure;let failed=false;try{await run('example')}catch(e){failed=true}
    check(failed,'module failure propagated');
   }
   fixture.moduleFailure=null;
   const id="quoted' $(touch /unused)";await run(id);
   const expected="'"+(MOD_DIR+'/'+id).replace(/'/g, "'\\''")+"'";
   check(fixture.calls.at(-1)===`${NM_BIN} module ${action} ${expected}`,'module path shell quoting');
  }
  fixture.injected=1;await loadModules();
  check(document.querySelector('#modules-list .module-card')!==null||document.querySelector('#modules-list .switch-input')!==null,'module restored');
  document.getElementById('view-modules').classList.add('active');
  report.textContent='PASS '+checks+' DOM/text/order/selection/exclusion/module checks';document.title=report.textContent;
 }catch(error){report.textContent='FAIL '+error.stack+' STATE '+JSON.stringify(fixture);document.title='FAIL';}
},1500);
'''


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--zip',required=True,type=Path)
    p.add_argument('--browser',required=True,type=Path)
    p.add_argument('--output',required=True,type=Path)
    args=p.parse_args();out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    with zipfile.ZipFile(args.zip) as z:
        for name in z.namelist():
            if name.startswith('webroot/') and not name.endswith('/'):
                relative=Path(name).relative_to('webroot');assert '..' not in relative.parts
                dest=out/'site'/relative;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(z.read(name))
    site=out/'site';html=(site/'index.html').read_text()
    html=html.replace('<script src="index.js"', '<script src="fixture.js"></script>\n<script src="index.js"')
    (site/'index.html').write_text(html);(site/'fixture.js').write_text(FIXTURE)
    with (site/'index.js').open('a') as f:f.write('\n'+TEST)
    class Quiet(http.server.SimpleHTTPRequestHandler):
        def log_message(self,*args):pass
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),functools.partial(Quiet,directory=str(site)))
    threading.Thread(target=server.serve_forever,daemon=True).start()
    browser_log=(out/'browser.log').open('w')
    process=subprocess.Popen([str(args.browser),'--headless','--disable-gpu','--no-first-run',
        '--disable-background-networking','--disable-component-update','--remote-debugging-port=0',
        '--user-data-dir='+str(out/'profile'),'--window-size=1100,900',
        f'http://127.0.0.1:{server.server_port}/'],stdout=browser_log,stderr=browser_log)
    try:
        port_file=out/'profile'/'DevToolsActivePort'
        for _ in range(100):
            if port_file.exists():break
            if process.poll() is not None:raise RuntimeError('browser exited')
            time.sleep(.1)
        port=port_file.read_text().splitlines()[0]
        with urllib.request.urlopen(f'http://127.0.0.1:{port}/json') as response:
            pages=json.load(response)
        page=next(p for p in pages if p['type']=='page')
        driver=r'''const fs=require('node:fs');
const ws=new WebSocket(process.argv[1]);let seq=0;const pending=new Map();
ws.onmessage=e=>{const data=JSON.parse(e.data);if(data.id){const p=pending.get(data.id);pending.delete(data.id);data.error?p.reject(data.error):p.resolve(data.result)}};
const call=(method,params={})=>new Promise((resolve,reject)=>{const id=++seq;pending.set(id,{resolve,reject});ws.send(JSON.stringify({id,method,params}))});
(async()=>{await new Promise(r=>ws.onopen=r);let result='';
 for(let i=0;i<150;i++){const r=await call('Runtime.evaluate',{expression:"document.getElementById('dev099-result')?.textContent || ''",returnByValue:true});result=r.result.value;if(/^(PASS|FAIL)/.test(result))break;await new Promise(r=>setTimeout(r,100));}
 const dom=await call('Runtime.evaluate',{expression:'document.documentElement.outerHTML',returnByValue:true});fs.writeFileSync(process.argv[2]+'/dom.html',dom.result.value);
 const shot=await call('Page.captureScreenshot');fs.writeFileSync(process.argv[2]+'/render.png',Buffer.from(shot.data,'base64'));
 console.log(result||'FAIL missing browser result');ws.close();
})().catch(e=>{console.error(e);process.exit(1)});
'''
        result=subprocess.run(['node','-e',driver,page['webSocketDebuggerUrl'],str(out)],text=True,capture_output=True,timeout=30)
        (out/'driver.log').write_text(result.stdout+result.stderr);result.check_returncode()
        assert result.stdout.startswith('PASS '),result.stdout
        (out/'result.json').write_text(json.dumps({'result':result.stdout.strip(),'zip':str(args.zip)},ensure_ascii=False,indent=2)+'\n')
        print(result.stdout.strip())
    finally:
        process.terminate()
        try:process.wait(timeout=10)
        except subprocess.TimeoutExpired:process.kill();process.wait()
        browser_log.close();server.shutdown();server.server_close()

if __name__=='__main__':main()
