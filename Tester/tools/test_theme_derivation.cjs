#!/usr/bin/env node
/**
 * Tester fixture: Material You 主题种子色推导与回退逻辑验证
 * 覆盖任务书 A.1 三种输入：
 * 1. 系统返回种子色 -> 期望按种子色生成强调色
 * 2. 系统不返回种子色（老系统/取色失败）-> 期望走回退色，且不报错
 * 3. 二次调用 -> 期望命中缓存（记录系统调用次数为 0）
 */

const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');

const webrootJsPath = path.resolve(__dirname, '../../nomount/upstream/nomount/module/webroot/index.js');
const source = fs.readFileSync(webrootJsPath, 'utf8');

// 提取主题推导核心函数片段 (hexToHSL -> applyAppearance)
const startIdx = source.indexOf('function hexToHSL(');
const endIdx = source.indexOf('// Apply immediately', startIdx);
assert(startIdx > 0 && endIdx > startIdx, 'Failed to extract theme slice from index.js');
const themeCode = source.slice(startIdx, endIdx);

function createThemeSandbox(options = {}) {
    const {
        sdk = 35,
        overlayLookupResult = '#ff5c604d', // 默认返回有效种子色
        failOverlay = false,
        storage = {},
        scheme = 'light',
    } = options;

    let execCallCount = 0;
    const execCalls = [];

    const mockStorage = {
        getItem: (k) => storage[k] !== undefined ? storage[k] : null,
        setItem: (k, v) => { storage[k] = String(v); },
        removeItem: (k) => { delete storage[k]; },
        _store: storage,
    };

    const appliedStyles = {};
    const appliedAttributes = {};

    const mockDocEl = {
        setAttribute: (k, v) => { appliedAttributes[k] = v; },
        getAttribute: (k) => appliedAttributes[k],
        style: {
            setProperty: (k, v) => { appliedStyles[k] = v; },
            removeProperty: (k) => { delete appliedStyles[k]; },
        },
    };

    const mockDoc = {
        documentElement: mockDocEl,
        body: null,
        querySelector: () => null,
    };

    const mockExec = async (cmd) => {
        execCallCount++;
        execCalls.push(cmd);
        if (cmd.includes('ro.build.version.sdk')) {
            return { errno: 0, stdout: String(sdk) + '\n', stderr: '' };
        }
        if (cmd.includes('cmd overlay lookup')) {
            if (failOverlay || !overlayLookupResult) {
                return { errno: 1, stdout: '', stderr: 'lookup failed' };
            }
            return { errno: 0, stdout: overlayLookupResult + '\n', stderr: '' };
        }
        return { errno: 0, stdout: '', stderr: '' };
    };

    const ctx = {
        console,
        setTimeout,
        clearTimeout,
        isMaterial: true,
        activeTheme: scheme,
        customColor: '#6750a4',
        localStorage: mockStorage,
        document: mockDoc,
        getComputedStyle: () => ({ getPropertyValue: () => '' }),
        matchMedia: () => ({ matches: scheme === 'dark', addEventListener: () => {} }),
        exec: mockExec,
    };

    vm.createContext(ctx);
    vm.runInContext(themeCode, ctx);

    return {
        ctx,
        getExecCount: () => execCallCount,
        getExecCalls: () => [...execCalls],
        getStyles: () => ({ ...appliedStyles }),
        getStorage: () => mockStorage._store,
        getSeedState: () => vm.runInContext('({ seed: _nmSeed, source: _nmSeedSource })', ctx),
    };
}

async function runTests() {
    const results = {};

    console.log('--- 测试 1: 系统返回种子色 (#ff5c604d, SDK 35, light 模式) ---');
    {
        const sb = createThemeSandbox({
            sdk: 35,
            overlayLookupResult: '#ff5c604d',
            scheme: 'light'
        });

        // 初始应用
        sb.ctx.applyAppearance();
        // scheduleSystemProbe 是异步的，等待微任务完成
        await new Promise(r => setTimeout(r, 50));

        const styles = sb.getStyles();
        const primary = styles['--md-sys-color-primary'];
        const seedState = sb.getSeedState();
        const seed = seedState.seed;
        const seedSource = seedState.source;
        const cached = sb.getStorage()['nm_seed_cache'];

        console.log(`推导种子色: ${seed} (来源: ${seedSource})`);
        console.log(`生成强调色 (--md-sys-color-primary): ${primary}`);
        console.log(`写入缓存: ${cached}`);
        console.log(`系统调用次数: ${sb.getExecCount()}`);

        assert.equal(seed, '#5c604d');
        assert.equal(seedSource, 'probe');
        assert.equal(primary, '#6b6f5d');
        assert.equal(cached, '#5c604d');
        assert(sb.getExecCount() >= 2, '应当至少调用 getprop 与 cmd overlay lookup');

        results.case1_system_seed = {
            status: 'PASS',
            seed,
            seedSource,
            primaryAccent: primary,
            background: styles['--md-sys-color-background'],
            surfaceContainer: styles['--md-sys-color-surface-container'],
            cached,
            execCalls: sb.getExecCalls()
        };
    }

    console.log('\n--- 测试 2: 系统不返回种子色 (老系统 SDK 28 / 取色失败) -> 回退色且不报错 ---');
    {
        // 场景 2a: 老系统 SDK 28
        const sb28 = createThemeSandbox({ sdk: 28, overlayLookupResult: null, scheme: 'light' });
        sb28.ctx.applyAppearance();
        await new Promise(r => setTimeout(r, 50));

        const styles28 = sb28.getStyles();
        const primary28 = styles28['--md-sys-color-primary'];
        const state28 = sb28.getSeedState();
        const seed28 = state28.seed;
        const source28 = state28.source;

        console.log(`[SDK 28] 种子色: ${seed28} (来源: ${source28})`);
        console.log(`[SDK 28] 强调色: ${primary28}`);
        assert.equal(seed28, '#6750a4');
        assert.equal(source28, 'default');
        assert.equal(primary28, '#594a82');

        // 场景 2b: SDK 35 但 overlay lookup 失败
        const sbFail = createThemeSandbox({ sdk: 35, failOverlay: true, scheme: 'light' });
        sbFail.ctx.applyAppearance();
        await new Promise(r => setTimeout(r, 50));

        const stylesFail = sbFail.getStyles();
        const primaryFail = stylesFail['--md-sys-color-primary'];
        const stateFail = sbFail.getSeedState();
        const seedFail = stateFail.seed;

        console.log(`[Overlay 失败] 种子色: ${seedFail} (来源: ${stateFail.source})`);
        console.log(`[Overlay 失败] 强调色: ${primaryFail}`);
        assert.equal(seedFail, '#6750a4');
        assert.equal(primaryFail, '#594a82');

        results.case2_fallback = {
            status: 'PASS',
            sdk28_seed: seed28,
            sdk28_primary: primary28,
            failOverlay_seed: seedFail,
            failOverlay_primary: primaryFail,
            fallbackHex: '#6750a4'
        };
    }

    console.log('\n--- 测试 3: 二次调用 -> 命中本地缓存 (零系统调用) ---');
    {
        // 预置缓存
        const initialStorage = { 'nm_seed_cache': '#5c604d' };
        const sbCached = createThemeSandbox({
            storage: initialStorage,
            sdk: 35,
            scheme: 'light'
        });

        sbCached.ctx.applyAppearance();
        await new Promise(r => setTimeout(r, 50));

        const stylesCached = sbCached.getStyles();
        const primaryCached = stylesCached['--md-sys-color-primary'];
        const stateCached = sbCached.getSeedState();
        const seedCached = stateCached.seed;
        const sourceCached = stateCached.source;
        const callCount = sbCached.getExecCount();

        console.log(`二次调用命中缓存种子: ${seedCached} (来源: ${sourceCached})`);
        console.log(`生成强调色: ${primaryCached}`);
        console.log(`系统调用次数 (期望为 0): ${callCount}`);

        assert.equal(seedCached, '#5c604d');
        assert.equal(sourceCached, 'cache');
        assert.equal(primaryCached, '#6b6f5d');
        assert.equal(callCount, 0, '命中缓存时不应触发任何系统 exec');

        results.case3_cache_hit = {
            status: 'PASS',
            seed: seedCached,
            source: sourceCached,
            primaryAccent: primaryCached,
            execCallCount: callCount
        };
    }

    console.log('\n================ 所有离线逻辑层夹具验证全部 PASS ================');
    const outJson = JSON.stringify(results, null, 2);
    console.log(outJson);
    return results;
}

runTests().catch(err => {
    console.error('Fixture failed:', err);
    process.exit(1);
});
