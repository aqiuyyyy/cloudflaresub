// 优选 IP 接口（preferredIpApi）端到端测试：用真实接口地址跑 /api/generate
import assert from 'node:assert/strict';
import worker from '../src/worker.js';

const store = new Map();
const env = {
  SUB_STORE: {
    get: async (k) => store.get(k) ?? null,
    put: async (k, v) => { store.set(k, v); },
  },
};

const vmess = 'vmess://ewogICJ2IjogIjIiLAogICJwcyI6ICJkZW1vLXdzLXRscyIsCiAgImFkZCI6ICJlZGdlLmV4YW1wbGUuY29tIiwKICAicG9ydCI6ICI0NDMiLAogICJpZCI6ICIwMDAwMDAwMC0wMDAwLTQwMDAtODAwMC0wMDAwMDAwMDAwMDEiLAogICJzY3kiOiAiYXV0byIsCiAgIm5ldCI6ICJ3cyIsCiAgInRscyI6ICJ0bHMiLAogICJwYXRoIjogIi93cyIsCiAgImhvc3QiOiAiZWRnZS5leGFtcGxlLmNvbSIsCiAgInNuaSI6ICJlZGdlLmV4YW1wbGUuY29tIiwKICAiZnAiOiAiY2hyb21lIiwKICAiYWxwbiI6ICJoMixodHRwLzEuMSIKfQ==';

async function post(body) {
  const req = new Request('https://sub.example.com/api/generate', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const res = await worker.fetch(req, env);
  return { status: res.status, data: await res.json() };
}

// 1. 只用接口（bestcf 真实地址）
const r1 = await post({ nodeLinks: vmess, preferredIpApi: 'https://bestcf.pages.dev/xinyitang3/ipv4.txt' });
assert.equal(r1.status, 200, JSON.stringify(r1.data));
assert.ok(r1.data.counts.preferredApiEndpoints > 0);
assert.equal(r1.data.counts.outputNodes, r1.data.counts.preferredApiEndpoints);
assert.match(r1.data.preview[0].server, /^\d+\.\d+\.\d+\.\d+$/);
console.log('1 api-only ok: apiEndpoints=', r1.data.counts.preferredApiEndpoints);

// 2. 接口 + 手动合并去重
const firstIp = r1.data.preview[0].server;
const r2 = await post({ nodeLinks: vmess, preferredIpApi: 'https://bestcf.pages.dev/xinyitang3/ipv4.txt', preferredIps: `${firstIp}:443#dup\n1.2.3.4:443#manual` });
assert.equal(r2.status, 200, JSON.stringify(r2.data));
assert.equal(r2.data.counts.preferredEndpoints, r2.data.counts.preferredApiEndpoints + 1);
console.log('2 merge ok: total=', r2.data.counts.preferredEndpoints);

// 3. 090227 接口（含域名行，需被过滤掉）
const r3 = await post({ nodeLinks: vmess, preferredIpApi: 'https://090227.pages.dev/bestcf?isp=all&ips=10' });
assert.equal(r3.status, 200, JSON.stringify(r3.data));
assert.ok(r3.data.counts.preferredApiEndpoints > 0);
assert.ok(r3.data.preview.every((n) => /^\d+\.\d+\.\d+\.\d+$/.test(n.server)));
console.log('3 090227 ok: apiEndpoints=', r3.data.counts.preferredApiEndpoints);

// 4. 坏地址应返回 400
const r4 = await post({ nodeLinks: vmess, preferredIpApi: 'https://127.0.0.1:9/nope' });
assert.equal(r4.status, 400);
console.log('4 bad-url ok:', r4.data.error);

// 5. 什么优选地址都不填应返回 400
const r5 = await post({ nodeLinks: vmess });
assert.equal(r5.status, 400);
console.log('5 empty ok:', r5.data.error);

// 6. 取回订阅 raw，确认能导出
const subRes = await worker.fetch(new Request(`https://sub.example.com/sub/${r1.data.shortId}?target=raw`), env);
assert.equal(subRes.status, 200);
const lines = Buffer.from(await subRes.text(), 'base64').toString('utf8').split('\n').filter((l) => l.startsWith('vmess://'));
assert.equal(lines.length, r1.data.counts.outputNodes);
console.log('6 sub raw ok: lines=', lines.length);

console.log('api-generate test passed');
