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

// 3. 090227 接口（含域名行，域名也要保留）
const r3 = await post({ nodeLinks: vmess, preferredIpApi: 'https://090227.pages.dev/bestcf?isp=all&ips=10' });
assert.equal(r3.status, 200, JSON.stringify(r3.data));
assert.ok(r3.data.counts.preferredApiEndpoints > 0);
assert.ok(r3.data.preview.every((n) => /^(\d+\.\d+\.\d+\.\d+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$/.test(n.server)));
assert.ok(r3.data.preview.some((n) => !/^\d+\.\d+\.\d+\.\d+$/.test(n.server)), '应包含域名优选地址');
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

// 7. 缺少 UUID 的 vless 链接应直接报 400，不再静默生成坏节点
const r7 = await post({ nodeLinks: 'vless://162.159.198.1:443?type=tcp&path=%2F%3Fed%3D8192&alpn=h2#vless', preferredIps: '104.17.149.87' });
assert.equal(r7.status, 400);
assert.ok(r7.data.error.includes('缺少 UUID'), JSON.stringify(r7.data));
console.log('7 no-uuid ok:', r7.data.error);

// 8. Shadowrocket 导出的 base64 userinfo 格式 vless 链接（XHTTP，参数是 remarks/obfs/peer 风格）
// 链接里的 :UUID@www.ntu.edu.sg:443 整体被 base64 编码放在 vless:// 后面，不能丢 UUID；
// 输出保持 Shadowrocket 格式（标准链接放不下 mode/obfsParam），只换服务器
const srLink = 'vless://OjkxOWY2Y2JlLTJiYjUtNDRlYS1hYjE4LWIzODYzYTBjMTIyZkB3d3cubnR1LmVkdS5zZzo0NDM?path=/%3Fed%3D8192&remarks=Workers-xhttp&obfsParam=%7B%22%22:%7B%22xPaddingKey%22:%22key%22,%22xPaddingObfsMode%22:true,%22xPaddingHeader%22:%22referer%22,%22xPaddingMethod%22:%22tokenish%22%7D,%22Host%22:%22none.880849.xyz%22%7D&obfs=xhttp&tls=1&peer=none.880849.xyz&alpn=h2&udp=1&mode=stream-one&fingerprint=Chrome';
const r8 = await post({ nodeLinks: srLink, preferredIps: '104.17.149.87' });
assert.equal(r8.status, 200, JSON.stringify(r8.data));
assert.equal(r8.data.counts.outputNodes, 1);
const sub8 = await worker.fetch(new Request(`https://sub.example.com/sub/${r8.data.shortId}?target=raw`), env);
const line8 = Buffer.from(await sub8.text(), 'base64').toString('utf8').trim();
const authority8 = line8.slice('vless://'.length).split('?')[0];
assert.equal(Buffer.from(authority8, 'base64url').toString('utf8'), ':919f6cbe-2bb5-44ea-ab18-b3863a0c122f@104.17.149.87:443');
assert.ok(line8.includes('obfs=xhttp'), line8);
assert.ok(line8.includes('mode=stream-one'), line8);
assert.ok(line8.includes('tls=1'), line8);
assert.ok(line8.includes('peer=none.880849.xyz'), line8);
assert.ok(line8.includes('remarks=Workers-xhttp'), line8);
assert.ok(line8.includes('obfsParam='), line8);
console.log('8 shadowrocket-b64 ok:', line8);

// 10. 标准 vless 链接仍输出标准格式（不混用 Shadowrocket 格式）
const stdLink = 'vless://550e8400-e29b-41d4-a716-446655440000@edge.example.com:443?encryption=none&security=tls&sni=edge.example.com&fp=chrome&type=ws&host=edge.example.com&path=%2Fws#test-node';
const r10 = await post({ nodeLinks: stdLink, preferredIps: '104.17.149.87' });
assert.equal(r10.status, 200, JSON.stringify(r10.data));
const sub10 = await worker.fetch(new Request(`https://sub.example.com/sub/${r10.data.shortId}?target=raw`), env);
const line10 = Buffer.from(await sub10.text(), 'base64').toString('utf8').trim();
assert.ok(line10.startsWith('vless://550e8400-e29b-41d4-a716-446655440000@104.17.149.87:443?'), line10);
assert.ok(line10.includes('type=ws'), line10);
assert.ok(line10.includes('security=tls'), line10);
console.log('10 standard-vless ok:', line10);

// 9. 相同输入再次生成，应覆盖旧订阅内容（不留存坏节点）
// 先生成一次，再把存着的订阅改成坏内容，重新生成后应被新内容覆盖
const r9a = await post({ nodeLinks: srLink, preferredIps: '104.17.149.87' });
assert.equal(r9a.status, 200, JSON.stringify(r9a.data));
store.set(`sub:${r9a.data.shortId}`, JSON.stringify({ version: 1, nodes: [] }));
const r9b = await post({ nodeLinks: srLink, preferredIps: '104.17.149.87' });
assert.equal(r9b.status, 200, JSON.stringify(r9b.data));
assert.equal(r9b.data.shortId, r9a.data.shortId);
assert.equal(r9b.data.deduplicated, true);
const stored9 = JSON.parse(store.get(`sub:${r9a.data.shortId}`));
assert.equal(stored9.nodes.length, 1);
assert.equal(stored9.nodes[0].uuid, '919f6cbe-2bb5-44ea-ab18-b3863a0c122f');
console.log('9 dedup-overwrite ok: shortId=', r9b.data.shortId);

console.log('api-generate test passed');
