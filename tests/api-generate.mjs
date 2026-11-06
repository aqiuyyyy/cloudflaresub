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

// 2. 接口 + 手动合并去重（用接口返回的第一个地址原样拼一行，应去重）
const firstIp = r1.data.preview[0].server;
const firstPort = r1.data.preview[0].port;
const r2 = await post({ nodeLinks: vmess, preferredIpApi: 'https://bestcf.pages.dev/xinyitang3/ipv4.txt', preferredIps: `${firstIp}:${firstPort}#dup\n1.2.3.4:443#manual` });
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

// 11. ss 传统格式：整个 method:password@host:port 做 base64
const ssLegacy = 'ss://' + Buffer.from('aes-256-gcm:testpass123@edge.example.com:8388').toString('base64url') + '#demo-ss';
const r11 = await post({ nodeLinks: ssLegacy, preferredIps: '104.17.149.87' });
assert.equal(r11.status, 200, JSON.stringify(r11.data));
assert.equal(r11.data.counts.outputNodes, 1);
const sub11 = await worker.fetch(new Request(`https://sub.example.com/sub/${r11.data.shortId}?target=raw`), env);
const line11 = Buffer.from(await sub11.text(), 'base64').toString('utf8').trim();
const auth11 = line11.slice('ss://'.length).split('#')[0];
assert.equal(Buffer.from(auth11, 'base64url').toString('utf8'), 'aes-256-gcm:testpass123@104.17.149.87:8388');
assert.ok(line11.endsWith('#demo-ss%20%7C%201'), line11);
console.log('11 ss-legacy ok:', line11);

// 12. ss SIP002 格式，带 plugin：插件要保留，只换服务器
const ssSip002 = 'ss://' + Buffer.from('aes-256-gcm:testpass123').toString('base64url') + '@edge.example.com:8388/?plugin=' + encodeURIComponent('v2ray-plugin;tls;host=example.com') + '#demo-ss-plugin';
const r12 = await post({ nodeLinks: ssSip002, preferredIps: '104.17.149.87' });
assert.equal(r12.status, 200, JSON.stringify(r12.data));
const sub12 = await worker.fetch(new Request(`https://sub.example.com/sub/${r12.data.shortId}?target=raw`), env);
const line12 = Buffer.from(await sub12.text(), 'base64').toString('utf8').trim();
assert.ok(line12.startsWith('ss://'), line12);
assert.ok(line12.includes('@104.17.149.87:8388/'), line12);
assert.ok(line12.includes('plugin='), line12);
assert.ok(decodeURIComponent(line12).includes('v2ray-plugin;tls;host=example.com'), line12);
console.log('12 ss-sip002-plugin ok:', line12);

// 13. 缺密码的 ss 链接应报 400
const ssBad = 'ss://' + Buffer.from('aes-256-gcm:@edge.example.com:8388').toString('base64url') + '#bad-ss';
const r13 = await post({ nodeLinks: ssBad, preferredIps: '104.17.149.87' });
assert.equal(r13.status, 400);
assert.ok(r13.data.error.includes('缺少'), JSON.stringify(r13.data));
console.log('13 ss-no-password ok:', r13.data.error);

// 14. Clash 导出包含 ss 节点
const clash14 = await worker.fetch(new Request(`https://sub.example.com/sub/${r11.data.shortId}?target=clash`), env);
assert.equal(clash14.status, 200);
const clashText = await clash14.text();
assert.ok(clashText.includes('type: ss'), clashText);
assert.ok(clashText.includes('cipher: aes-256-gcm'), clashText);
assert.ok(clashText.includes('password: "testpass123"'), clashText);
console.log('14 ss-clash ok');

// 17. ss 2022-blake3 密钥（含 +/= 特殊字符）原样保留：加密方法和密码必须和原来一样
const blakeKey = 'oL+wQ7vK9JmX2pL4sD8fG6hJ1kN3mP5qR7tV9yB0=';
const ssBlake = 'ss://' + Buffer.from(`2022-blake3-aes-256-gcm:${blakeKey}@edge.example.com:8388`).toString('base64url') + '#demo-ss-blake';
const r17 = await post({ nodeLinks: ssBlake, preferredIps: '104.17.149.87' });
assert.equal(r17.status, 200, JSON.stringify(r17.data));
const sub17 = await worker.fetch(new Request(`https://sub.example.com/sub/${r17.data.shortId}?target=raw`), env);
const line17 = Buffer.from(await sub17.text(), 'base64').toString('utf8').trim();
const auth17 = line17.slice('ss://'.length).split('#')[0];
assert.equal(Buffer.from(auth17, 'base64url').toString('utf8'), `2022-blake3-aes-256-gcm:${blakeKey}@104.17.149.87:8388`);
console.log('17 ss-blake3-key ok:', line17);

// 18. 用户的真实 ss 链接：插件用 ?v2ray-plugin=<base64 JSON> 传（不是 ?plugin=），
// 生成后插件、加密、密码、端口都要和原来一样，只换服务器
const ssReal = 'ss://YWVzLTEyOC1nY206NjQxNGI5NWQ4ZTU0YzRiZGE5ODM3ZmMzYjk3MjcwZmQ4NzFmQHNhYXMuc2luLmZhbjo4MA?v2ray-plugin=eyJwYXRoIjoiXC8iLCJtdXgiOmZhbHNlLCJob3N0IjoiYWVhZC41MjEuZG5zLWR5bmFtaWMubmV0IiwibW9kZSI6IndlYnNvY2tldCJ9#Snippet%E2%80%A2Ss-aead-dynamic';
const r18 = await post({ nodeLinks: ssReal, preferredIps: '104.17.149.87' });
assert.equal(r18.status, 200, JSON.stringify(r18.data));
assert.equal(r18.data.counts.outputNodes, 1);
const sub18 = await worker.fetch(new Request(`https://sub.example.com/sub/${r18.data.shortId}?target=raw`), env);
const line18 = Buffer.from(await sub18.text(), 'base64').toString('utf8').trim();
const auth18 = line18.slice('ss://'.length).split('@')[0];
assert.equal(Buffer.from(auth18, 'base64url').toString('utf8'), 'aes-128-gcm:6414b95d8e54c4bda9837fc3b97270fd871f');
assert.ok(line18.includes('@104.17.149.87:80/'), line18);
assert.ok(line18.includes('v2ray-plugin=eyJwYXRoIjoiXC8iLCJtdXgiOmZhbHNlLCJob3N0IjoiYWVhZC41MjEuZG5zLWR5bmFtaWMubmV0IiwibW9kZSI6IndlYnNvY2tldCJ9'), line18);
assert.ok(line18.includes('#Snippet'), line18);
const clash18 = await worker.fetch(new Request(`https://sub.example.com/sub/${r18.data.shortId}?target=clash`), env);
const clashText18 = await clash18.text();
assert.ok(clashText18.includes('plugin: v2ray-plugin'), clashText18);
assert.ok(clashText18.includes('host: "aead.521.dns-dynamic.net"'), clashText18);
assert.ok(clashText18.includes('mode: "websocket"'), clashText18);
assert.ok(clashText18.includes('cipher: aes-128-gcm'), clashText18);
console.log('18 ss-v2ray-plugin-json ok:', line18);

// 20. 接口地址直接混在优选框里：手动 IP + 接口 URL 一起用，合并去重
const r20 = await post({ nodeLinks: vmess, preferredIps: '192.0.2.1\nhttps://bestcf.pages.dev/xinyitang3/ipv4.txt' });
assert.equal(r20.status, 200, JSON.stringify(r20.data));
assert.ok(r20.data.counts.preferredApiEndpoints > 0);
assert.equal(r20.data.counts.preferredManualEndpoints, 1);
assert.equal(r20.data.counts.preferredEndpoints, r20.data.counts.preferredApiEndpoints + 1);
assert.equal(r20.data.counts.outputNodes, r20.data.counts.preferredEndpoints);
console.log('20 mixed-input ok: total=', r20.data.counts.preferredEndpoints);

// 21. 带查询参数的接口 URL 也能直接粘在优选框里
const r21 = await post({ nodeLinks: vmess, preferredIps: '192.0.2.1\nhttps://090227.pages.dev/bestcf?isp=all&ips=10' });
assert.equal(r21.status, 200, JSON.stringify(r21.data));
assert.ok(r21.data.counts.preferredApiEndpoints > 0);
assert.equal(r21.data.counts.preferredManualEndpoints, 1);
console.log('21 url-with-query ok: apiEndpoints=', r21.data.counts.preferredApiEndpoints);

// 22. 优选框里只有拉取失败的接口地址 → 400
const r22 = await post({ nodeLinks: vmess, preferredIps: 'https://127.0.0.1:9/nope' });
assert.equal(r22.status, 400);
console.log('22 all-urls-fail ok:', r22.data.error);

// 23. 一个接口失败 + 一个手动 IP：照常用手动的，失败的进 warnings
const r23 = await post({ nodeLinks: vmess, preferredIps: '192.0.2.1\nhttps://127.0.0.1:9/nope' });
assert.equal(r23.status, 200, JSON.stringify(r23.data));
assert.equal(r23.data.counts.preferredEndpoints, 1);
assert.ok(r23.data.warnings.some((w) => w.includes('127.0.0.1')), JSON.stringify(r23.data.warnings));
console.log('23 partial-fail ok: warnings=', r23.data.warnings);

// 24. sub:// 订阅器链接：无路径时补 /sub 嗅探参数，拉取订阅里的节点地址
// （订阅内容每次拉取可能轮换，只断言端点数，不断言具体某个地址）
const r24 = await post({ nodeLinks: vmess, preferredIps: '192.0.2.1\nsub://sub.cmliussss.net' });
assert.equal(r24.status, 200, JSON.stringify(r24.data));
assert.ok(r24.data.counts.preferredApiEndpoints >= 1);
assert.equal(r24.data.counts.preferredManualEndpoints, 1);
assert.equal(r24.data.counts.outputNodes, r24.data.counts.preferredEndpoints);
console.log('24 sub-no-path ok: apiEndpoints=', r24.data.counts.preferredApiEndpoints);

// 25. sub:// 带路径和参数时原样拉取
const r25 = await post({ nodeLinks: vmess, preferredIps: 'sub://sub.cmliussss.net/sub?host=example.com&uuid=00000000-0000-4000-8000-000000000000' });
assert.equal(r25.status, 200, JSON.stringify(r25.data));
assert.ok(r25.data.counts.preferredApiEndpoints >= 1);
console.log('25 sub-with-path ok: apiEndpoints=', r25.data.counts.preferredApiEndpoints);

// 26. sub:// 拉到的不是订阅（没有节点地址）→ 400，报错提到订阅
const r26 = await post({ nodeLinks: vmess, preferredIps: 'sub://example.com/' });
assert.equal(r26.status, 400);
assert.match(r26.data.error, /订阅/);
console.log('26 sub-no-nodes ok:', r26.data.error);

console.log('api-generate test passed');
