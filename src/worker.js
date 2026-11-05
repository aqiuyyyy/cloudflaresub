// Cloudflare Worker: KV short link subscription + access token protection
// Requires:
// - KV namespace binding: SUB_STORE
// - Secret/Variable: SUB_ACCESS_TOKEN
// Optional:
// - Secret/Variable: SUB_LINK_SECRET (legacy long-token compatibility)

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'GET,POST,OPTIONS',
      'access-control-allow-headers': 'content-type',
    },
  });
}

function text(body, status = 200, contentType = 'text/plain; charset=utf-8') {
  return new Response(body, {
    status,
    headers: {
      'content-type': contentType,
      'access-control-allow-origin': '*',
    },
  });
}

function b64EncodeUtf8(str) {
  return btoa(unescape(encodeURIComponent(str)));
}

function b64DecodeUtf8(str) {
  return decodeURIComponent(escape(atob(str)));
}

function escapeYaml(str = '') {
  return String(str)
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"')
    .replace(/\n/g, ' ');
}

function parsePreferredEndpoints(input) {
  return String(input || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const [raw, remark = ''] = line.split('#');
      const value = raw.trim();
      const hashRemark = remark.trim();
      const match = value.match(/^(.*?)(?::(\d+))?$/);
      return {
        server: match?.[1] || value,
        port: match?.[2] ? Number(match[2]) : undefined,
        remark: hashRemark,
      };
    });
}

function isValidIPv4(value = '') {
  const parts = String(value).split('.');
  if (parts.length !== 4) return false;
  return parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

function isValidHostname(value = '') {
  return /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$/.test(
    value
  );
}

// 从优选 IP 接口拉取地址列表：接口返回每行一个 IP/域名[:端口][#备注] 的文本，
// 只保留合法 IPv4 或域名（过滤掉注释行等），去重后返回。
async function fetchPreferredEndpointsFromApi(apiUrl) {
  let parsed;
  try {
    parsed = new URL(String(apiUrl).trim());
  } catch {
    throw new Error('优选 IP 接口地址不是合法 URL');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('优选 IP 接口地址只支持 http(s)');
  }

  let resp;
  try {
    resp = await fetch(parsed.toString(), { signal: AbortSignal.timeout(10000) });
  } catch (e) {
    throw new Error(
      `优选 IP 接口拉取失败: ${e.name === 'TimeoutError' ? '超时 10 秒' : e.message}`
    );
  }
  if (!resp.ok) {
    throw new Error(`优选 IP 接口返回 HTTP ${resp.status}`);
  }

  const endpoints = parsePreferredEndpoints(await resp.text()).filter(
    (ep) => isValidIPv4(ep.server) || isValidHostname(ep.server)
  );

  const seen = new Set();
  const deduped = [];
  for (const ep of endpoints) {
    const key = `${ep.server}:${ep.port || ''}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(ep);
  }

  if (!deduped.length) {
    throw new Error('优选 IP 接口里没有解析到可用地址');
  }
  return deduped;
}

function parseVmess(link) {
  const raw = link.slice('vmess://'.length).trim();
  const obj = JSON.parse(b64DecodeUtf8(raw));
  if (!obj.id) {
    throw new Error(
      `节点「${obj.ps || 'vmess'}」缺少 UUID：请粘贴完整的 vmess 链接`
    );
  }
  return {
    type: 'vmess',
    name: obj.ps || 'vmess',
    server: obj.add,
    port: Number(obj.port || 443),
    uuid: obj.id,
    cipher: obj.scy || 'auto',
    network: obj.net || 'ws',
    tls: obj.tls === 'tls',
    host: obj.host || '',
    path: obj.path || '/',
    sni: obj.sni || obj.host || '',
    alpn: obj.alpn || '',
    fp: obj.fp || '',
  };
}

// Shadowrocket 等客户端导出的 vless 链接会把整个 :UUID@域名:端口 做 base64，
// 放在 vless:// 后面（不含 @），例如：
// vless://OjkxOWY2Y2JlLTJiYjUtNDRlYS1hYjE4LWIzODYzYTBjMTIyZkB3d3cubnR1LmVkdS5zZzo0NDM?…
// 解码后是 :919f6cbe-2bb5-44ea-ab18-b3863a0c122f@www.ntu.edu.sg:443
function decodeB64Authority(authority) {
  try {
    const padded = authority + '='.repeat((4 - (authority.length % 4)) % 4);
    const decoded = b64DecodeUtf8(padded);
    const m = decoded.match(/^:?([^@]+)@([^:]+):(\d+)$/);
    if (m) return { uuid: m[1], server: m[2], port: Number(m[3]) };
  } catch {}
  return null;
}

function parseUrlLike(link, type) {
  // 先看是不是 base64 形式的 userinfo：是的话先还原成标准形式再解析，
  // 否则 new URL() 会把整段 base64 当成 hostname（还会小写化，无法还原）
  let effectiveLink = link;
  let b64Userinfo = false;
  if (type === 'vless') {
    const authority = link.slice(`${type}://`.length).split(/[/?#]/)[0];
    if (authority && !authority.includes('@')) {
      const decoded = decodeB64Authority(authority);
      if (decoded) {
        b64Userinfo = true;
        const rest = link.slice(link.indexOf(authority) + authority.length);
        effectiveLink = `${type}://${decoded.uuid}@${decoded.server}:${decoded.port}${rest}`;
      }
    }
  }
  const u = new URL(effectiveLink);
  const params = u.searchParams;
  // 有的客户端只把 UUID 单独做 base64 放在用户名位置
  let username = decodeURIComponent(u.username || '');
  if (type === 'vless' && username && !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(username)) {
    try {
      const padded = username + '='.repeat((4 - (username.length % 4)) % 4);
      const decoded = b64DecodeUtf8(padded);
      if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(decoded)) {
        username = decoded;
        b64Userinfo = true;
      }
    } catch {}
  }
  // Shadowrocket 风格参数：obfsParam 里的 Host 是 XHTTP 的 Host 头
  let obfsHost = '';
  try {
    const obfsParam = params.get('obfsParam');
    if (obfsParam) obfsHost = JSON.parse(obfsParam).Host || '';
  } catch {}
  const node = {
    type,
    name:
      decodeURIComponent(u.hash.replace(/^#/, '')) ||
      params.get('remarks') ||
      type,
    server: u.hostname,
    port: Number(u.port || 443),
    password: type === 'trojan' ? username : undefined,
    uuid: type === 'vless' ? username : undefined,
    // 标准参数 type/security/sni/fp 之外，再认 Shadowrocket 的 obfs/tls/peer/fingerprint
    network: params.get('type') || params.get('obfs') || 'tcp',
    tls:
      (params.get('security') || '').toLowerCase() === 'tls' ||
      params.get('tls') === '1',
    host: params.get('host') || params.get('sni') || obfsHost || '',
    path: params.get('path') || '/',
    sni:
      params.get('sni') ||
      params.get('peer') ||
      params.get('host') ||
      obfsHost ||
      '',
    fp: params.get('fp') || params.get('fingerprint') || '',
    alpn: params.get('alpn') || '',
    flow: params.get('flow') || '',
    // 原链接是 Shadowrocket 格式（base64 userinfo，或 obfs/remarks/peer 等参数）时，
    // 输出也保持 Shadowrocket 格式：标准 vless 链接放不下 mode/obfsParam 这些参数，
    // 转标准格式会丢配置，节点行为就和原来不一样了
    inputFormat:
      b64Userinfo ||
      params.has('obfs') ||
      params.has('remarks') ||
      params.has('peer') ||
      params.has('fingerprint') ||
      params.has('obfsParam') ||
      params.has('mode')
        ? 'shadowrocket'
        : 'standard',
    srExtra: {
      mode: params.get('mode') || '',
      udp: params.get('udp') || '',
      obfsParam: params.get('obfsParam') || '',
    },
  };
  if (type === 'vless' && !node.uuid) {
    throw new Error(
      `节点「${node.name}」缺少 UUID：请粘贴完整的 vless 链接（形如 vless://UUID@域名:端口?...），不要只复制一部分`
    );
  }
  if (type === 'trojan' && !node.password) {
    throw new Error(
      `节点「${node.name}」缺少密码：请粘贴完整的 trojan 链接（形如 trojan://密码@域名:端口?...）`
    );
  }
  return node;
}

function parseRawLinks(input) {
  const lines = String(input || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  const result = [];
  for (const line of lines) {
    if (line.startsWith('vmess://')) {
      result.push(parseVmess(line));
      continue;
    }
    if (line.startsWith('vless://')) {
      result.push(parseUrlLike(line, 'vless'));
      continue;
    }
    if (line.startsWith('trojan://')) {
      result.push(parseUrlLike(line, 'trojan'));
      continue;
    }
    try {
      const decoded = b64DecodeUtf8(line);
      if (/^(vmess|vless|trojan):\/\//m.test(decoded)) {
        result.push(...parseRawLinks(decoded));
      }
    } catch {}
  }
  return result;
}

function buildNodes(baseNodes, preferredEndpoints, options = {}) {
  const output = [];
  const prefix = (options.namePrefix || '').trim();
  let counter = 0;
  for (const node of baseNodes) {
    for (const ep of preferredEndpoints) {
      counter += 1;
      const nameParts = [];
      if (node.name) nameParts.push(node.name);
      if (prefix) nameParts.push(prefix);
      if (ep.remark) nameParts.push(ep.remark);
      else nameParts.push(String(counter));
      output.push({
        ...node,
        name: nameParts.join(' | '),
        server: ep.server,
        port: ep.port || node.port,
        host: options.keepOriginalHost ? node.host : '',
        sni: options.keepOriginalHost ? node.sni : '',
      });
    }
  }
  return output;
}

function encodeVmess(node) {
  const obj = {
    v: '2',
    ps: node.name,
    add: node.server,
    port: String(node.port),
    id: node.uuid,
    aid: '0',
    scy: node.cipher || 'auto',
    net: node.network || 'ws',
    type: 'none',
    host: node.host || '',
    path: node.path || '/',
    tls: node.tls ? 'tls' : '',
    sni: node.sni || '',
    alpn: node.alpn || '',
    fp: node.fp || '',
  };
  return 'vmess://' + b64EncodeUtf8(JSON.stringify(obj));
}

function encodeVless(node) {
  if (node.inputFormat === 'shadowrocket') return encodeVlessShadowrocket(node);
  const url = new URL(`vless://${encodeURIComponent(node.uuid)}@${node.server}:${node.port}`);
  url.searchParams.set('type', node.network || 'ws');
  if (node.tls) url.searchParams.set('security', 'tls');
  if (node.host) url.searchParams.set('host', node.host);
  if (node.sni) url.searchParams.set('sni', node.sni);
  if (node.path) url.searchParams.set('path', node.path);
  if (node.alpn) url.searchParams.set('alpn', node.alpn);
  if (node.fp) url.searchParams.set('fp', node.fp);
  if (node.flow) url.searchParams.set('flow', node.flow);
  url.hash = node.name;
  return url.toString();
}

// Shadowrocket 格式：整个 :UUID@域名:端口 做 base64url（无填充）放在 vless:// 后面，
// 参数用 remarks/obfs/obfsParam/tls/peer/mode/fingerprint 这一套。
// 注意不能用 new URL() 拼 authority，WHATWG URL 会把 host 小写化，base64 会被破坏。
function encodeVlessShadowrocket(node) {
  const authority = b64EncodeUtf8(`:${node.uuid}@${node.server}:${node.port}`)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  const parts = [];
  const set = (k, v) => {
    if (v !== undefined && v !== null && v !== '') parts.push(`${k}=${encodeURIComponent(v)}`);
  };
  set('path', node.path);
  set('remarks', node.name);
  set('obfsParam', node.srExtra?.obfsParam);
  set('obfs', node.network || 'xhttp');
  if (node.tls) set('tls', '1');
  set('peer', node.sni);
  set('alpn', node.alpn);
  set('udp', node.srExtra?.udp);
  set('mode', node.srExtra?.mode);
  set('fingerprint', node.fp);
  return `vless://${authority}?${parts.join('&')}`;
}

function encodeTrojan(node) {
  const url = new URL(`trojan://${encodeURIComponent(node.password)}@${node.server}:${node.port}`);
  if (node.network) url.searchParams.set('type', node.network);
  if (node.tls) url.searchParams.set('security', 'tls');
  if (node.host) url.searchParams.set('host', node.host);
  if (node.sni) url.searchParams.set('sni', node.sni);
  if (node.path) url.searchParams.set('path', node.path);
  if (node.alpn) url.searchParams.set('alpn', node.alpn);
  if (node.fp) url.searchParams.set('fp', node.fp);
  url.hash = node.name;
  return url.toString();
}

function renderRaw(nodes) {
  const lines = nodes
    .map((node) => {
      if (node.type === 'vmess') return encodeVmess(node);
      if (node.type === 'vless') return encodeVless(node);
      if (node.type === 'trojan') return encodeTrojan(node);
      return '';
    })
    .filter(Boolean);
  return b64EncodeUtf8(lines.join('\n'));
}

function renderClash(nodes) {
  const proxies = nodes
    .map((node) => {
      if (node.type === 'vmess') {
        const lines = [
          `  - name: "${escapeYaml(node.name)}"`,
          `    type: vmess`,
          `    server: ${node.server}`,
          `    port: ${node.port}`,
          `    uuid: ${node.uuid}`,
          `    alterId: 0`,
          `    cipher: ${node.cipher || 'auto'}`,
          `    udp: true`,
          `    tls: ${node.tls ? 'true' : 'false'}`,
          `    network: ${node.network || 'ws'}`,
        ];

        if (node.sni) {
          lines.push(`    servername: "${escapeYaml(node.sni)}"`);
        }

        if ((node.network || 'ws') === 'ws') {
          lines.push(
            `    ws-opts:`,
            `      path: "${escapeYaml(node.path || '/')}"`,
            `      headers:`,
            `        Host: "${escapeYaml(node.host || node.sni || '')}"`
          );
        }

        return lines.join('\n');
      }

      if (node.type === 'vless') {
        const lines = [
          `  - name: "${escapeYaml(node.name)}"`,
          `    type: vless`,
          `    server: ${node.server}`,
          `    port: ${node.port}`,
          `    uuid: ${node.uuid}`,
          `    udp: true`,
          `    tls: ${node.tls ? 'true' : 'false'}`,
          `    network: ${node.network || 'ws'}`,
        ];

        if (node.sni) {
          lines.push(`    servername: "${escapeYaml(node.sni)}"`);
        }

        if ((node.network || 'ws') === 'ws') {
          lines.push(
            `    ws-opts:`,
            `      path: "${escapeYaml(node.path || '/')}"`,
            `      headers:`,
            `        Host: "${escapeYaml(node.host || node.sni || '')}"`
          );
        }

        return lines.join('\n');
      }

      if (node.type === 'trojan') {
        const lines = [
          `  - name: "${escapeYaml(node.name)}"`,
          `    type: trojan`,
          `    server: ${node.server}`,
          `    port: ${node.port}`,
          `    password: "${escapeYaml(node.password || '')}"`,
          `    udp: true`,
        ];

        if (node.sni) {
          lines.push(`    sni: "${escapeYaml(node.sni)}"`);
        }

        if (node.tls !== false) {
          lines.push(`    tls: true`);
        }

        if (node.network) {
          lines.push(`    network: ${node.network}`);
        }

        if (node.network === 'ws') {
          lines.push(
            `    ws-opts:`,
            `      path: "${escapeYaml(node.path || '/')}"`,
            `      headers:`,
            `        Host: "${escapeYaml(node.host || node.sni || '')}"`
          );
        }

        return lines.join('\n');
      }

      return '';
    })
    .filter(Boolean);

  const proxyNames = nodes.map(
    (node) => `      - "${escapeYaml(node.name)}"`
  );

  const allGroupMembers = [
    `      - "自动选择"`,
    ...proxyNames,
    `      - DIRECT`,
  ];

  const autoGroupMembers = proxyNames.length ? proxyNames : [`      - DIRECT`];

  return [
    `mixed-port: 7890`,
    `allow-lan: false`,
    `mode: rule`,
    `log-level: info`,
    `ipv6: true`,
    ``,
    `proxies:`,
    ...(proxies.length ? proxies : []),
    ``,
    `proxy-groups:`,
    `  - name: "自动选择"`,
    `    type: url-test`,
    `    url: "http://www.gstatic.com/generate_204"`,
    `    interval: 300`,
    `    tolerance: 50`,
    `    proxies:`,
    ...autoGroupMembers,
    ``,
    `  - name: "节点选择"`,
    `    type: select`,
    `    proxies:`,
    ...allGroupMembers,
    ``,
    `rules:`,
    `  - MATCH,节点选择`,
  ].join('\n');
}

function renderSurge(nodes, baseUrl, accessToken) {
  const proxies = nodes
    .filter((node) => node.type === 'vmess' || node.type === 'trojan')
    .map((node) => {
      if (node.type === 'vmess') {
        return `${node.name} = vmess, ${node.server}, ${node.port}, username=${node.uuid}, ws=true, ws-path=${node.path || '/'}, ws-headers=Host:${node.host || ''}, tls=${node.tls ? 'true' : 'false'}, sni=${node.sni || ''}`;
      }
      return `${node.name} = trojan, ${node.server}, ${node.port}, password=${node.password || ''}, sni=${node.sni || ''}`;
    });

  return [
    '[General]',
    'skip-proxy = 127.0.0.1, localhost',
    '',
    '[Proxy]',
    ...proxies,
    '',
    '[Proxy Group]',
    'Proxy = select, ' +
      nodes
        .filter((n) => n.type === 'vmess' || n.type === 'trojan')
        .map((n) => n.name)
        .join(', '),
    '',
    '[Rule]',
    'FINAL,Proxy',
    '',
    '; token-protected subscription',
    `; ${baseUrl}?token=${accessToken}`,
  ].join('\n');
}

function createShortId(length = 10) {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  let out = '';
  for (let i = 0; i < length; i++) {
    out += chars[bytes[i] % chars.length];
  }
  return out;
}

async function createUniqueShortId(env, tries = 8) {
  for (let i = 0; i < tries; i++) {
    const id = createShortId(10);
    const exists = await env.SUB_STORE.get(`sub:${id}`);
    if (!exists) return id;
  }
  throw new Error('无法生成唯一短链接，请稍后再试');
}

function normalizeLines(value = '') {
  return String(value)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .sort()
    .join('\n');
}

async function sha256Hex(input) {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

async function buildDedupHash(body) {
  const normalized = {
    nodeLinks: normalizeLines(body.nodeLinks || ''),
    preferredIps: normalizeLines(body.preferredIps || ''),
    preferredIpApi: String(body.preferredIpApi || body.preferredApiUrl || '').trim(),
    namePrefix: String(body.namePrefix || '').trim(),
    keepOriginalHost: body.keepOriginalHost !== false,
  };
  return sha256Hex(JSON.stringify(normalized));
}

async function handleGenerate(request, env, url) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: '请求体不是合法 JSON' }, 400);
  }

  let baseNodes;
  try {
    baseNodes = parseRawLinks(body.nodeLinks || '');
  } catch (e) {
    return json({ ok: false, error: e.message }, 400);
  }
  if (!baseNodes.length) return json({ ok: false, error: '没有识别到可用节点' }, 400);

  // 优选地址来源二选一或两者合并：接口拉取 + 手动粘贴，去重后使用
  const preferredIpApi = String(body.preferredIpApi || body.preferredApiUrl || '').trim();
  let apiEndpoints = [];
  if (preferredIpApi) {
    try {
      apiEndpoints = await fetchPreferredEndpointsFromApi(preferredIpApi);
    } catch (e) {
      return json({ ok: false, error: e.message }, 400);
    }
  }

  const manualEndpoints = parsePreferredEndpoints(body.preferredIps || '');
  const seenEndpoints = new Set();
  const preferredEndpoints = [];
  for (const ep of [...apiEndpoints, ...manualEndpoints]) {
    const key = `${ep.server}:${ep.port || ''}`;
    if (seenEndpoints.has(key)) continue;
    seenEndpoints.add(key);
    preferredEndpoints.push(ep);
  }

  if (!preferredEndpoints.length) return json({ ok: false, error: '没有识别到可用优选地址' }, 400);

  const options = {
    namePrefix: body.namePrefix || '',
    keepOriginalHost: body.keepOriginalHost !== false,
    preferredIpApi,
  };

  const nodes = buildNodes(baseNodes, preferredEndpoints, options);

  const payload = {
    version: 2,
    createdAt: new Date().toISOString(),
    options,
    nodes,
  };

  const dedupHash = await buildDedupHash(body);
  const dedupKey = `dedup:${dedupHash}`;

  let id = await env.SUB_STORE.get(dedupKey);
  const deduplicated = !!id;
  const ttl = 60 * 60 * 24 * 7; // 7天
  if (!id) {
    id = await createUniqueShortId(env);
    await env.SUB_STORE.put(dedupKey, id, {
      expirationTtl: ttl,
    });
  }
  // 相同输入再次生成时，用新算出的内容覆盖旧订阅：解析规则修过之后，
  // 旧订阅里可能还存着坏节点（比如缺 UUID 的），不覆盖就永远修不好
  await env.SUB_STORE.put(`sub:${id}`, JSON.stringify(payload), {
    expirationTtl: ttl,
  });

  const origin = url.origin;
  const accessToken = env.SUB_ACCESS_TOKEN || '';
  const withToken = (target) =>
    `${origin}/sub/${id}${
      target
        ? `?target=${target}&token=${encodeURIComponent(accessToken)}`
        : `?token=${encodeURIComponent(accessToken)}`
    }`;

  return json({
    ok: true,
    storage: 'kv',
    deduplicated,
    shortId: id,
    urls: {
      auto: withToken(''),
      raw: withToken('raw'),
      clash: withToken('clash'),
      surge: withToken('surge'),
    },
    counts: {
      inputNodes: baseNodes.length,
      preferredEndpoints: preferredEndpoints.length,
      preferredApiEndpoints: apiEndpoints.length,
      preferredManualEndpoints: manualEndpoints.length,
      outputNodes: nodes.length,
    },
    preview: nodes.slice(0, 20).map((node) => ({
      name: node.name,
      type: node.type,
      server: node.server,
      port: node.port,
      host: node.host || '',
      sni: node.sni || '',
    })),
    warnings: accessToken ? [] : ['未检测到 SUB_ACCESS_TOKEN，订阅链接将没有第二层访问保护。'],
  });
}

function validateAccessToken(url, env) {
  const expected = env.SUB_ACCESS_TOKEN;
  if (!expected) return { ok: true };
  const provided = url.searchParams.get('token') || '';
  if (!provided || provided !== expected) {
    return { ok: false, response: text('Forbidden: invalid token', 403) };
  }
  return { ok: true };
}

async function handleSub(url, env) {
  const tokenCheck = validateAccessToken(url, env);
  if (!tokenCheck.ok) return tokenCheck.response;

  const id = url.pathname.split('/').pop();
  if (!id) return text('missing id', 400);

  const raw = await env.SUB_STORE.get(`sub:${id}`);
  if (!raw) return text('not found', 404);

  const record = JSON.parse(raw);
  const nodes = record.nodes || [];
  const target = (url.searchParams.get('target') || 'raw').toLowerCase();

  if (target === 'clash') {
    return text(renderClash(nodes), 200, 'text/yaml; charset=utf-8');
  }
  if (target === 'surge') {
    return text(
      renderSurge(nodes, url.origin + url.pathname, env.SUB_ACCESS_TOKEN || ''),
      200,
      'text/plain; charset=utf-8',
    );
  }
  return text(renderRaw(nodes), 200, 'text/plain; charset=utf-8');
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'access-control-allow-origin': '*',
          'access-control-allow-methods': 'GET,POST,OPTIONS',
          'access-control-allow-headers': 'content-type',
        },
      });
    }

    if (request.method === 'POST' && url.pathname === '/api/generate') {
      return handleGenerate(request, env, url);
    }

    if (request.method === 'GET' && url.pathname.startsWith('/sub/')) {
      return handleSub(url, env);
    }

    return env.ASSETS.fetch(request);
  },
};