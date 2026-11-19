/** Recent, non-secret record of how passkey requests were handled, so a user can
 * see why a site fell back or failed without opening developer tools.
 *
 * Only origin, operation and a reason code are kept. It lives in
 * `storage.session` (memory only, cleared when the browser closes) and never
 * holds request options, challenges, credential IDs or Vault data. */

const KEY = 'vaultmesh.passkey.diagnostics.v1';
export const MAX_PASSKEY_DIAGNOSTICS = 20;
const MAX_MESSAGE_CHARS = 300;

export type PasskeyDiagnostic = { at: number; message: string };

let queue: Promise<unknown> = Promise.resolve();

function sanitize(message: string): string {
  // eslint-disable-next-line no-control-regex
  return message.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, MAX_MESSAGE_CHARS);
}

function isDiagnostic(value: unknown): value is PasskeyDiagnostic {
  return !!value && typeof value === 'object'
    && typeof (value as PasskeyDiagnostic).at === 'number'
    && typeof (value as PasskeyDiagnostic).message === 'string';
}

export async function readPasskeyDiagnostics(): Promise<PasskeyDiagnostic[]> {
  try {
    const stored = await browser.storage.session.get(KEY);
    const entries = stored[KEY];
    return Array.isArray(entries) ? entries.filter(isDiagnostic).slice(-MAX_PASSKEY_DIAGNOSTICS) : [];
  } catch {
    return [];
  }
}

/** Appends serially so concurrent requests cannot overwrite one another. */
export function recordPasskeyDiagnostic(message: string, now: () => number = Date.now): Promise<void> {
  const entry: PasskeyDiagnostic = { at: now(), message: sanitize(message) };
  const next = queue.then(async () => {
    const current = await readPasskeyDiagnostics();
    await browser.storage.session.set({ [KEY]: [...current, entry].slice(-MAX_PASSKEY_DIAGNOSTICS) });
  }).catch(() => undefined);
  queue = next;
  return next as Promise<void>;
}

export async function clearPasskeyDiagnostics(): Promise<void> {
  await queue;
  await browser.storage.session.remove(KEY).catch(() => undefined);
}

const REASON_TEXT: Array<[RegExp, string]> = [
  [/^takeover-disabled/, '设置里已关闭“接管网页通行密钥请求”，交给浏览器。'],
  [/^firefox-unsupported/, 'Firefox 暂不支持网页通行密钥接管（缺少相关浏览器 API），交给浏览器。'],
  [/^permissions-policy-denied/, '跨源子框架未获得网页的通行密钥权限策略授权（Permissions Policy），交给浏览器。'],
  [/^frame-ancestry-untrusted/, '无法验证完整安全的页面框架来源链，交给浏览器。'],
  [/^cross-origin-frame/, '请求来自跨源 iframe，交给浏览器按权限策略处理。'],
  [/^frame-tree-unavailable/, '读取不到页面的 frame 信息，交给浏览器。'],
  [/^(invalid-options|unreadable-options)/, '页面传入的请求参数无法解析，交给浏览器。'],
  [/^request-too-large/, '请求体超过大小上限，交给浏览器。'],
  [/^desktop-update-required/, '桌面端还不支持取消通行密钥请求，已交给浏览器。请更新桌面端。'],
  [/^desktop-unpaired/, '插件还没有与桌面端配对。请在桌面端重新配对。'],
  [/^(desktop-desktop-unavailable|desktop-unreachable|probe-desktop-unavailable|probe-failed)/, '连接不上 VaultMesh 桌面端。请确认桌面端正在运行。'],
  [/^desktop-passkey-unavailable/, '桌面端没有该网站可用的通行密钥，交给浏览器。'],
  [/^no-matching-passkey/, 'VaultMesh 里没有该网站的通行密钥，交给浏览器。'],
  [/^site-mode-native/, '当前网站的 Passkey 模式设为“系统”，交给浏览器。'],
  [/^site-mode-vaultmesh/, '当前网站的 Passkey 模式设为“VaultMesh”，直接使用 VaultMesh。'],
  [/^site-mode-ask/, '当前网站的 Passkey 模式设为“询问”，显示选择对话框。'],
  [/^default-vaultmesh/, '按默认策略由 VaultMesh 处理通行密钥请求。'],
  [/^remembered-browser-choice/, '你之前为这个网站选择了“浏览器/系统”，交给浏览器。可在设置里清除。'],
  [/^remembered-vaultmesh-choice/, '你之前为这个网站选择了“VaultMesh”，直接使用 VaultMesh。可在设置里清除。'],
  [/^user-chose-browser/, '你选择了“浏览器/系统”。'],
  [/^user-skipped-unlock/, '你选择不解锁，改用浏览器/系统。'],
  [/^user-cancelled-choice/, '你在选择对话框里点了取消。'],
  [/^choice-timed-out/, '选择对话框 5 分钟内无人操作，请求已取消。'],
  [/^request-timed-out/, '通行密钥请求已超过允许等待时间。'],
  [/^shim-timeout/, '网页设定的通行密钥等待超时，请求已取消。'],
  [/^user-cancelled-unlock/, '你在解锁等待中点了取消。'],
  [/^unlock-timed-out/, 'VaultMesh 5 分钟内没有解锁，请求已取消。'],
  [/^desktop-confirmation-declined/, '你在桌面端的原生确认框里点了取消。'],
  [/^conditional-pending/, '已挂起条件式通行密钥请求，等待你在输入框内联菜单中选择。'],
  [/^conditional-unavailable/, '当前网站没有可用于条件式内联菜单的通行密钥，交给浏览器。'],
  [/^conditional-confirmation-declined/, '你在桌面端确认中取消了操作，内联菜单中的通行密钥选项已保留供重试。'],
  [/^page-aborted-or-navigated/, '页面取消了请求，或标签页已跳转/关闭。'],
  [/^unsupported-extension:([A-Za-z]+)/, '页面请求了 VaultMesh 不支持的扩展（$1），交给浏览器。'],
  [/^conditional-mediation/, '页面使用条件式 UI，由浏览器处理。'],
  [/^background-fallback/, '由后台决定交给浏览器（原因见同一时间的其他记录）。'],
  [/^malformed-response/, '桌面端返回的响应无法解析，已交给浏览器。'],
  [/^platform-(authenticator|capabilities)-reported-by-vaultmesh/, '浏览器自己没有平台认证器，已向网站报告“有”，让网站愿意发起请求。'],
  [/^availability/, '查询 VaultMesh 是否可用。'],
  [/^(choose|unlock|no-match), in-page/, '已在页面里显示 VaultMesh 对话框，等待你操作。'],
  [/^(choose|unlock|no-match), extension-window/, '页面无法显示对话框，已改为打开插件窗口，等待你操作。'],
  [/^chose-vaultmesh/, '你选择了使用 VaultMesh。'],
  [/^served/, 'VaultMesh 已生成凭据并交还给网页。如果网站仍提示失败，说明是网站拒绝了这份凭据，不是请求没送到。'],
];

/** One short Chinese sentence for a diagnostic line, or `null` when it is not recognised. */
export function explainPasskeyDiagnostic(message: string): string | null {
  const match = /\((?<reason>[^)]*)\)\s*$/.exec(message);
  if (!match?.groups) return null;
  const reason = match.groups.reason;
  if (/-> error /.test(message)) {
    const detail = /: (?<text>.*)$/.exec(reason)?.groups?.text;
    return detail ? `桌面端未能完成：${detail}` : '请求失败。';
  }
  for (const [pattern, text] of REASON_TEXT) {
    const found = pattern.exec(reason);
    if (found) return text.replace('$1', found[1] ?? '');
  }
  return null;
}
