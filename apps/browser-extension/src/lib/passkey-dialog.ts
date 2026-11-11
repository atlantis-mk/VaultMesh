/** In-page chooser for a WebAuthn call that is waiting for the user (ADR-0057).
 *
 * It only asks "who serves this request" and offers to open the VaultMesh
 * unlock window. The master password, PIN and biometrics are never entered
 * here: the page can see the DOM around a closed shadow root, so unlocking stays
 * in the extension's own window. */

export type PasskeyPromptView = { token: string; operation: 'create' | 'get'; origin: string | null; stage: 'choose' | 'unlock' };
export type PasskeyDialogChoice = 'vaultmesh' | 'native' | 'cancel';

export type PasskeyDialogHandlers = {
  choose(token: string, choice: PasskeyDialogChoice, remember: boolean): void;
  openUnlock(token: string): void;
};

export function passkeyPromptText(prompt: PasskeyPromptView): string {
  const site = prompt.origin ?? '当前网站';
  if (prompt.stage === 'unlock') {
    return prompt.operation === 'create'
      ? `${site} 正在创建通行密钥。VaultMesh 已锁定，解锁后将继续保存。`
      : `${site} 正在请求通行密钥登录。VaultMesh 已锁定，解锁后将继续。`;
  }
  return prompt.operation === 'create'
    ? `${site} 正在创建通行密钥。要保存到 VaultMesh，还是使用浏览器/系统？`
    : `${site} 正在请求通行密钥登录。要使用 VaultMesh，还是使用浏览器/系统？`;
}

/** Dialog wording: the site is shown on its own row, so the sentences stay short. */
export function passkeyDialogCopy(prompt: PasskeyPromptView): { title: string; description: string } {
  const title = prompt.operation === 'create' ? '创建通行密钥' : '使用通行密钥登录';
  if (prompt.stage === 'unlock') {
    return { title, description: 'VaultMesh 已锁定。请在插件窗口解锁后继续，或改用浏览器/系统。' };
  }
  return {
    title,
    description: prompt.operation === 'create' ? '要保存到 VaultMesh，还是使用浏览器/系统？' : '要使用 VaultMesh，还是使用浏览器/系统？',
  };
}

/* Tokens mirror the popup (assets/tailwind.css) and the in-page menu (inline-autofill.ts):
 * indigo primary, 10px radius, 13px system-ui, 22px "V" mark, soft neutral borders. */
const STYLE = `
:host{all:initial}
*{box-sizing:border-box}
.card{
  --foreground:oklch(0.208 0.042 265.755);--muted-foreground:oklch(0.551 0.027 264.364);
  --primary:oklch(0.424 0.199 265.638);--muted:oklch(0.967 0.003 264.542);--accent:oklch(0.957 0.022 261.325);
  --border:oklch(0.928 0.006 264.531);
  width:360px;max-width:calc(100vw - 24px);padding:14px;border:1px solid rgba(127,127,127,.35);border-radius:10px;
  background:#fff;color:var(--foreground);box-shadow:0 12px 32px rgba(0,0,0,.22);
  font:13px/1.35 system-ui,-apple-system,"Segoe UI",sans-serif;
  animation:enter .14s ease-out;
}
@keyframes enter{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:none}}
@media (prefers-reduced-motion:reduce){.card{animation:none}}
.head{display:flex;align-items:center;gap:10px}
.mark{flex:none;display:grid;place-items:center;width:22px;height:22px;border-radius:6px;background:#6d5dfc;color:#fff;font-weight:800}
.title{font-size:13px;font-weight:650;line-height:1.25}
.brand{font-size:11px;color:var(--muted-foreground);line-height:1.25}
.site{margin:12px 0 8px;padding:6px 8px;border-radius:8px;background:var(--muted);font-size:12px;word-break:break-all}
.desc{margin:0 0 12px;color:var(--muted-foreground)}
.remember{display:flex;align-items:center;gap:6px;margin:0 0 12px;font-size:12px;cursor:pointer}
.remember input{width:14px;height:14px;margin:0;accent-color:var(--primary)}
.row{display:flex;gap:8px;justify-content:flex-end}
button{height:28px;padding:0 10px;border:1px solid transparent;border-radius:8px;background:transparent;color:inherit;font:inherit;font-size:12.8px;font-weight:500;white-space:nowrap;cursor:pointer;transition:background-color .12s}
button:hover{background:var(--muted)}
button.outline{border-color:var(--border);background:#fff}
button.outline:hover{background:var(--muted)}
button.primary{background:var(--primary);color:#fff}
button.primary:hover{background:color-mix(in oklch,var(--primary),white 20%)}
button:active{transform:translateY(1px)}
button:focus-visible{outline:2px solid color-mix(in oklch,var(--primary),transparent 50%);outline-offset:2px}
`;

export function createPasskeyDialog(
  doc: Document,
  handlers: PasskeyDialogHandlers,
  options: { requireTrustedEvents?: boolean; shadowMode?: 'open' | 'closed' } = {},
) {
  const requireTrusted = options.requireTrustedEvents !== false;
  let host: HTMLElement | null = null;
  let currentToken: string | null = null;
  let onKey: ((event: KeyboardEvent) => void) | null = null;

  function hide(token?: string) {
    if (token !== undefined && token !== currentToken) return;
    if (onKey) doc.removeEventListener('keydown', onKey, true);
    onKey = null;
    host?.remove();
    host = null;
    currentToken = null;
  }

  function show(prompt: PasskeyPromptView) {
    hide();
    currentToken = prompt.token;
    host = doc.createElement('div');
    host.dataset.vaultmeshPasskey = '';
    host.style.cssText = 'all:initial;position:fixed;z-index:2147483647;top:16px;right:16px;display:block';
    const shadow = host.attachShadow({ mode: options.shadowMode ?? 'closed' });
    const style = doc.createElement('style');
    style.textContent = STYLE;
    const card = doc.createElement('div');
    card.className = 'card';
    card.setAttribute('role', 'alertdialog');
    card.setAttribute('aria-modal', 'false');

    const copy = passkeyDialogCopy(prompt);
    const head = doc.createElement('div');
    head.className = 'head';
    const mark = doc.createElement('span');
    mark.className = 'mark';
    mark.setAttribute('aria-hidden', 'true');
    mark.textContent = 'V';
    const heading = doc.createElement('div');
    const title = doc.createElement('div');
    title.className = 'title';
    title.id = 'title';
    title.textContent = copy.title;
    const brand = doc.createElement('div');
    brand.className = 'brand';
    brand.textContent = 'VaultMesh';
    heading.append(title, brand);
    head.append(mark, heading);

    const site = doc.createElement('div');
    site.className = 'site';
    site.textContent = prompt.origin ?? '当前网站';
    const description = doc.createElement('p');
    description.className = 'desc';
    description.id = 'description';
    description.textContent = copy.description;
    card.setAttribute('aria-labelledby', 'title');
    card.setAttribute('aria-describedby', 'description');
    card.append(head, site, description);

    let remember: HTMLInputElement | null = null;
    if (prompt.stage === 'choose') {
      const label = doc.createElement('label');
      label.className = 'remember';
      remember = doc.createElement('input');
      remember.type = 'checkbox';
      label.append(remember, doc.createTextNode('记住此网站的选择'));
      card.append(label);
    }

    const row = doc.createElement('div');
    row.className = 'row';
    const act = (run: () => void) => (event: Event) => {
      if (requireTrusted && !event.isTrusted) return;
      run();
    };
    const button = (label: string, run: () => void, variant: 'primary' | 'outline' | 'ghost') => {
      const element = doc.createElement('button');
      element.type = 'button';
      element.textContent = label;
      if (variant !== 'ghost') element.className = variant;
      element.addEventListener('click', act(run));
      return element;
    };
    const token = prompt.token;
    const rememberValue = () => remember?.checked === true;
    // Ghost cancel, outline alternative, primary action last, as in the popup's dialogs.
    row.append(button('取消', () => handlers.choose(token, 'cancel', false), 'ghost'));
    if (prompt.stage === 'choose') {
      row.append(
        button('使用浏览器/系统', () => handlers.choose(token, 'native', rememberValue()), 'outline'),
        button('使用 VaultMesh', () => handlers.choose(token, 'vaultmesh', rememberValue()), 'primary'),
      );
    } else {
      row.append(
        button('改用浏览器/系统', () => handlers.choose(token, 'native', false), 'outline'),
        button('打开解锁窗口', () => handlers.openUnlock(token), 'primary'),
      );
    }
    card.append(row);
    shadow.append(style, card);
    doc.documentElement.append(host);

    onKey = (event) => {
      if (event.key !== 'Escape' || event.isComposing || (requireTrusted && !event.isTrusted)) return;
      handlers.choose(token, 'cancel', false);
    };
    doc.addEventListener('keydown', onKey, true);
    (shadow.querySelector('button.primary') as HTMLButtonElement | null)?.focus({ preventScroll: true });
  }

  return { show, hide, current: () => currentToken, element: () => host };
}
