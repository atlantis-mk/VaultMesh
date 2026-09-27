import { useState } from "react";

import { ScrollArea } from "@/components/ui/scroll-area";
import { generatePassword, generateRandomLogin, type GeneratedLogin, type PasswordGeneratorOptions, type UsernameGeneratorOptions } from "@/lib/generated-credentials";
import { DEFAULT_PASSWORD_GENERATOR_OPTIONS, DEFAULT_USERNAME_GENERATOR_OPTIONS } from "@/lib/generator-preferences";
import type { InlineAutofillCandidate } from "@/lib/protocol";

type CandidateGroup = {
  key: string;
  label: string | null;
  candidates: InlineAutofillCandidate[];
};

export function InlineAutofillView({
  candidates,
  currentHost,
  currentHostname,
  generatedLoginKey,
  generatedMode,
  generatedEmailRequired = false,
  statusMessage = null,
  passwordGeneratorOptions = DEFAULT_PASSWORD_GENERATOR_OPTIONS,
  usernameGeneratorOptions = DEFAULT_USERNAME_GENERATOR_OPTIONS,
  onGeneratedPasswordSelect,
  onGeneratedSelect,
  onSelect,
}: {
  candidates: InlineAutofillCandidate[];
  currentHost: string;
  currentHostname: string;
  generatedLoginKey: number;
  generatedMode: "none" | "login" | "password";
  generatedEmailRequired?: boolean;
  statusMessage?: string | null;
  passwordGeneratorOptions?: PasswordGeneratorOptions;
  usernameGeneratorOptions?: UsernameGeneratorOptions;
  onGeneratedPasswordSelect: (password: string) => void;
  onGeneratedSelect: (login: GeneratedLogin) => void;
  onSelect: (candidate: InlineAutofillCandidate) => void;
}) {
  const groups = candidateGroups(candidates, currentHost, currentHostname);
  return (
    <div className="panel" role="listbox" aria-label="VaultMesh 自动填充建议">
      {statusMessage ? <div className="status" role="status" aria-live="polite">{statusMessage}</div> : null}
      <ScrollArea className="candidate-scroll">
        {generatedMode === "password"
          ? <GeneratedPasswordOption key={generatedLoginKey} options={passwordGeneratorOptions} onSelect={onGeneratedPasswordSelect} />
          : null}
        {groups.length === 0 && generatedMode === "login"
          ? <GeneratedLoginOption
              key={generatedLoginKey}
              emailRequired={generatedEmailRequired}
              passwordOptions={passwordGeneratorOptions}
              usernameOptions={usernameGeneratorOptions}
              onSelect={onGeneratedSelect}
            />
          : null}
        {groups.length === 0 && generatedMode === "none" && !statusMessage ? <div className="empty">当前站点没有可用项目</div> : null}
        <div className="groups">
          {groups.map((group) => (
            <section className="group" role="group" aria-label={group.label ?? undefined} key={group.key}>
              {group.label ? <div className="group-label">{group.label}</div> : null}
              {group.candidates.map((candidate) => (
                <button className="option" type="button" role="option" key={`${candidate.kind}:${candidate.id}`} onPointerDown={(event) => event.preventDefault()} onClick={() => onSelect(candidate)}>
                  <span className="mark" aria-hidden="true">{candidate.kind === "email-otp" ? "码" : "V"}</span>
                  <span className="text">
                    <span className="name">{candidate.title}</span>
                    <span className="subtitle">{candidate.subtitle}</span>
                  </span>
                </button>
              ))}
            </section>
          ))}
        </div>
      </ScrollArea>
    </div>
  );
}

function GeneratedPasswordOption({ options, onSelect }: { options: PasswordGeneratorOptions; onSelect: (password: string) => void }) {
  const [password, setPassword] = useState(() => generatePassword(options));
  return (
    <section className="generated" role="group" aria-label="随机生成的密码">
      <div className="generated-heading">
        <span>随机生成的密码</span>
        <button className="refresh" type="button" aria-label="刷新随机密码" title="刷新随机密码" onPointerDown={(event) => event.preventDefault()} onClick={() => setPassword(generatePassword(options))}>↻</button>
      </div>
      <button className="option generated-option" type="button" role="option" onPointerDown={(event) => event.preventDefault()} onClick={() => onSelect(password)}>
        <span className="mark generated-mark" aria-hidden="true">G</span>
        <span className="text">
          <span className="name">填充已生成的密码</span>
          <span className="subtitle generated-password">{password}</span>
        </span>
      </button>
    </section>
  );
}

function GeneratedLoginOption({
  emailRequired,
  passwordOptions,
  usernameOptions,
  onSelect,
}: {
  emailRequired: boolean;
  passwordOptions: PasswordGeneratorOptions;
  usernameOptions: UsernameGeneratorOptions;
  onSelect: (login: GeneratedLogin) => void;
}) {
  const generate = () => generateRandomLogin({ username: usernameOptions, password: passwordOptions, emailRequired });
  const [login, setLogin] = useState(generate);
  return (
    <section className="generated" role="group" aria-label="随机生成的账号密码">
      <div className="generated-heading">
        <span>随机生成的账号密码</span>
        <button className="refresh" type="button" aria-label="刷新随机账号和密码" title="刷新随机账号和密码" onPointerDown={(event) => event.preventDefault()} onClick={() => setLogin(generate())}>↻</button>
      </div>
      <button className="option generated-option" type="button" role="option" onPointerDown={(event) => event.preventDefault()} onClick={() => onSelect(login)}>
        <span className="mark generated-mark" aria-hidden="true">G</span>
        <span className="text">
          <span className="name generated-username">{login.username}</span>
          <span className="subtitle generated-password">{login.password}</span>
        </span>
      </button>
    </section>
  );
}

export function candidateGroups(candidates: InlineAutofillCandidate[], currentHost: string, currentHostname: string): CandidateGroup[] {
  const emailOtp = candidates.filter((candidate) => candidate.kind === "email-otp");
  // Paired-phone sources are not vault matches for this site; keep them apart.
  const device = candidates.filter((candidate) => candidate.kind === "device-assist");
  const vault = candidates.filter((candidate) => candidate.kind !== "email-otp" && candidate.kind !== "device-assist");
  const deviceGroup: CandidateGroup[] = device.length > 0 ? [{ key: "device-assist", label: "已配对手机", candidates: device }] : [];
  const groups: CandidateGroup[] = emailOtp.length > 0
    ? [{ key: "email-otp", label: "邮箱验证码", candidates: emailOtp }]
    : [];

  if (!vault.some((candidate) => candidate.kind === "login")) {
    const available: CandidateGroup[] = vault.length > 0 ? [{ key: "available", label: null, candidates: vault }] : [];
    // A lone phone entry needs no heading; next to other groups it gets one.
    const phone = deviceGroup.map((group) => groups.length || available.length ? group : { ...group, label: null });
    return [...groups, ...available, ...phone];
  }

  const exact = [
    ...vault.filter((candidate) => candidate.matchScope === "path"),
    ...vault.filter((candidate) => candidate.matchScope === "origin"),
  ];
  const domain = vault.filter((candidate) => candidate.matchScope !== "path" && candidate.matchScope !== "origin");
  return [...groups,
    { key: "origin", label: `当前站点 · ${currentHost}`, candidates: exact },
    { key: "domain", label: `同域名 · ${currentHostname}`, candidates: domain },
    ...deviceGroup,
  ].filter((group) => group.candidates.length > 0);
}
