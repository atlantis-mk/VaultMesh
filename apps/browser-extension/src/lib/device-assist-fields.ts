import type { FieldDescriptor } from './protocol';
export type AssistKind = 'phone' | 'sms';
export function isDeviceAssistField(f: FieldDescriptor, kind: AssistKind): boolean {
  if (!f.isEmpty || f.control !== 'input' || !['', 'text', 'tel', 'number'].includes(f.inputType ?? '')) return false;
  const label = [f.label, f.placeholder].join(' ').toLowerCase();
  const text = [label, f.name, f.id, ...f.autocomplete].join(' ').toLowerCase();
  if (/totp|authenticator|验证器|银行卡|credit-card|cc-/.test(text)) return false;
  const phonePattern = /手机号|手机号码|电话|phone|mobile/;
  const explicitPhone = f.autocomplete.some(v => v === 'tel' || v === 'tel-national') || phonePattern.test(label);
  // Labels/autocomplete describe the field; IDs can include the enclosing flow (password login).
  if (/password|密码/.test(label) || f.autocomplete.some(v => /password/.test(v)) || (!explicitPhone && /password|密码/.test(text))) return false;
  const otpPattern = /验证码|校验码|sms|otp|verification|one-time/;
  const explicitOtp = f.autocomplete.includes('one-time-code') || otpPattern.test(label);
  const phone = !explicitOtp && (explicitPhone || phonePattern.test(text));
  if (kind === 'phone') return phone;
  if (phone || f.autocomplete.some(v => v === 'username' || v === 'email')) return false;
  // Form context alone is insufficient: unrelated numeric fields can share an OTP form.
  return explicitOtp || otpPattern.test(text);
}
