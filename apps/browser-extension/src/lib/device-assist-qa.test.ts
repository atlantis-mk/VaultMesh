import html from '../../../../autofill-test.html?raw';
import { afterEach, describe, expect, it } from 'vitest';
import { classifyControl, deviceAssistKindForControl } from './form-discovery';

const fixture = new DOMParser().parseFromString(html, 'text/html');
afterEach(() => { document.body.innerHTML = ''; });
function mount(id: string) {
  document.body.innerHTML = fixture.getElementById(id)!.innerHTML;
  for (const input of document.querySelectorAll<HTMLInputElement>('input')) {
    Object.defineProperty(input, 'getClientRects', { value: () => [{ width: 240, height: 32 }] });
    Object.defineProperty(input, 'getBoundingClientRect', { value: () => ({ left: 20, top: 20, right: 260, bottom: 52, width: 240, height: 32 }) });
  }
}
describe('CT-DEVICE-ASSIST-002 real QA form coverage', () => {
  it('offers the correct phone or SMS source for every dedicated positive fixture', () => {
    mount('device-assist-tests');
    const fields = [...document.querySelectorAll<HTMLInputElement>('[data-expect="fill"]')];
    expect(fields.length).toBeGreaterThan(15);
    for (const input of fields) {
      expect(classifyControl(input), input.id).not.toBeNull();
      expect(deviceAssistKindForControl(input), input.id).toBe(/code|digit/.test(input.id) ? 'sms' : 'phone');
    }
  });
  it.each(['login-tests', 'account-lifecycle-tests'])('offers both sources inside %s', (suite) => {
    mount(suite);
    const phone = document.querySelector<HTMLInputElement>('input[id$="phone-account"]')!;
    const sms = document.querySelector<HTMLInputElement>('input[id$="phone-code"]')!;
    expect(classifyControl(phone)).not.toBeNull();
    expect(deviceAssistKindForControl(phone)).toBe('phone');
    expect(classifyControl(sms)).not.toBeNull();
    expect(deviceAssistKindForControl(sms)).toBe('sms');
  });
  it('withholds phone/SMS entries from protected, unrelated and occupied fixtures', () => {
    mount('device-assist-tests');
    for (const input of document.querySelectorAll<HTMLInputElement>('[data-expect="empty"], [data-expect="preserve"]')) {
      expect(deviceAssistKindForControl(input), input.id).toBeNull();
    }
  });
});
