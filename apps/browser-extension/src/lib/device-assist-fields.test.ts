import { describe, it, expect } from 'vitest';
import { isDeviceAssistField } from './device-assist-fields';
import { DeviceAssistCandidateSchema } from './device-assist-schema';
import type { FieldDescriptor } from './protocol';
const field = (overrides:Partial<FieldDescriptor> = {}):FieldDescriptor => ({handle:crypto.randomUUID(),control:'input',inputType:'text',isEmpty:true,autocomplete:[],label:'',name:'',id:'',placeholder:'',context:'unknown',...overrides});
describe('CT-DEVICE-ASSIST-002',()=>{
 it('accepts only explicit phone and OTP fields',()=>{
  expect(isDeviceAssistField(field({autocomplete:['tel']}),'phone')).toBe(true);
  expect(isDeviceAssistField(field({label:'手机号'}),'phone')).toBe(true);
  expect(isDeviceAssistField(field({label:'联系电话'}),'phone')).toBe(true);
  expect(isDeviceAssistField(field({autocomplete:['one-time-code']}),'sms')).toBe(true);
  expect(isDeviceAssistField(field({inputType:'number'}),'sms')).toBe(false);
  expect(isDeviceAssistField(field({label:'用户名'}),'phone')).toBe(false);
 });
 it('keeps phone accounts separate from codes in an OTP form',()=>{
  const phone=field({label:'登录手机号',autocomplete:['username'],context:'otp'});
  expect(isDeviceAssistField(phone,'phone')).toBe(true);
  expect(isDeviceAssistField(phone,'sms')).toBe(false);
  expect(isDeviceAssistField(field({autocomplete:['username'],context:'otp'}),'sms')).toBe(false);
  expect(isDeviceAssistField(field({autocomplete:['email'],context:'otp'}),'sms')).toBe(false);
 });
 it('rejects occupied and protected unrelated fields',()=>{
  for(const f of [field({label:'手机号',isEmpty:false}),field({label:'手机号码',inputType:'password'})]) expect(isDeviceAssistField(f,'phone')).toBe(false);
  for(const label of ['TOTP code','authenticator otp','银行卡验证码','password otp']) expect(isDeviceAssistField(field({label}),'sms')).toBe(false);
 });
 it('rejects secrets in metadata',()=>{
  const candidate={id:'opaque',peer:'peer',device:'Synthetic',kind:'sms',source:'SMS',remainingMs:120000};
  expect(DeviceAssistCandidateSchema.safeParse(candidate).success).toBe(true);
  expect(DeviceAssistCandidateSchema.safeParse({...candidate,code:'428193'}).success).toBe(false);
 });
});
