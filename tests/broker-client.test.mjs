import assert from 'node:assert/strict';
import test from 'node:test';
import { callBroker } from '../src/dsh/broker-client.mjs';
test('an already-cancelled execution cannot connect to or start a broker operation',async()=>{
  const controller=new AbortController();controller.abort();
  await assert.rejects(callBroker({operation:'native_admit'},controller.signal),/cancelled/);
});
