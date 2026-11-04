import test from 'node:test';
import assert from 'node:assert/strict';
import {routingPayload} from '../src/dsh/routing-request.mjs';

test('collect works when a model also supplies a domain hint from the shared form',()=>{
 const args={operation:'collect',url:'https://support.example.com/regions',target:'api.example.com',path:'proxy'};
 assert.deepEqual(routingPayload(args),{operation:'route_source',url:args.url});
 assert.equal(args.target,'api.example.com');
});
test('evaluation keeps referenced evidence while excluding fields from collection and application',()=>{
 assert.deepEqual(routingPayload({operation:'evaluate',target:'api.example.com',path:'proxy',evidence_ids:'["cmp_test"]',business_requirement_evidence_ids:'["req_test"]',url:'https://example.com/',proposal:'{}'}),{operation:'route_evaluate',target:'api.example.com',path:'proxy',evidence_ids:['cmp_test'],business_requirement_evidence_ids:['req_test']});
});
test('actor and publication metadata come from the trusted tool executor',()=>{
 assert.deepEqual(routingPayload({operation:'apply',proposal:'{"domain":"api.example.com"}',session_id:'model-supplied',commit_message:'unvalidated'}),{operation:'route_apply',proposal:{domain:'api.example.com'}});
 assert.throws(()=>routingPayload({operation:'execute'}));
 assert.throws(()=>routingPayload({operation:'get',evidence_ids:'invalid JSON'}));
});
