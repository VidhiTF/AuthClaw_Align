import test from 'node:test';
import assert from 'node:assert/strict';

import {
  mapCanonicalPath,
  mapCanonicalRequest,
  normalizeCanonicalResponse,
} from '../src/lib/api-contract.ts';

test('maps core console resources to canonical control-plane routes', () => {
  assert.equal(mapCanonicalPath('/audit/logs'), '/audit-logs');
  assert.equal(mapCanonicalPath('/providers'), '/provider-credentials');
  assert.equal(mapCanonicalPath('/providers/abc'), '/provider-credentials/abc');
  assert.equal(mapCanonicalPath('/gateway-routes/abc'), '/gateways/abc');
  assert.equal(mapCanonicalPath('/approvals?_t=1'), '/workflows/approvals?_t=1');
  assert.equal(mapCanonicalPath('/compliance/scores'), '/compliance-scores');
});

test('maps imported mutation semantics to canonical methods', () => {
  assert.deepEqual(mapCanonicalRequest('post', '/api-keys/key-1/revoke'), {
    method: 'DELETE',
    path: '/api-keys/key-1',
  });
  assert.deepEqual(mapCanonicalRequest('patch', '/gateway-routes/route-1'), {
    method: 'PUT',
    path: '/gateways/route-1',
  });
  assert.deepEqual(mapCanonicalRequest('post', '/compliance/scores/calculate'), {
    method: 'GET',
    path: '/compliance-scores?persist_snapshot=true',
  });
});

test('normalizes audit and compliance response shapes', () => {
  assert.deepEqual(
    normalizeCanonicalResponse('/audit/logs', { records: [{ id: 'a-1' }], total: 1 }),
    { records: [{ id: 'a-1' }], items: [{ id: 'a-1' }], total: 1 },
  );
  const compliance = normalizeCanonicalResponse('/compliance/dashboard', {
    overall_score: 82,
    frameworks: [{ framework: 'SOC 2', score: 82 }],
  }) as Record<string, unknown>;
  assert.deepEqual(compliance.soc2, {
    framework: 'SOC 2',
    score: 82,
    status: 'calculated',
  });
});

test('leaves already canonical and unknown routes unchanged', () => {
  assert.equal(mapCanonicalPath('/auth/login'), '/auth/login');
  assert.equal(mapCanonicalPath('/findings'), '/findings');
});
