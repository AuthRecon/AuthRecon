import { test } from 'node:test'
import assert from 'node:assert/strict'
import { describeDetectionError, hasKnownAuthType, isTimeoutError } from './detectionStatus.js'

const TIMEOUT = "HTTPSConnectionPool(host='target.invalid', port=443): Read timed out. (read timeout=10)"

test('no probe error shows nothing', () => {
  assert.equal(describeDetectionError({ status: 'succeeded', detected_auth: {} }), null)
  assert.equal(describeDetectionError({ status: 'failed' }), null)
})

test('succeeded run with a probe timeout is an amber note, not a failure', () => {
  const d = describeDetectionError({ status: 'succeeded', auth_type: 'form_auth', detected_auth: { error: TIMEOUT } })
  assert.equal(d.severity, 'warning')
  assert.equal(d.title, 'Pre-run detection probe timed out; auth type was detected during the run')
  assert.equal(d.detail, TIMEOUT)
})

test('succeeded run is amber even if auth type is still unknown', () => {
  const d = describeDetectionError({ status: 'succeeded', auth_type: 'unknown', detected_auth: { error: TIMEOUT } })
  assert.equal(d.severity, 'warning')
})

test('known auth type on a running run is amber', () => {
  const d = describeDetectionError({ status: 'running', auth_type: 'basic_auth', detected_auth: { error: 'Connection reset' } })
  assert.equal(d.severity, 'warning')
  assert.match(d.title, /^Pre-run detection probe failed; auth type was detected/)
})

test('running run with nothing detected yet is amber and says the run will detect', () => {
  const d = describeDetectionError({ status: 'running', auth_type: null, detected_auth: { error: TIMEOUT } })
  assert.equal(d.severity, 'warning')
  assert.match(d.title, /the run will detect the auth type itself$/)
})

test('failed run keeps the red Detection Failed banner', () => {
  const d = describeDetectionError({ status: 'failed', auth_type: 'form_auth', detected_auth: { error: TIMEOUT } })
  assert.deepEqual(d, { severity: 'error', title: 'Detection Failed', detail: TIMEOUT })
})

test('helpers', () => {
  assert.ok(isTimeoutError('Read timed out.'))
  assert.ok(isTimeoutError('ConnectTimeout'))
  assert.ok(!isTimeoutError('Connection refused'))
  assert.ok(hasKnownAuthType('form_auth'))
  assert.ok(!hasKnownAuthType('generic'))
  assert.ok(!hasKnownAuthType(undefined))
})
