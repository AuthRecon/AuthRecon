import { test } from 'node:test'
import assert from 'node:assert/strict'
import { shouldLogout } from './sessionGuard.js'

const valid = async () => true
const invalid = async () => false

test('a 401 from one endpoint with a still-valid session does not log out', async () => {
  assert.equal(await shouldLogout({ status: 401, url: '/api/tools', pathname: '/authrecon', checkSession: valid }), false)
})

test('a 401 with an invalid session logs out', async () => {
  assert.equal(await shouldLogout({ status: 401, url: '/api/tools', pathname: '/authrecon', checkSession: invalid }), true)
})

test('a 401 from the session check or login itself logs out without re-checking', async () => {
  let checked = false
  const spy = async () => { checked = true; return true }
  assert.equal(await shouldLogout({ status: 401, url: '/api/auth/me', pathname: '/', checkSession: spy }), true)
  assert.equal(checked, false)
})

test('403 and other errors never log out', async () => {
  for (const status of [403, 404, 500, undefined]) {
    assert.equal(await shouldLogout({ status, url: '/api/tools', pathname: '/authrecon', checkSession: invalid }), false)
  }
})

test('nothing happens on public pages', async () => {
  assert.equal(await shouldLogout({ status: 401, url: '/api/auth/login', pathname: '/login', checkSession: invalid }), false)
})
