// Maintainer-only generator. Never imports the candidate Python implementation.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

// Deliberately restricted to the fixture profile: no floating-point numbers,
// undefined, non-JSON objects or lone surrogates. Object keys use UTF-16 order.
function canonical(value) {
  if (value === null) return 'null';
  if (typeof value === 'string') {
    assert(value.isWellFormed());
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    assert(Number.isSafeInteger(value) && value >= 0);
    return String(value);
  }
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  assert(value && Object.getPrototypeOf(value) === Object.prototype);
  return '{' + Object.keys(value).sort().map(
    key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
}

function keyFromPublicTestSeed(seedHex) {
  return crypto.createPrivateKey({
    key: Buffer.from('302e020100300506032b657004220420' + seedHex, 'hex'),
    format: 'der', type: 'pkcs8',
  });
}

function publicHex(key) {
  const der = crypto.createPublicKey(key).export({format: 'der', type: 'spki'});
  assert(der.subarray(0, 12).equals(Buffer.from('302a300506032b6570032100', 'hex')));
  return der.subarray(12).toString('hex');
}

function publish(vectors) {
  const filename = path.join(__dirname, 'vectors.json');
  const expected = JSON.stringify(vectors, null, 2) + '\n';
  assert(process.argv.length <= 3 && (!process.argv[2] || process.argv[2] === '--write'));
  if (process.argv[2] === '--write') fs.writeFileSync(filename, expected);
  else assert.equal(fs.readFileSync(filename, 'utf8'), expected);
  console.log('Independent Node/OpenSSL vectors reproduce exactly');
}

const seed = '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f';
const key = keyFromPublicTestSeed(seed);
const vectors = [false, true].map(bound => {
  const caller = {caller_ref: 'caller:vector', tenant: 'tenant:vector', audience: bound ? 'audience:é/🚀' : 'audience:vector'};
  const challenge = {
    profile: 'openmfa.challenge.v0', id: '00000000-0000-4000-8000-000000000001',
    issuer: 'issuer:vector', ...caller, subject_ref: 'subject:machine:vector',
    nonce: Buffer.alloc(32, bound ? 2 : 1).toString('base64url'),
    method: 'wallet-ed25519-possession.v0', issued_at: 1000, expires_at: 1120,
    request_digest: bound ? 'sha256:' + 'a'.repeat(64) : null,
  };
  const challengeCanonical = canonical(challenge);
  const digest = 'sha256:' + crypto.createHash('sha256').update(challengeCanonical).digest('hex');
  const unsigned = {
    profile: 'openmfa.verification-receipt.v0', alg: 'Ed25519',
    id: '00000000-0000-4000-8000-000000000002', issuer: challenge.issuer,
    key_ref: 'issuer-key:vector', subject_ref: challenge.subject_ref, ...caller,
    challenge_digest: digest, request_digest: challenge.request_digest,
    verified_methods: [challenge.method], verified_at: 1005, expires_at: 1065,
    binding_ref: 'binding:vector:1', binding_revision: bound ? 9007199254740991 : 3,
  };
  const unsignedCanonical = canonical(unsigned);
  const message = Buffer.concat([Buffer.from('openMFA.receipt.v0\0'), Buffer.from(unsignedCanonical)]);
  const signature = crypto.sign(null, message, key);
  assert(crypto.verify(null, message, crypto.createPublicKey(key), signature));
  return {
    name: bound ? 'bound-unicode-and-max-safe-revision' : 'unbound',
    public_test_seed_hex: seed, public_key_hex: publicHex(key), caller,
    challenge, challenge_canonical_utf8: challengeCanonical, challenge_digest: digest,
    unsigned_canonical_utf8: unsignedCanonical, message_hex: message.toString('hex'),
    receipt: {...unsigned, signature: signature.toString('base64url')},
  };
});
publish(vectors);
