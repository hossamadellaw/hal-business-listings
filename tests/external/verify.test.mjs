import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { brotliCompressSync, deflateSync, gzipSync } from 'node:zlib';

import { __test, decideAttempts, githubRequest, isUnsafeIp, manageIssue, parseManagementPayload, preflight, runVerifyMode, validateConfig, verify } from './verify.mjs';

const LIMITS = Object.freeze({ max_attempts: 3, consecutive_successes: 2, incident_repeat_count: 2, max_requests_per_attempt: 10, max_total_requests: 30, request_concurrency: 2, request_timeout_ms: 10000, phase_timeout_ms: 360000, evidence_reserve_ms: 30000, retry_delay_ms: 100, max_redirect_hops: 3, max_response_headers: 64, max_header_bytes: 32768, max_body_bytes: 1048576, max_artifact_bytes: 262144 });
const PRIMARY_VERSION_SOURCE = Object.freeze({ id: 'page', target: 'primary', type: 'text_marker', path: '/', required: true, prefix: 'Version: ', suffix: '\n' });

function rawConfig(options = {}) {
  return {
    schema_version: 2,
    provenance: { mode: options.provenanceMode ?? 'claims_only', release_asset_name: 'plugin-{version}.zip' },
    environments: { preview: {
      targets: { primary: { base_url: options.primary ?? 'https://public.example.com/base/', basic_auth: options.basicAuth ?? false }, cdn: { base_url: 'https://cdn.example.com/assets/', basic_auth: false } },
      allowed_redirects: options.redirects ?? [],
      checks: options.checks ?? [{ id: 'home', target: 'primary', type: 'page', path: '/', method: 'GET', expected_status: 200, required: true, fatal_signatures: true, required_text: ['Ready'], forbidden_text: ['Never'] }],
      version_sources: options.versionSources ?? [
        { id: 'page', target: 'primary', type: 'text_marker', path: '/', required: true, prefix: 'Version: ', suffix: '\n' },
        { id: 'cdn', target: 'cdn', type: 'response_header', path: '/plugin.css', required: true, header_name: 'x-release-version' },
      ],
    } },
    limits: { ...LIMITS, ...options.limits },
  };
}

function validated(options = {}) { return { ...validateConfig(rawConfig(options), 'preview'), configDigest: 'a'.repeat(64) }; }
const provenanceClaims = Object.freeze({ mode: 'claims_only', status: 'owner_assertion', github_release_id: null, release_tag_commit_sha: null, asset: null });
function encode(value) { return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url'); }
function encodeText(value) { return Buffer.from(value, 'utf8').toString('base64url'); }
const ENVIRONMENT_DIGEST = crypto.createHash('sha256').update('hal-release-verification:environment:v1\0preview', 'utf8').digest('hex');
const TEST_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const CONTRACT_ROOT = path.resolve(TEST_DIRECTORY, '..', '..');
const TEMPLATE_PATH = path.join(TEST_DIRECTORY, 'verification-config.json');
const ENGINE_PATH = path.join(TEST_DIRECTORY, 'verify.mjs');
const WORKFLOW_PATH = path.join(CONTRACT_ROOT, '.github', 'workflows', 'release-verification.yml');
function templateDocument() { return JSON.parse(fs.readFileSync(TEMPLATE_PATH, 'utf8')); }
function engineDocument() { return fs.readFileSync(ENGINE_PATH, 'utf8'); }
function workflowDocument() { return fs.readFileSync(WORKFLOW_PATH, 'utf8'); }

const baseEnv = Object.freeze({ TARGET_ENVIRONMENT: 'preview', EXPECTED_VERSION: '1.2.3', DEPLOYMENT_COMMIT_SHA: '1'.repeat(40), RELEASE_ID: 'v1.2.3', CLAIM_SOURCE: 'manual_operator', VERIFIER_COMMIT_SHA: '2'.repeat(40), WORKFLOW_SHA: '3'.repeat(40), GITHUB_REPOSITORY: 'owner/plugin', GITHUB_RUN_ID: '100', GITHUB_RUN_ATTEMPT: '1', GITHUB_EVENT_NAME: 'workflow_dispatch', INVOCATION_KIND: 'dispatch', MANUAL_INSTALL_CONFIRMED: 'true', DEPLOYMENT_CONCLUSION: '', PROVENANCE_PAYLOAD: encode(provenanceClaims), OUTPUT_DIR: undefined, GITHUB_OUTPUT: undefined, GITHUB_STEP_SUMMARY: undefined });

async function withEnv(values, callback) {
  const saved = new Map(Object.keys(values).map((key) => [key, process.env[key]]));
  for (const [key, value] of Object.entries(values)) value === undefined || value === null ? delete process.env[key] : process.env[key] = String(value);
  try { return await callback(); } finally { for (const [key, value] of saved) value === undefined ? delete process.env[key] : process.env[key] = value; }
}

function outputFileSystem(options = {}) {
  const normalize = (value) => path.resolve(value).toLowerCase();
  const workingDirectory = path.resolve(process.cwd());
  const root = path.resolve(workingDirectory, 'verification-output');
  const directories = new Set([normalize(workingDirectory)]);
  const files = new Map();
  const links = new Map((options.links ?? []).map(([from, to]) => [normalize(from), path.resolve(to)]));
  const calls = [];
  const existsSync = (candidate) => directories.has(normalize(candidate)) || files.has(normalize(candidate)) || links.has(normalize(candidate));
  const realpathSync = (candidate) => {
    const key = normalize(candidate);
    calls.push({ operation: 'realpath', path: path.resolve(candidate) });
    if (links.has(key)) return links.get(key);
    if (!existsSync(candidate)) throw Object.assign(new Error('missing'), { code: 'ENOENT' });
    return path.resolve(candidate);
  };
  const fileSystem = {
    existsSync,
    realpathSync,
    mkdirSync(candidate) { calls.push({ operation: 'mkdir', path: path.resolve(candidate) }); directories.add(normalize(candidate)); },
    openSync(candidate, flags) {
      calls.push({ operation: 'open', path: path.resolve(candidate) });
      assert.equal(flags, 'wx');
      if (existsSync(candidate)) throw Object.assign(new Error('exists'), { code: 'EEXIST' });
      files.set(normalize(candidate), '');
      return path.resolve(candidate);
    },
    closeSync(descriptor) { calls.push({ operation: 'close', path: descriptor }); },
    lstatSync(candidate) {
      const key = normalize(candidate);
      calls.push({ operation: 'lstat', path: path.resolve(candidate) });
      return { isFile: () => files.has(key), isSymbolicLink: () => links.has(key) };
    },
    writeFileSync(candidate, value) { calls.push({ operation: 'write', path: path.resolve(candidate) }); files.set(normalize(candidate), String(value)); },
    appendFileSync(candidate, value) {
      calls.push({ operation: 'append', path: path.resolve(candidate) });
      const key = normalize(candidate);
      files.set(key, `${files.get(key) ?? ''}${String(value)}`);
    },
  };
  return { fileSystem, files, calls, root, normalize };
}

function response(statusCode = 200, body = '', headers = {}) { return { statusCode, body, headers, headerCounts: new Map(Object.keys(headers).map((name) => [name.toLowerCase(), 1])) }; }
function successTarget(url, method) { return url.hostname === 'cdn.example.com' ? Promise.resolve(response(200, method === 'HEAD' ? '' : 'asset', { 'x-release-version': '1.2.3' })) : Promise.resolve(response(200, 'Ready\nVersion: 1.2.3\n', { 'content-type': 'text/html' })); }

function management(overrides = {}) {
  return { schema_version: 3, management_eligible: true, environment_digest: ENVIRONMENT_DIGEST, claims: { expected_version: { value: '1.2.3', source: 'manual_operator' }, deployment_commit_sha: { value: '1'.repeat(40), source: 'manual_operator' }, release_id: { value: 'v1.2.3', source: 'manual_operator' } }, observations: { observed_version: null, provenance: provenanceClaims }, verifier_commit_sha: '2'.repeat(40), workflow_sha: '3'.repeat(40), repository: 'owner/plugin', run_id: '100', run_attempt: '1', run_url: 'https://github.com/owner/plugin/actions/runs/100', config_digest: 'a'.repeat(64), overall: 'fail', code: 'repeated_incident_fingerprint', incident: true, incident_fingerprints: ['b'.repeat(24)], completed_at: '2026-08-26T12:00:00.000Z', ...overrides };
}

function bindingEnvironment(template, options = {}) {
  const values = {
    target_environment: 'preview',
    release_asset_name_template: 'plugin-{version}.zip',
    primary_origin: 'https://public.example.com/',
    primary_check_path: '/',
    primary_public_marker: 'Ready',
    primary_version_path: '/',
    primary_version_header: 'x-release-version',
    ...(options.includeCdn === false ? {} : {
      cdn_origin: 'https://cdn.example.com/',
      cdn_check_path: '/plugin.css',
      cdn_version_path: '/plugin.css',
      cdn_version_header: 'x-release-version',
    }),
    ...options.values,
  };
  const environment = { TARGET_ENVIRONMENT: 'preview', ...options.controls };
  for (const [key, metadata] of Object.entries(template.bindings)) {
    if (values[key] !== undefined) environment[metadata.environment_variable] = values[key];
  }
  return environment;
}

function resolvedPathEnvironment(temporaryRoot, overrides = {}) {
  return {
    VERIFICATION_TEMP_ROOT: temporaryRoot,
    RUNNER_TEMP: temporaryRoot,
    VERIFICATION_CONFIG: path.join(temporaryRoot, 'release-verification-resolved', 'verification-config.resolved.json'),
    TARGET_ENVIRONMENT: 'preview',
    ...overrides,
  };
}

function resolvedOutputFileSystem(options = {}) {
  const normalize = (value) => process.platform === 'win32' ? path.resolve(value).toLowerCase() : path.resolve(value);
  const directories = new Set([normalize(CONTRACT_ROOT)]);
  const files = new Map();
  const links = new Map((options.links ?? []).map(([from, to]) => [normalize(from), path.resolve(to)]));
  const calls = [];
  if (options.templateText !== undefined) files.set(normalize(TEMPLATE_PATH), String(options.templateText));
  const roots = [options.temporaryRoot, options.authorityRoot].filter(Boolean);
  for (const root of roots) {
    if (options.rootAsFile && normalize(root) === normalize(options.temporaryRoot)) files.set(normalize(root), 'not-a-directory');
    else if (!links.has(normalize(root))) directories.add(normalize(root));
  }
  const existsSync = (candidate) => directories.has(normalize(candidate)) || files.has(normalize(candidate)) || links.has(normalize(candidate));
  const realpathSync = (candidate) => {
    const key = normalize(candidate);
    calls.push({ operation: 'realpath', path: path.resolve(candidate) });
    if (links.has(key)) return links.get(key);
    if (!existsSync(candidate)) throw Object.assign(new Error('missing'), { code: 'ENOENT' });
    return path.resolve(candidate);
  };
  realpathSync.native = realpathSync;
  let failWrite = options.failWrite === true;
  const fileSystem = {
    existsSync,
    realpathSync,
    lstatSync(candidate) {
      const key = normalize(candidate);
      calls.push({ operation: 'lstat', path: path.resolve(candidate) });
      if (!existsSync(candidate)) throw Object.assign(new Error('missing'), { code: 'ENOENT' });
      return {
        isDirectory: () => directories.has(key),
        isFile: () => files.has(key),
        isSymbolicLink: () => links.has(key),
      };
    },
    mkdirSync(candidate) {
      calls.push({ operation: 'mkdir', path: path.resolve(candidate) });
      if (existsSync(candidate)) throw Object.assign(new Error('exists'), { code: 'EEXIST' });
      if (options.directoryLinkTarget) links.set(normalize(candidate), path.resolve(options.directoryLinkTarget));
      else directories.add(normalize(candidate));
    },
    openSync(candidate, flags) {
      calls.push({ operation: 'open', path: path.resolve(candidate), flags });
      assert.equal(flags, 'wx');
      if (existsSync(candidate)) throw Object.assign(new Error('exists'), { code: 'EEXIST' });
      if (options.fileLinkTarget) links.set(normalize(candidate), path.resolve(options.fileLinkTarget));
      else files.set(normalize(candidate), '');
      return path.resolve(candidate);
    },
    closeSync(descriptor) { calls.push({ operation: 'close', path: descriptor }); },
    writeFileSync(candidate, value) {
      calls.push({ operation: 'write', path: path.resolve(candidate) });
      if (failWrite) { failWrite = false; throw new Error('injected-write-failure'); }
      files.set(normalize(candidate), String(value));
    },
    readFileSync(candidate) {
      calls.push({ operation: 'read', path: path.resolve(candidate) });
      const value = files.get(normalize(candidate));
      if (value === undefined) throw Object.assign(new Error('missing'), { code: 'ENOENT' });
      return Buffer.from(value, 'utf8');
    },
    chmodSync(candidate, mode) { calls.push({ operation: 'chmod', path: path.resolve(candidate), mode }); },
    readdirSync(directory) {
      const normalizedDirectory = normalize(directory);
      const entries = new Set();
      for (const candidate of [...directories, ...files.keys(), ...links.keys()]) {
        if (candidate !== normalizedDirectory && normalize(path.dirname(candidate)) === normalizedDirectory) entries.add(path.basename(candidate));
      }
      return [...entries];
    },
    unlinkSync(candidate) { calls.push({ operation: 'unlink', path: path.resolve(candidate) }); files.delete(normalize(candidate)); links.delete(normalize(candidate)); },
    rmdirSync(candidate) {
      calls.push({ operation: 'rmdir', path: path.resolve(candidate) });
      assert.equal(fileSystem.readdirSync(candidate).length, 0);
      directories.delete(normalize(candidate));
    },
  };
  return { fileSystem, directories, files, links, calls, normalize };
}
const ACTIONS_BOT = Object.freeze({ login: 'github-actions[bot]', type: 'Bot' });
function searchResult(items) { const normalized = items.map((item) => Object.hasOwn(item, 'user') ? item : { ...item, user: ACTIONS_BOT }); return { status: 200, body: { total_count: normalized.length, items: normalized }, headers: {} }; }

test('schema v2 supports direct targets and multiple version sources', () => {
  const config = validated();
  assert.deepEqual(Object.keys(config.environment.targets), ['primary', 'cdn']);
  assert.deepEqual(config.environment.versionSources.map((item) => item.id), ['page', 'cdn']);
});

test('all environments are strict and primary target instances are one-to-one', () => {
  const raw = rawConfig(); raw.environments.other = structuredClone(raw.environments.preview);
  assert.throws(() => validateConfig(raw, 'preview'), /duplicate_target_instance/);
  raw.environments.other.targets.primary.base_url = 'https://other.example.com/base/';
  raw.environments.other.targets.cdn.base_url = 'https://other-cdn.example.com/assets/';
  assert.equal(validateConfig(raw, 'preview').environments.other.targets.primary.origin, 'https://other.example.com:443');
  raw.environments.other.unknown = true;
  assert.throws(() => validateConfig(raw, 'preview'), /environment_1_unknown_key/);
});

test('environment and every target instance have globally canonical unique identities', () => {
  const secondary = rawConfig(); secondary.environments.other = structuredClone(secondary.environments.preview);
  secondary.environments.other.targets.primary.base_url = 'https://other.example.com/base/';
  assert.throws(() => validateConfig(secondary, 'preview'), /duplicate_target_instance/);

  const names = rawConfig(); names.environments.Preview = structuredClone(names.environments.preview);
  names.environments.Preview.targets.primary.base_url = 'https://other.example.com/base/';
  names.environments.Preview.targets.cdn.base_url = 'https://other-cdn.example.com/assets/';
  assert.throws(() => validateConfig(names, 'preview'), /duplicate_environment_name_case_insensitive/);

  const trailing = rawConfig(); trailing.environments.preview.targets.primary.base_url = 'https://public.example.com./base/';
  trailing.environments.preview.targets.cdn.base_url = 'https://public.example.com/assets/';
  assert.throws(() => validateConfig(trailing, 'preview'), /duplicate_target_origin/);
  assert.equal(__test.canonicalOrigin(new URL('https://EXAMPLE.com./')), 'https://example.com:443');
});

test('IPv4/IPv6 literals, duplicate origins and base-path escapes are rejected', () => {
  for (const base_url of ['https://127.0.0.1/', 'https://[::1]/']) { const raw = rawConfig(); raw.environments.preview.targets.primary.base_url = base_url; assert.throws(() => validateConfig(raw, 'preview'), /ip_literal_forbidden/); }
  const duplicate = rawConfig(); duplicate.environments.preview.targets.cdn.base_url = 'https://public.example.com/assets/'; assert.throws(() => validateConfig(duplicate, 'preview'), /duplicate_target_origin/);
  assert.throws(() => validateConfig(rawConfig({ redirects: [{ from: 'https://public.example.com/base/start', to: 'https://public.example.com/outside' }] }), 'preview'), /outside_target_base_path/);
  const pathGrant = rawConfig(); pathGrant.environments.preview.targets.cdn.base_url = 'https://cdn.example.com/assets'; assert.throws(() => validateConfig(pathGrant, 'preview'), /base_path_must_end_slash/);
});

test('path isolation rejects raw, encoded and repeatedly encoded separator ambiguity', () => {
  const hostile = [
    '/safe\\..\\escape',
    '/safe/%5c..%5c/escape',
    '/safe/%2f..%2fescape',
    '/safe/%252e%252e/escape',
    '/safe/%255c..%255c/escape',
    '/safe/%25252e%25252e/escape',
  ];
  for (const requestPath of hostile) {
    const raw = rawConfig(); raw.environments.preview.checks[0].path = requestPath;
    assert.throws(() => validateConfig(raw, 'preview'), /backslash_forbidden|encoded_separator_forbidden|traversal_forbidden|encoding_depth_exceeded/);
  }
  const valid = rawConfig(); valid.environments.preview.checks[0].path = '/documents/My%20File/';
  assert.equal(validateConfig(valid, 'preview').environment.checks[0].path, '/documents/My%20File/');
});

test('config rejects unsafe capabilities and impossible limits', () => {
  const mutations = [
    (raw) => { raw.environments.preview.checks[0].method = 'POST'; },
    (raw) => { raw.environments.preview.checks[0].expected_status = 302; },
    (raw) => { raw.environments.preview.checks[0].regex = '.*'; },
    (raw) => { raw.environments.preview.targets.cdn.basic_auth = true; },
    (raw) => { raw.limits.max_attempts = 1; },
    (raw) => { raw.limits.max_requests_per_attempt = 2; raw.limits.max_total_requests = 6; },
    (raw) => { raw.provenance.release_asset_name = '../bad-{version}.zip'; },
  ];
  for (const mutate of mutations) { const raw = rawConfig(); mutate(raw); assert.throws(() => validateConfig(raw, 'preview')); }
});

test('configuration requires an observable Version source and required unobservable checks fail closed', async () => {
  const empty = rawConfig();
  for (const check of empty.environments.preview.checks) check.required = false;
  for (const source of empty.environments.preview.version_sources) source.required = false;
  assert.throws(() => validateConfig(empty, 'preview'), /required_observable_version_source_missing/);

  const checkOnly = rawConfig({ versionSources: [] });
  assert.throws(() => validateConfig(checkOnly, 'preview'), /required_observable_version_source_missing/);

  const config = validated({ checks: [{ id: 'private-only', target: 'primary', type: 'page', path: '/', method: 'GET', expected_status: 200, required: true, fatal_signatures: false, required_text: [], forbidden_text: [], observable: false }], versionSources: [PRIMARY_VERSION_SOURCE] });
  await withEnv(baseEnv, async () => {
    const output = outputFileSystem();
    const report = await verify(config, { now: () => Date.parse('2026-08-26T12:00:00Z'), provenance: provenanceClaims, performRequest: successTarget, fs: output.fileSystem });
    assert.equal(report.overall, 'not_observable_read_only');
    assert.equal(report.incident, false);
    assert.equal(report.metadata.observations.observed_version, null);
  });
});

test('unsafe IP ranges are rejected while public unicast is accepted', () => {
  for (const value of ['10.0.0.1', '127.0.0.1', '169.254.169.254', '192.168.1.1', '::1', 'fc00::1', 'fe80::1', '64:ff9b::a00:1', '2001:db8::1', '2002:0a00:1::']) assert.equal(isUnsafeIp(value), true, value);
  assert.equal(isUnsafeIp('8.8.8.8'), false); assert.equal(isUnsafeIp('2606:4700:4700::1111'), false);
});

test('per-check fingerprints distinguish checks and survive companion faults', () => {
  const first = __test.failureResult('check-a', true, { code: 'same', status: 'fail', incidentEligible: true });
  const second = __test.failureResult('check-b', true, { code: 'same', status: 'fail', incidentEligible: true });
  assert.notEqual(first.fingerprint, second.fingerprint);
  const decision = decideAttempts([{ status: 'fail', incidentFingerprints: [first.fingerprint, '1'.repeat(24)] }, { status: 'fail', incidentFingerprints: [first.fingerprint, '2'.repeat(24)] }], LIMITS);
  assert.deepEqual(decision.incidentFingerprints, [first.fingerprint]);
});

test('attempt table and result priority are exact', () => {
  const pass = { status: 'pass', incidentFingerprints: [] }; const fail = { status: 'fail', incidentFingerprints: ['a'.repeat(24)] }; const blocked = { status: 'blocked', incidentFingerprints: ['b'.repeat(24)] };
  assert.equal(decideAttempts([pass, pass], LIMITS).overall, 'pass'); assert.equal(decideAttempts([fail, pass, pass], LIMITS).overall, 'pass');
  assert.equal(decideAttempts([pass, fail, pass], LIMITS).code, 'stability_requirement_not_met'); assert.equal(decideAttempts([blocked, blocked], LIMITS).overall, 'blocked');
  assert.equal(decideAttempts([{ status: 'not_observable_read_only', incidentFingerprints: [] }], LIMITS).overall, 'not_observable_read_only');
  const classified = __test.classifyAttempt([{ id: 'x', required: true, status: 'not_observable_read_only', code: 'x', incident_eligible: false }, { id: 'y', required: true, status: 'blocked', code: 'y', fingerprint: '1'.repeat(24), incident_eligible: true }, { id: 'z', required: true, status: 'fail', code: 'z', fingerprint: '2'.repeat(24), incident_eligible: true }], []);
  assert.equal(classified.status, 'fail');
  for (const status of ['fail', 'blocked', 'not_observable_read_only']) {
    const requiredNonPass = __test.classifyAttempt([{ id: status, required: true, status, code: status, fingerprint: null, incident_eligible: false }], [{ id: 'version:page', required: true, status: 'pass', code: 'expected_version_observed', fingerprint: null, incident_eligible: false }]);
    assert.notEqual(requiredNonPass.status, 'pass', status);
  }
});

test('normal verification supplies usable default timers and preserves isolated timer injection', async () => {
  await withEnv(baseEnv, async () => {
    const customSetTimeout = () => 1;
    const customClearTimeout = () => {};
    for (const injected of [undefined, { setTimeout: customSetTimeout, clearTimeout: customClearTimeout }]) {
      const output = outputFileSystem();
      const observed = [];
      const dependencies = {
        ...(injected ?? {}),
        now: () => Date.parse('2026-08-26T12:00:00Z'),
        sleep: async () => {},
        provenance: provenanceClaims,
        performRequest: async (url, method, context) => { observed.push(context.dependencies); return successTarget(url, method); },
        fs: output.fileSystem,
      };
      const report = await verify(validated(), dependencies);
      assert.equal(report.overall, 'pass');
      assert.ok(observed.length > 0);
      assert.equal(typeof observed[0].setTimeout, 'function');
      assert.equal(typeof observed[0].clearTimeout, 'function');
      if (injected) {
        assert.equal(observed[0].setTimeout, customSetTimeout);
        assert.equal(observed[0].clearTimeout, customClearTimeout);
      }
    }
  });
});

test('redirects are declared, base-confined, counted and strip cross-target auth', async () => {
  const config = validated({ redirects: [{ from: 'https://public.example.com/base/start', to: 'https://cdn.example.com/assets/final' }] });
  const calls = [];
  const context = { targets: config.environment.targets, allowedRedirects: config.environment.allowedRedirects, auth: { username: 'u', password: 'p' }, limits: config.limits, totalRequests: 0, attemptRequests: 0, phaseDeadline: 100000, now: () => 0, dependencies: { setTimeout, clearTimeout }, resolvePublic: async () => [{ address: '93.184.216.34', family: 4 }], requestOnce: async (url, method, auth) => { calls.push({ url: url.href, method, auth }); return calls.length === 1 ? response(302, '', { location: 'https://cdn.example.com/assets/final', 'set-cookie': 'ignored=x' }) : response(200, 'ok'); } };
  assert.equal((await __test.boundedRequest(new URL('https://public.example.com/base/start'), 'GET', context)).statusCode, 200);
  assert.deepEqual(calls.map((item) => item.auth), [context.auth, null]); assert.equal(context.totalRequests, 2);
  await assert.rejects(__test.boundedRequest(new URL('https://public.example.com/outside'), 'GET', { ...context, attemptRequests: 0 }), /outside_target_base_path/);
});

test('redirect and request budgets reject undeclared, downgrade and exhausted paths', async () => {
  const config = validated();
  const base = { targets: config.environment.targets, allowedRedirects: new Map(), auth: null, limits: config.limits, totalRequests: 0, attemptRequests: 0, phaseDeadline: 100000, now: () => 0, dependencies: { setTimeout, clearTimeout }, resolvePublic: async () => [{ address: '93.184.216.34', family: 4 }], requestOnce: async () => response(302, '', { location: 'https://cdn.example.com/assets/x' }) };
  await assert.rejects(__test.boundedRequest(new URL('https://public.example.com/base/start'), 'GET', base), /undeclared_transition/);
  const downgrade = { ...base, totalRequests: 0, attemptRequests: 0, allowedRedirects: new Map([['https://public.example.com:443/base/start', 'http://public.example.com:80/base/x']]), requestOnce: async () => response(302, '', { location: 'http://public.example.com/base/x' }) };
  await assert.rejects(__test.boundedRequest(new URL('https://public.example.com/base/start'), 'GET', downgrade), /https_downgrade/);
  await assert.rejects(__test.boundedRequest(new URL('https://public.example.com/base/start'), 'HEAD', { ...base, attemptRequests: 10, requestOnce: async () => assert.fail() }), /request_limit/);
  await assert.rejects(__test.boundedRequest(new URL('https://public.example.com/base/start'), 'HEAD', { ...base, phaseDeadline: 30000, requestOnce: async () => assert.fail() }), /phase_deadline/);
});

test('headers, decompression and teardown paths are bounded', async () => {
  assert.throws(() => __test.inspectHeaders(Array.from({ length: 130 }, (_, index) => index % 2 ? 'v' : 'x'), LIMITS), /too_many_headers/);
  const compressed = new PassThrough(); compressed.headers = { 'content-encoding': 'gzip' }; const promise = __test.readDecodedBody(compressed, 'GET', { ...LIMITS, max_body_bytes: 100 }); compressed.end(gzipSync(Buffer.alloc(1000, 65))); await assert.rejects(promise, /decoded_body_too_large/);
  const unsupported = new PassThrough(); unsupported.headers = { 'content-encoding': 'compress' }; await assert.rejects(__test.readDecodedBody(unsupported, 'GET', LIMITS), /unsupported_content_encoding/);
  const head = new PassThrough(); head.headers = {}; assert.equal(await __test.readDecodedBody(head, 'HEAD', LIMITS), '');
});

function fakeHttpsResponse({ status = 200, body = '{}', headers = {}, rawHeaders = [] } = {}) {
  return () => { const request = new EventEmitter(); request.write = () => {}; request.destroy = (error) => { if (error) queueMicrotask(() => request.emit('error', error)); }; request.end = () => queueMicrotask(() => { const socket = new EventEmitter(); socket.remoteAddress = '93.184.216.34'; socket.destroy = (error) => request.emit('error', error); request.emit('socket', socket); socket.emit('secureConnect'); const stream = new PassThrough(); stream.statusCode = status; stream.headers = headers; stream.rawHeaders = rawHeaders; request.emit('response', stream); stream.end(body); }); return request; };
}

test('requestOnce executes fixed lookup and destroys malformed responses', async () => {
  const result = await __test.requestOnce(new URL('https://public.example.com/base/'), 'GET', null, LIMITS, [{ address: '93.184.216.34', family: 4 }], { httpsRequest: fakeHttpsResponse({ status: 200, body: 'Ready', headers: { 'content-encoding': 'identity' }, rawHeaders: ['content-type', 'text/plain'] }), setTimeout, clearTimeout });
  assert.equal(result.body, 'Ready');
  await assert.rejects(__test.requestOnce(new URL('https://public.example.com/base/'), 'GET', null, LIMITS, [{ address: '93.184.216.34', family: 4 }], { httpsRequest: fakeHttpsResponse({ rawHeaders: Array.from({ length: 130 }, (_, index) => index % 2 ? 'v' : 'x') }), setTimeout, clearTimeout }), /too_many_headers/);
});

test('DNS resolver blocks empty, private and network errors', async () => {
  await assert.rejects(__test.resolvePublic('x', { dnsLookup: async () => [] }), /dns_empty/);
  await assert.rejects(__test.resolvePublic('x', { dnsLookup: async () => [{ address: '10.0.0.1', family: 4 }] }), /dns_non_public/);
  await assert.rejects(__test.resolvePublic('x', { dnsLookup: async () => { throw Object.assign(new Error(), { code: 'ENOTFOUND' }); } }), /enotfound/);
  assert.equal((await __test.resolvePublic('x', { dnsLookup: async () => [{ address: '8.8.8.8', family: 4 }] }))[0].address, '8.8.8.8');
});

test('verification passes only after two consecutive complete observations', async () => {
  await withEnv(baseEnv, async () => {
    const reports = [];
    const report = await verify(validated(), {
      now: (() => { let value = Date.parse('2026-08-26T12:00:00Z'); return () => value += 10; })(),
      performRequest: async (url, method, context) => {
        context.totalRequests += 1;
        context.attemptRequests += 1;
        return successTarget(url, method);
      },
      sleep: async () => {},
      provenance: provenanceClaims,
      fs: outputFileSystem().fileSystem,
    });
    reports.push(report);
    assert.equal(report.overall, 'pass');
    assert.equal(report.schema_version, 3);
    assert.equal(report.environment_digest, ENVIRONMENT_DIGEST);
    assert.equal(Object.hasOwn(report, 'environment'), false);
    assert.equal(report.attempts.length, 2);
    assert.equal(report.budgets.requests_used, 6);
    assert.equal(report.metadata.observations.observed_version, '1.2.3');
    assert.equal(report.metadata.verifier_commit_sha, baseEnv.VERIFIER_COMMIT_SHA);
    assert.equal(report.metadata.claims.deployment_commit_sha.value, baseEnv.DEPLOYMENT_COMMIT_SHA);
  });
});

test('mixed required version sources fail and never publish an observed stable version', async () => {
  await withEnv(baseEnv, async () => {
    const report = await verify(validated(), {
      now: () => Date.parse('2026-08-26T12:00:00Z'),
      performRequest: async (url, method) => url.hostname === 'cdn.example.com' ? response(200, '', { 'x-release-version': '9.9.9' }) : successTarget(url, method),
      sleep: async () => {}, provenance: provenanceClaims,
      fs: outputFileSystem().fileSystem,
    });
    assert.equal(report.overall, 'fail');
    assert.equal(report.incident, true);
    assert.equal(report.metadata.observations.observed_version, null);
    assert.match(JSON.stringify(report), /target_version:mismatch/);
  });
});

test('pass-fail-pass is a nonincident stability failure', async () => {
  await withEnv(baseEnv, async () => {
    let primaryCalls = 0;
    const report = await verify(validated({ versionSources: [{ id: 'page', target: 'primary', type: 'text_marker', path: '/', required: true, prefix: 'Version: ', suffix: '\n' }] }), {
      now: () => Date.parse('2026-08-26T12:00:00Z'), sleep: async () => {}, provenance: provenanceClaims,
      performRequest: async (url) => {
        primaryCalls += 1;
        const attempt = Math.ceil(primaryCalls / 2);
        return response(200, `${attempt === 2 ? 'Broken' : 'Ready'}\nVersion: 1.2.3\n`);
      },
      fs: outputFileSystem().fileSystem,
    });
    assert.equal(report.overall, 'fail');
    assert.equal(report.code, 'stability_requirement_not_met');
    assert.equal(report.incident, false);
  });
});

test('missing configured Basic Auth still emits a bounded blocked report and evidence', async () => {
  const temporaryRoot = path.resolve(CONTRACT_ROOT, '..', 'verify-mode-auth-temp');
  const resolvedEnvironment = resolvedPathEnvironment(temporaryRoot);
  const output = resolvedOutputFileSystem({ temporaryRoot, authorityRoot: temporaryRoot });
  const outputRoot = path.resolve(process.cwd(), 'verification-output');
  output.directories.add(output.normalize(path.resolve(process.cwd())));
  output.directories.add(output.normalize(path.dirname(resolvedEnvironment.VERIFICATION_CONFIG)));
  output.files.set(output.normalize(resolvedEnvironment.VERIFICATION_CONFIG), '{}');
  let loadConfigCalls = 0;
  await withEnv({ ...baseEnv, ...resolvedEnvironment, TARGET_BASIC_AUTH_USERNAME: undefined, TARGET_BASIC_AUTH_PASSWORD: undefined }, async () => {
    const report = await runVerifyMode({
      loadConfig: (configPath) => {
        loadConfigCalls += 1;
        assert.equal(path.resolve(configPath), resolvedEnvironment.VERIFICATION_CONFIG);
        return validated({ basicAuth: true });
      },
      now: () => Date.parse('2026-08-26T12:00:00Z'),
      fs: output.fileSystem,
    });
    assert.equal(report.overall, 'blocked');
    assert.equal(report.code, 'config:target_basic_auth_missing_or_invalid');
    assert.equal(report.management_eligible, false);
    assert.equal(report.metadata.observations.provenance, null);
    const payload = parseManagementPayload(encode(__test.managementPayload(report)));
    assert.equal(payload.management_eligible, false);
    assert.equal(await manageIssue(payload, async () => assert.fail('ineligible setup must not call GitHub')), 'no_issue');
    assert.equal(output.files.has(output.normalize(path.join(outputRoot, 'report.json'))), true);
    assert.equal(output.files.has(output.normalize(path.join(outputRoot, 'junit.xml'))), true);
  });
  assert.equal(loadConfigCalls, 1);
  assert.equal(output.calls.some((call) => call.operation === 'read' && call.path === TEMPLATE_PATH), false);
});

test('invalid setup is blocked and explicitly ineligible for incident management', async () => {
  const temporaryRoot = path.resolve(CONTRACT_ROOT, '..', 'verify-mode-redaction-temp');
  const resolvedEnvironment = resolvedPathEnvironment(temporaryRoot);
  const output = resolvedOutputFileSystem({ temporaryRoot, authorityRoot: temporaryRoot });
  output.directories.add(output.normalize(path.resolve(process.cwd())));
  output.directories.add(output.normalize(path.dirname(resolvedEnvironment.VERIFICATION_CONFIG)));
  output.files.set(output.normalize(resolvedEnvironment.VERIFICATION_CONFIG), '{}');
  let loadConfigCalls = 0;
  await withEnv({ ...baseEnv, ...resolvedEnvironment }, async () => {
    const report = await runVerifyMode({
      loadConfig: (configPath) => {
        loadConfigCalls += 1;
        assert.equal(path.resolve(configPath), resolvedEnvironment.VERIFICATION_CONFIG);
        throw new Error('secret\n::warning::never');
      },
      now: () => Date.parse('2026-08-26T12:00:00Z'),
      fs: output.fileSystem,
    });
    assert.equal(report.overall, 'blocked');
    assert.equal(report.management_eligible, false);
    assert.doesNotMatch(JSON.stringify(report), /secret|warning|never/iu);
  });
  assert.equal(loadConfigCalls, 1);
  assert.equal(output.calls.some((call) => call.operation === 'read' && call.path === TEMPLATE_PATH), false);
});

test('JUnit reports real counts and all emitted evidence remains redacted', async () => {
  const report = await withEnv(baseEnv, async () => __test.blockedReport(Object.assign(new Error('password=hunter2\n::error::x'), { code: 'BAD\n::warning::x' }), validated(), { now: () => Date.parse('2026-08-26T12:00:00Z') }));
  const xml = __test.junitXml(report);
  assert.match(xml, /tests="1" failures="0" errors="1"/);
  assert.doesNotMatch(`${JSON.stringify(report)}${xml}`, /hunter2|password=|::error::/iu);
  assert.match(report.code, /^[a-z0-9_:.-]+$/u);
});

test('engine preflight emits the full Environment digest and rejects untrusted invocations', async () => {
  const request = async (method, endpoint) => {
    assert.equal(method, 'GET');
    if (endpoint === '/repos/owner/plugin') return { status: 200, body: { visibility: 'public', private: false }, headers: {} };
    if (endpoint.includes('/environments/preview')) return { status: 200, body: {}, headers: {} };
    assert.fail(endpoint);
  };
  await withEnv(baseEnv, async () => {
    const result = await preflight(validated(), request);
    assert.equal(result.environment_digest, ENVIRONMENT_DIGEST);
    assert.match(result.environment_digest, /^[0-9a-f]{64}$/u);
    assert.equal(Object.hasOwn(result, 'environment'), false);
  });
  await withEnv({ ...baseEnv, GITHUB_EVENT_NAME: 'workflow_call', INVOCATION_KIND: 'call', MANUAL_INSTALL_CONFIRMED: 'false', DEPLOYMENT_CONCLUSION: 'success', CLAIM_SOURCE: 'deployment_caller' }, async () => assert.equal((await preflight(validated(), request)).provenance.status, 'owner_assertion'));
  await withEnv({ ...baseEnv, GITHUB_EVENT_NAME: 'pull_request' }, async () => assert.rejects(preflight(validated(), request), /untrusted_pr_event_forbidden/));
  await withEnv({ ...baseEnv, MANUAL_INSTALL_CONFIRMED: 'false' }, async () => assert.rejects(preflight(validated(), request), /manual_install_not_confirmed/));
});

test('preflight distinguishes inaccessible environments and non-public repositories', async () => {
  await withEnv(baseEnv, async () => {
    await assert.rejects(preflight(validated(), async () => ({ status: 200, body: { visibility: 'private', private: true }, headers: {} })), /repository_must_be_public/);
    let count = 0;
    await assert.rejects(preflight(validated(), async () => ++count === 1 ? { status: 200, body: { visibility: 'public', private: false }, headers: {} } : { status: 404, body: {}, headers: {} }), /environment_not_found_or_inaccessible/);
  });
});

test('required GitHub release provenance binds release, asset, tag and deployment commit', async () => {
  await withEnv(baseEnv, async () => {
    const config = validated({ provenanceMode: 'github_release_required' });
    const calls = [];
    const request = async (method, endpoint) => {
      calls.push(endpoint);
      if (endpoint === '/repos/owner/plugin') return { status: 200, body: { visibility: 'public', private: false }, headers: {} };
      if (endpoint.includes('/environments/preview')) return { status: 200, body: {}, headers: {} };
      if (endpoint.includes('/releases/tags/')) return { status: 200, body: { id: 77, tag_name: 'v1.2.3', draft: false, prerelease: false, assets: [{ id: 88, name: 'plugin-1.2.3.zip', size: 1234, digest: `sha256:${'a'.repeat(64)}` }] }, headers: {} };
      if (endpoint.includes('/git/ref/tags/')) return { status: 200, body: { object: { type: 'tag', sha: '4'.repeat(40) } }, headers: {} };
      if (endpoint.includes('/git/tags/')) return { status: 200, body: { object: { type: 'commit', sha: '1'.repeat(40) } }, headers: {} };
      assert.fail(endpoint);
    };
    const result = await preflight(config, request);
    assert.equal(result.provenance.status, 'verified');
    assert.equal(result.provenance.release_tag_commit_sha, baseEnv.DEPLOYMENT_COMMIT_SHA);
    assert.equal(calls.length, 5);
    const mismatchRequest = async (method, endpoint) => endpoint.includes('/git/tags/') ? { status: 200, body: { object: { type: 'commit', sha: '9'.repeat(40) } }, headers: {} } : request(method, endpoint);
    await assert.rejects(preflight(config, mismatchRequest), /provenance_deployment_commit_mismatch/);
  });
});

test('GitHub control requests retain only safe rate-limit headers', async () => {
  await withEnv({ GITHUB_TOKEN: 'not-recorded' }, async () => {
    const result = await githubRequest('GET', '/repos/owner/plugin', undefined, { httpsRequest: fakeHttpsResponse({ body: '{}', headers: { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': '123', 'set-cookie': 'secret=x', 'x-private': 'no' } }) });
    assert.deepEqual(result.headers, { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': '123' });
    assert.equal(__test.githubFailure(result, 'repository').code, 'github_control:repository_rate_limit');
  });
});

test('Environment identity is domain-separated full SHA-256 and never emitted raw', async () => {
  const expected = crypto.createHash('sha256').update('hal-release-verification:environment:v1\0preview', 'utf8').digest('hex');
  assert.equal(__test.environmentDigest('preview'), expected);
  assert.equal(expected, ENVIRONMENT_DIGEST);
  assert.match(expected, /^[0-9a-f]{64}$/u);
  assert.notEqual(expected, crypto.createHash('sha256').update('preview', 'utf8').digest('hex'));
  assert.notEqual(__test.environmentDigest('Preview'), expected);
  assert.throws(() => __test.environmentDigest('bad\nenvironment'), /environment_digest_source_invalid/);

  const report = __test.blockedReport(new Error('opaque'), validated(), { now: () => Date.parse('2026-08-26T12:00:00Z') });
  const payload = __test.managementPayload(report);
  assert.equal(report.schema_version, 3);
  assert.equal(report.environment_digest, expected);
  assert.equal(payload.schema_version, 3);
  assert.equal(payload.environment_digest, expected);
  assert.equal(Object.hasOwn(report, 'environment'), false);
  assert.equal(Object.hasOwn(payload, 'environment'), false);

  const incident = management();
  const body = __test.issueBody(incident, 'b'.repeat(24));
  assert.match(body, new RegExp(expected, 'u'));
  assert.doesNotMatch(body, /\bpreview\b/u);
  assert.match(__test.groupMarker(incident), /^<!-- release-verification-group:[0-9a-f]{32} -->$/u);
  assert.match(__test.issueMarker(incident, 'b'.repeat(24)), /^<!-- release-verification:[0-9a-f]{32} -->$/u);
  const recordText = __test.issueRecord(incident, 'b'.repeat(24));
  const encodedRecord = recordText.match(/release-verification-record:([A-Za-z0-9_-]+)/u)?.[1] ?? '';
  const decodedRecord = JSON.parse(Buffer.from(encodedRecord, 'base64url').toString('utf8'));
  assert.equal(decodedRecord.schema_version, 3);
  assert.deepEqual(Object.keys(decodedRecord).sort(), ['claims', 'code', 'completed_at', 'config_digest', 'current_fingerprint', 'environment_digest', 'incident', 'incident_fingerprints', 'management_eligible', 'observations', 'overall', 'repository', 'run_attempt', 'run_id', 'run_url', 'schema_version', 'verifier_commit_sha', 'workflow_sha']);
  const parsedRecord = __test.parseIssueRecord(recordText);
  assert.equal(parsedRecord.payload.environment_digest, expected);
  assert.equal(Object.hasOwn(parsedRecord.payload, 'environment'), false);

  let query = '';
  await __test.searchIssues(incident, 'version', async (method, endpoint) => { assert.equal(method, 'GET'); query = decodeURIComponent(endpoint); return searchResult([]); });
  assert.match(query, new RegExp(expected, 'u'));
  assert.doesNotMatch(query, /\bpreview\b/u);
});

test('report and management schema-v3 allowlists reject legacy, malformed, extra and duplicate identity fields', () => {
  const valid = management();
  assert.deepEqual(parseManagementPayload(encode(valid)), valid);
  assert.deepEqual(Object.keys(valid).sort(), ['claims', 'code', 'completed_at', 'config_digest', 'environment_digest', 'incident', 'incident_fingerprints', 'management_eligible', 'observations', 'overall', 'repository', 'run_attempt', 'run_id', 'run_url', 'schema_version', 'verifier_commit_sha', 'workflow_sha']);
  assert.throws(() => parseManagementPayload(encode(management({ run_url: 'https://evil.example/' }))), /run_url_mismatch/);
  assert.throws(() => parseManagementPayload(encode(management({ overall: 'pass', code: 'stable_pass', incident: true }))), /management_pass_inconsistent|management_incident/);
  assert.throws(() => parseManagementPayload(encode({ ...valid, extra: true })), /unknown_key/);
  assert.throws(() => parseManagementPayload(encode({ ...valid, target_url: 'https://private.example/' })), /unknown_key/);
  assert.throws(() => parseManagementPayload(encode({ ...valid, environment_digest: 'a'.repeat(63) })), /management_environment_digest_invalid/);
  const missing = { ...valid }; delete missing.environment_digest;
  assert.throws(() => parseManagementPayload(encode(missing)), /management_environment_digest_invalid/);
  const legacy = { ...valid, schema_version: 2, environment: 'preview' }; delete legacy.environment_digest;
  assert.throws(() => parseManagementPayload(encode(legacy)), /unknown_key|management_payload_schema_invalid/);
  const duplicate = JSON.stringify(valid).replace(`"environment_digest":"${ENVIRONMENT_DIGEST}"`, `"environment_digest":"${'0'.repeat(64)}","environment_digest":"${ENVIRONMENT_DIGEST}"`);
  assert.throws(() => parseManagementPayload(encodeText(duplicate)), /management_payload_invalid/);
});

test('public evidence allowlist excludes site values even when errors or base64url transport contain them', () => {
  const prohibited = ['https://private.example/base/', '/secret/request/path', 'x-private-version', 'literal-site-marker', 'private-password', 'verification-config.resolved.json', 'runner-temp-private', 'raw failure detail'];
  const report = __test.blockedReport(new Error(prohibited.join(' ')), validated(), { now: () => Date.parse('2026-08-26T12:00:00Z') });
  const payload = __test.managementPayload(report);
  const xml = __test.junitXml(report);
  const evidence = `${JSON.stringify(report)}\n${JSON.stringify(payload)}\n${xml}`;
  for (const value of prohibited) assert.doesNotMatch(evidence, new RegExp(value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&'), 'iu'));
  assert.deepEqual(Object.keys(report).sort(), ['attempts', 'budgets', 'code', 'completed_at', 'environment_digest', 'incident', 'incident_fingerprints', 'management_eligible', 'metadata', 'overall', 'schema_version', 'scope_notice', 'started_at']);
  assert.throws(() => parseManagementPayload(encode({ ...management(), headers: { authorization: 'Basic hidden' } })), /unknown_key/);
});

test('engine GitHub outputs use the exact PB1 public allowlist and omit raw Environment identity', () => {
  const engine = engineDocument();
  const outputNames = [...engine.matchAll(/writeGithubOutput\('([a-z_]+)'/gu)].map((match) => match[1]);
  assert.deepEqual([...new Set(outputNames)].sort(), ['basic_auth_required', 'config_digest', 'environment_digest', 'management_payload', 'overall', 'provenance_payload']);
  assert.doesNotMatch(engine, /writeGithubOutput\('environment'/u);
  assert.doesNotMatch(engine, /environment:\s*(?:report|config\.selectedEnvironment|payload\.environment_digest)/u);
});

test('GitHub outputs and summaries expose only schema-v3 digest identity', async () => {
  const output = outputFileSystem();
  const githubOutputPath = path.resolve(process.cwd(), 'github-output.txt');
  const summaryPath = path.resolve(process.cwd(), 'github-summary.txt');
  await withEnv({ OUTPUT_DIR: undefined, GITHUB_OUTPUT: githubOutputPath, GITHUB_STEP_SUMMARY: summaryPath }, async () => {
    const report = __test.blockedReport(new Error('opaque'), validated(), { now: () => Date.parse('2026-08-26T12:00:00Z') });
    __test.emitReport(report, LIMITS, { fs: output.fileSystem });
  });
  const githubOutput = output.files.get(output.normalize(githubOutputPath));
  const summary = output.files.get(output.normalize(summaryPath));
  assert.match(githubOutput, /^overall=blocked\nmanagement_payload=[A-Za-z0-9_-]+\n$/u);
  assert.doesNotMatch(githubOutput, /\benvironment=|\bpreview\b/u);
  assert.match(summary, new RegExp(ENVIRONMENT_DIGEST, 'u'));
  assert.doesNotMatch(summary, /\bpreview\b/u);
  const encodedPayload = githubOutput.match(/^management_payload=([A-Za-z0-9_-]+)$/mu)?.[1] ?? '';
  const payload = parseManagementPayload(encodedPayload);
  assert.equal(payload.schema_version, 3);
  assert.equal(payload.environment_digest, ENVIRONMENT_DIGEST);
});

test('legacy or inconsistent embedded issue records are ignored without lifecycle mutation', async () => {
  const legacy = { ...management(), schema_version: 2, environment: 'preview', current_fingerprint: 'b'.repeat(24) };
  delete legacy.environment_digest;
  const legacyBody = `<!-- release-verification-record:${encode(legacy)} -->`;
  const mismatched = management({ environment_digest: '0'.repeat(64) });
  const mismatchedBody = __test.issueBody(mismatched, 'b'.repeat(24));
  const duplicateJson = JSON.stringify({ ...management(), current_fingerprint: 'b'.repeat(24) }).replace(`"environment_digest":"${ENVIRONMENT_DIGEST}"`, `"environment_digest":"${ENVIRONMENT_DIGEST}","environment_digest":"${ENVIRONMENT_DIGEST}"`);
  const duplicateBody = `<!-- release-verification-record:${encodeText(duplicateJson)} -->`;
  const extraBody = `<!-- release-verification-record:${encode({ ...management(), current_fingerprint: 'b'.repeat(24), target_url: 'https://private.example/' })} -->`;
  const malformedDigestBody = __test.issueRecord(management({ environment_digest: 'bad' }), 'b'.repeat(24));
  assert.equal(__test.parseIssueRecord(legacyBody), null);
  assert.equal(__test.parseIssueRecord(duplicateBody), null);
  assert.equal(__test.parseIssueRecord(extraBody), null);
  assert.equal(__test.parseIssueRecord(malformedDigestBody), null);

  const recovery = management({ run_id: '101', run_url: 'https://github.com/owner/plugin/actions/runs/101', overall: 'pass', code: 'stable_pass', incident: false, incident_fingerprints: [], observations: { observed_version: '1.2.3', provenance: provenanceClaims }, completed_at: '2026-08-26T12:01:00.000Z' });
  for (const body of [legacyBody, duplicateBody, extraBody, malformedDigestBody, mismatchedBody]) {
    let writes = 0;
    const issue = { number: 90, state: 'open', user: ACTIONS_BOT, body };
    assert.equal(await manageIssue(recovery, async (method) => method === 'GET' ? searchResult([issue]) : (writes += 1, { status: 200, body: {}, headers: {} })), 'recovered');
    assert.equal(writes, 0);
  }
});

test('nonincident results never search or write Issues', async () => {
  const result = await manageIssue(management({ incident: false, incident_fingerprints: [], code: 'stability_requirement_not_met' }), async () => assert.fail('GitHub must not be called'));
  assert.equal(result, 'no_issue');
});

test('forged public Issues cannot poison, update, or close the automation lifecycle', async () => {
  const future = management({ run_id: '999', run_url: 'https://github.com/owner/plugin/actions/runs/999', completed_at: '2026-08-26T23:00:00.000Z' });
  const forged = { number: 66, state: 'open', user: { login: 'public-user', type: 'User' }, body: __test.issueBody(future, 'b'.repeat(24)) };
  const wrongType = { number: 67, state: 'open', user: { login: 'github-actions[bot]', type: 'User' }, body: __test.issueBody(future, 'b'.repeat(24)) };
  const writes = [];
  assert.equal(await manageIssue(management(), async (method, endpoint, body) => { if (method === 'GET') return searchResult([forged, wrongType]); writes.push({ method, endpoint, body }); return { status: 201, body: {}, headers: {} }; }), 'changed');
  assert.deepEqual(writes.map((item) => item.method), ['POST']);

  const recovery = management({ run_id: '101', run_url: 'https://github.com/owner/plugin/actions/runs/101', overall: 'pass', code: 'stable_pass', incident: false, incident_fingerprints: [], observations: { observed_version: '1.2.3', provenance: provenanceClaims }, completed_at: '2026-08-26T12:01:00.000Z' });
  let recoveryWrites = 0;
  assert.equal(await manageIssue(recovery, async (method) => method === 'GET' ? searchResult([forged, wrongType]) : (recoveryWrites += 1, { status: 200, body: {}, headers: {} })), 'recovered');
  assert.equal(recoveryWrites, 0);
});

test('121 forged matching Issues cannot flood out a real incident creation', async () => {
  const future = management({ run_id: '999', run_url: 'https://github.com/owner/plugin/actions/runs/999', completed_at: '2026-08-26T23:00:00.000Z' });
  const forged = Array.from({ length: 121 }, (_, index) => ({ number: 1000 + index, state: 'open', user: { login: `public-user-${index}`, type: 'User' }, body: __test.issueBody(future, 'b'.repeat(24)) }));
  const calls = [];
  let searchPage = 0;
  const result = await manageIssue(management(), async (method, endpoint, body) => {
    calls.push({ method, endpoint, body });
    if (method === 'GET') return ++searchPage === 1 ? searchResult(forged) : searchResult([]);
    return { status: 201, body: {}, headers: {} };
  });
  assert.equal(result, 'changed');
  assert.deepEqual(calls.filter((call) => call.method !== 'GET').map((call) => call.method), ['POST']);
  assert.ok(calls.filter((call) => call.method === 'GET').every((call) => decodeURIComponent(call.endpoint).includes('author:app/github-actions')));
});

test('mixed forged and trusted results derive lifecycle decisions only from the bot record', async () => {
  const forgedFuture = management({ run_id: '999', run_url: 'https://github.com/owner/plugin/actions/runs/999', completed_at: '2026-08-26T23:00:00.000Z' });
  const trustedOlder = management({ run_id: '99', run_url: 'https://github.com/owner/plugin/actions/runs/99', completed_at: '2026-08-26T11:59:00.000Z' });
  const forged = { number: 70, state: 'open', user: { login: 'public-user', type: 'User' }, body: __test.issueBody(forgedFuture, 'b'.repeat(24)) };
  const trusted = { number: 71, state: 'open', user: ACTIONS_BOT, body: __test.issueBody(trustedOlder, 'b'.repeat(24)) };
  const writes = [];
  assert.equal(await manageIssue(management(), async (method, endpoint, body) => { if (method === 'GET') return searchResult([forged, trusted]); writes.push({ method, endpoint, body }); return { status: 200, body: {}, headers: {} }; }), 'changed');
  assert.deepEqual(writes.map((item) => [item.method, item.endpoint]), [['PATCH', '/repos/owner/plugin/issues/71']]);
});

test('forged flooding cannot block trusted recovery or supersession', async () => {
  const forgedPayload = management({ run_id: '999', run_url: 'https://github.com/owner/plugin/actions/runs/999', completed_at: '2026-08-26T23:00:00.000Z' });
  const forged = Array.from({ length: 121 }, (_, index) => ({ number: 2000 + index, state: 'open', user: { login: `public-${index}`, type: 'User' }, body: __test.issueBody(forgedPayload, 'b'.repeat(24)) }));
  const trustedIncident = { number: 80, state: 'open', user: ACTIONS_BOT, body: __test.issueBody(management(), 'b'.repeat(24)) };
  const recovery = management({ run_id: '102', run_url: 'https://github.com/owner/plugin/actions/runs/102', overall: 'pass', code: 'stable_pass', incident: false, incident_fingerprints: [], observations: { observed_version: '1.2.3', provenance: provenanceClaims }, completed_at: '2026-08-26T12:02:00.000Z' });
  const recoveryWrites = [];
  let recoveryPage = 0;
  await manageIssue(recovery, async (method, endpoint, body) => { if (method === 'GET') return ++recoveryPage === 1 ? searchResult([...forged, trustedIncident]) : searchResult([]); recoveryWrites.push({ endpoint, body }); return { status: 200, body: {}, headers: {} }; });
  assert.deepEqual(recoveryWrites.map((item) => item.endpoint), ['/repos/owner/plugin/issues/80']);

  const verified = { mode: 'github_release_required', status: 'verified', github_release_id: '77', release_tag_commit_sha: '1'.repeat(40), asset: { id: '88', name: 'plugin-1.2.4.zip', size: 1234, digest: `sha256:${'a'.repeat(64)}` } };
  const newer = management({ run_id: '200', run_url: 'https://github.com/owner/plugin/actions/runs/200', completed_at: '2026-08-26T13:00:00.000Z', overall: 'pass', code: 'stable_pass', incident: false, incident_fingerprints: [], claims: { ...management().claims, expected_version: { value: '1.2.4', source: 'manual_operator' }, release_id: { value: 'v1.2.4', source: 'manual_operator' } }, observations: { observed_version: '1.2.4', provenance: verified } });
  const oldTrusted = { number: 81, state: 'open', user: ACTIONS_BOT, body: __test.issueBody(management(), 'b'.repeat(24)) };
  const supersedeWrites = [];
  let search = 0;
  await manageIssue(newer, async (method, endpoint, body) => {
    if (method === 'GET') {
      search += 1;
      if (search === 1 || search === 2) return searchResult(search === 1 ? forged : []);
      return searchResult(search === 3 ? [...forged, oldTrusted] : []);
    }
    supersedeWrites.push({ endpoint, body }); return { status: 200, body: {}, headers: {} };
  });
  assert.deepEqual(supersedeWrites.map((item) => item.endpoint), ['/repos/owner/plugin/issues/81']);
});

test('trusted automation search is bounded to two pages and 120 records', async () => {
  const payload = management();
  const botIssues = (start, count) => Array.from({ length: count }, (_, index) => ({ number: start + index, state: 'open', user: ACTIONS_BOT, body: __test.issueBody(payload, 'b'.repeat(24)) }));
  let calls = 0;
  await assert.rejects(__test.searchIssues(payload, 'version', async (method, endpoint) => {
    calls += 1;
    assert.equal(method, 'GET');
    assert.match(decodeURIComponent(endpoint), /author:app\/github-actions/u);
    return calls === 1 ? searchResult(botIssues(1, 100)) : searchResult(botIssues(101, 21));
  }), /trusted_issue_search_limit/);
  assert.equal(calls, 2);

  calls = 0;
  const bounded = await __test.searchIssues(payload, 'version', async () => ++calls === 1 ? searchResult(botIssues(1, 100)) : searchResult(botIssues(101, 20)));
  assert.equal(bounded.length, 120);
  assert.equal(calls, 2);
});

test('repeated fingerprints create exact marked issues and deduplicate stale runs', async () => {
  const payload = management({ incident_fingerprints: ['b'.repeat(24), 'c'.repeat(24)] });
  const calls = [];
  const request = async (method, endpoint, body) => { calls.push({ method, endpoint, body }); return method === 'GET' ? searchResult([]) : { status: 201, body: {}, headers: {} }; };
  assert.equal(await manageIssue(payload, request), 'changed');
  assert.equal(calls.filter((call) => call.method === 'POST').length, 2);
  const firstPost = calls.find((call) => call.method === 'POST');
  assert.match(firstPost.body.title, new RegExp(ENVIRONMENT_DIGEST, 'u'));
  assert.doesNotMatch(firstPost.body.title, /\bpreview\b/u);
  assert.match(firstPost.body.body, /release-verification-record:/u);

  const stalePayload = management({ incident_fingerprints: ['b'.repeat(24)] });
  const newer = management({ run_id: '101', run_url: 'https://github.com/owner/plugin/actions/runs/101', completed_at: '2026-08-26T12:01:00.000Z' });
  const issue = { number: 7, state: 'open', body: __test.issueBody(newer, 'b'.repeat(24)) };
  assert.ok(__test.parseIssueRecord(issue.body));
  let writes = 0;
  assert.equal(await manageIssue(stalePayload, async (method) => method === 'GET' ? searchResult([issue]) : (writes += 1, { status: 201, body: {}, headers: {} })), 'stale_noop');
  assert.equal(writes, 0);
});

test('recovery closes only newer matching incidents and preserves original evidence', async () => {
  const incident = management();
  const issue = { number: 9, state: 'open', body: __test.issueBody(incident, 'b'.repeat(24)) };
  const recovery = management({ run_id: '102', run_url: 'https://github.com/owner/plugin/actions/runs/102', run_attempt: '2', completed_at: '2026-08-26T12:03:00.000Z', overall: 'pass', code: 'stable_pass', incident: false, incident_fingerprints: [], observations: { observed_version: '1.2.3', provenance: provenanceClaims } });
  const writes = [];
  assert.equal(await manageIssue(recovery, async (method, endpoint, body) => { if (method === 'GET') return searchResult([issue]); writes.push({ endpoint, body }); return { status: 200, body: {}, headers: {} }; }), 'recovered');
  assert.equal(writes.length, 1);
  assert.match(writes[0].body.body, /repeated incident[\s\S]*### Recovery/u);
  const recoveredRecord = __test.parseIssueRecord(writes[0].body.body);
  assert.equal(recoveredRecord.payload.run_id, '102');
  assert.equal(recoveredRecord.payload.overall, 'pass');
});

test('recovery freshness record prevents an older incident from reopening', async () => {
  const incident100 = management();
  const original = { number: 21, state: 'open', body: __test.issueBody(incident100, 'b'.repeat(24)) };
  const recovery102 = management({ run_id: '102', run_url: 'https://github.com/owner/plugin/actions/runs/102', completed_at: '2026-08-26T12:02:00.000Z', overall: 'pass', code: 'stable_pass', incident: false, incident_fingerprints: [], observations: { observed_version: '1.2.3', provenance: provenanceClaims } });
  let recoveryBody;
  await manageIssue(recovery102, async (method, endpoint, body) => { if (method === 'GET') return searchResult([original]); recoveryBody = body.body; return { status: 200, body: {}, headers: {} }; });
  const recovered = { number: 21, state: 'closed', body: recoveryBody };
  assert.equal(__test.parseIssueRecord(recovered.body).payload.run_id, '102');

  const stale101 = management({ run_id: '101', run_url: 'https://github.com/owner/plugin/actions/runs/101', completed_at: '2026-08-26T12:01:00.000Z' });
  let staleWrites = 0;
  assert.equal(await manageIssue(stale101, async (method) => method === 'GET' ? searchResult([recovered]) : (staleWrites += 1, { status: 200, body: {}, headers: {} })), 'stale_noop');
  assert.equal(staleWrites, 0);
});

test('supersession requires a newer proven and observed stable release', async () => {
  const verified = { mode: 'github_release_required', status: 'verified', github_release_id: '77', release_tag_commit_sha: '1'.repeat(40), asset: { id: '88', name: 'plugin-1.2.4.zip', size: 1234, digest: `sha256:${'a'.repeat(64)}` } };
  const oldPayload = management();
  const oldIssue = { number: 11, state: 'open', body: __test.issueBody(oldPayload, 'b'.repeat(24)) };
  const current = management({ run_id: '200', run_url: 'https://github.com/owner/plugin/actions/runs/200', completed_at: '2026-08-26T13:00:00.000Z', overall: 'pass', code: 'stable_pass', incident: false, incident_fingerprints: [], claims: { ...oldPayload.claims, expected_version: { value: '1.2.4', source: 'manual_operator' }, release_id: { value: 'v1.2.4', source: 'manual_operator' } }, observations: { observed_version: '1.2.4', provenance: verified } });
  let searches = 0; const writes = [];
  await manageIssue(current, async (method, endpoint, body) => { if (method === 'GET') return ++searches === 1 ? searchResult([]) : searchResult([oldIssue]); writes.push({ endpoint, body }); return { status: 200, body: {}, headers: {} }; });
  assert.equal(writes.length, 1);
  assert.equal(writes[0].body.state_reason, 'not_planned');
  assert.match(writes[0].body.body, /### Superseded/u);
  assert.equal(__test.parseIssueRecord(writes[0].body.body).payload.run_id, '200');
});

test('artifact inventory is exactly two small sanitized evidence files', async () => {
  const output = outputFileSystem();
  await withEnv({ ...baseEnv, OUTPUT_DIR: undefined }, async () => {
    const report = __test.blockedReport(new Error('opaque setup error'), validated(), { now: () => Date.parse('2026-08-26T12:00:00Z') });
    __test.outputFiles(report, LIMITS, { fs: output.fileSystem });
  });
  const names = [...output.files.keys()].map((name) => path.basename(name)).sort();
  assert.deepEqual(names, ['junit.xml', 'report.json']);
  const evidence = [...output.files.values()].join('\n');
  assert.ok(Buffer.byteLength(evidence) < LIMITS.max_artifact_bytes);
  assert.doesNotMatch(evidence, /cookie|authorization|password|query string=|stack trace:/iu);
  for (const name of ['report.json', 'junit.xml']) {
    const candidate = path.join(output.root, name);
    const createdAt = output.calls.findIndex((item) => item.operation === 'open' && item.path === candidate);
    const canonicalizedAt = output.calls.findIndex((item, index) => index > createdAt && item.operation === 'realpath' && item.path === candidate);
    const writtenAt = output.calls.findIndex((item) => item.operation === 'write' && item.path === candidate);
    assert.ok(createdAt >= 0 && canonicalizedAt > createdAt && writtenAt > canonicalizedAt, name);
  }
});

test('output contract rejects absolute overrides, traversal and noncanonical roots', async () => {
  const report = __test.blockedReport(new Error('opaque setup error'), validated(), { now: () => Date.parse('2026-08-26T12:00:00Z') });
  for (const [override, pattern] of [
    [path.resolve('verification-output'), /output_override_must_be_relative/],
    ['other/../verification-output', /output_traversal_forbidden/],
    ['other-output', /output_override_outside_contract/],
  ]) {
    await withEnv({ OUTPUT_DIR: override }, async () => {
      assert.throws(() => __test.outputFiles(report, LIMITS, { fs: outputFileSystem().fileSystem }), pattern);
    });
  }

  const root = path.resolve(process.cwd(), 'verification-output');
  const outside = path.resolve(process.cwd(), '..', 'outside-output');
  const escapedRoot = outputFileSystem({ links: [[root, outside]] });
  await withEnv({ OUTPUT_DIR: undefined }, async () => {
    assert.throws(() => __test.outputFiles(report, LIMITS, { fs: escapedRoot.fileSystem }), /output_ancestor_escape/);
  });

  const escapedFile = outputFileSystem({ links: [[path.join(root, 'report.json'), path.join(outside, 'report.json')]] });
  await withEnv({ OUTPUT_DIR: undefined }, async () => {
    assert.throws(() => __test.outputFiles(report, LIMITS, { fs: escapedFile.fileSystem }), /output_file_ancestor_escape/);
  });
});

test('portable binding names are adaptable while keys and semantics remain exact', () => {
  const canonical = templateDocument();
  assert.equal(__test.validateConfigTemplate(structuredClone(canonical)).document_kind, 'verification-config-template');
  const adapted = structuredClone(canonical);
  let index = 0;
  for (const binding of Object.values(adapted.bindings)) binding.environment_variable = `SITE_INPUT_${String(index += 1).padStart(2, '0')}`;
  assert.equal(__test.validateConfigTemplate(structuredClone(adapted)).bindings.primary_origin.environment_variable, 'SITE_INPUT_03');

  const values = bindingEnvironment(adapted);
  values.UNRELATED_RUNTIME_VALUE = 'must-not-be-read';
  const reads = [];
  const environment = new Proxy(values, {
    get(target, property, receiver) { if (typeof property === 'string') reads.push(property); return Reflect.get(target, property, receiver); },
    ownKeys() { assert.fail('resolver must not enumerate the surrounding environment'); },
  });
  const resolved = __test.resolveConfigBindings(adapted, environment);
  assert.deepEqual(Object.keys(resolved.environments), [ENVIRONMENT_DIGEST]);
  assert.deepEqual([...new Set(reads)].sort(), [...Object.values(adapted.bindings).map((binding) => binding.environment_variable), 'TARGET_ENVIRONMENT'].sort());
  assert.equal(reads.includes('UNRELATED_RUNTIME_VALUE'), false);

  for (const mutate of [
    (copy) => { copy.bindings.primary_origin.required = false; },
    (copy) => { copy.bindings.primary_origin.value_type = 'literal_text'; },
    (copy) => { copy.bindings.cdn_origin.on_missing = 'retain_empty'; },
    (copy) => { copy.bindings.cdn_check_path.required_when_binding_present = 'primary_origin'; },
    (copy) => { copy.bindings.primary_origin.sensitive = true; },
    (copy) => { copy.bindings.unapproved = structuredClone(copy.bindings.primary_origin); },
  ]) {
    const copy = structuredClone(canonical); mutate(copy);
    assert.throws(() => __test.validateConfigTemplate(copy));
  }
});

test('binding names reject invalid, duplicate, reserved and platform-controlled spellings', () => {
  const forbidden = [
    'VERIFICATION_CONFIG_TEMPLATE', 'VERIFICATION_TEMP_ROOT', 'VERIFICATION_CONFIG', 'TARGET_ENVIRONMENT',
    'TARGET_BASIC_AUTH_USERNAME', 'TARGET_BASIC_AUTH_PASSWORD', 'GITHUB_TOKEN', 'NODE_OPTIONS',
    'GITHUB_SHA', 'RUNNER_TEMP_VALUE', 'ACTIONS_STEP_DEBUG', '1INVALID', 'lowercase', 'HAS-DASH', `A${'B'.repeat(128)}`,
  ];
  for (const name of forbidden) {
    const copy = templateDocument();
    copy.bindings.primary_origin.environment_variable = name;
    assert.throws(() => __test.validateConfigTemplate(copy), undefined, name);
  }
  const duplicate = templateDocument();
  duplicate.bindings.primary_origin.environment_variable = duplicate.bindings.release_asset_name_template.environment_variable;
  assert.throws(() => __test.validateConfigTemplate(duplicate), /environment_variable_duplicate/);
});

test('resolver fails closed for required and conditional inputs and removes an absent optional CDN', () => {
  const template = templateDocument();
  const absentEnvironment = bindingEnvironment(template, { includeCdn: false });
  const absent = __test.resolveConfigBindings(template, absentEnvironment);
  assert.deepEqual(Object.keys(absent.environments[ENVIRONMENT_DIGEST].targets), ['primary']);
  assert.deepEqual(absent.environments[ENVIRONMENT_DIGEST].checks.map((check) => check.id), ['primary-public']);
  assert.deepEqual(absent.environments[ENVIRONMENT_DIGEST].version_sources.map((source) => source.id), ['primary-version']);

  const present = __test.resolveConfigBindings(template, bindingEnvironment(template));
  assert.deepEqual(Object.keys(present.environments[ENVIRONMENT_DIGEST].targets), ['primary', 'cdn']);
  assert.deepEqual(present.environments[ENVIRONMENT_DIGEST].checks.map((check) => check.id), ['primary-public', 'cdn-public']);
  assert.deepEqual(present.environments[ENVIRONMENT_DIGEST].version_sources.map((source) => source.id), ['primary-version', 'cdn-version']);

  const missingRequired = bindingEnvironment(template); delete missingRequired[template.bindings.primary_origin.environment_variable];
  assert.throws(() => __test.resolveConfigBindings(template, missingRequired), /binding_primary_origin_missing/);
  const invalidRequired = bindingEnvironment(template, { values: { primary_origin: 'http://private.example/' } });
  assert.throws(() => __test.resolveConfigBindings(template, invalidRequired), /binding_primary_origin_https_required/);
  const orphan = bindingEnvironment(template, { includeCdn: false }); orphan[template.bindings.cdn_check_path.environment_variable] = '/orphan.css';
  assert.throws(() => __test.resolveConfigBindings(template, orphan), /binding_cdn_check_path_without_cdn_origin/);
  const contradictory = bindingEnvironment(template, { controls: { TARGET_ENVIRONMENT: 'other' } });
  assert.throws(() => __test.resolveConfigBindings(template, contradictory), /target_environment_control_mismatch/);
  const interpolation = bindingEnvironment(template, { values: { primary_public_marker: '${UNRESOLVED}' } });
  assert.throws(() => __test.resolveConfigBindings(template, interpolation), /raw_interpolation_forbidden/);
});

test('trusted temporary-root authority rejects mismatch, symlink or junction types, overlap, traversal and wrong fixed paths', () => {
  const template = templateDocument();
  const resolved = __test.resolveConfigBindings(template, bindingEnvironment(template, { includeCdn: false }));
  const temporaryRoot = path.resolve(CONTRACT_ROOT, '..', 'isolated-runner-temp');
  const otherRoot = path.resolve(CONTRACT_ROOT, '..', 'other-runner-temp');

  const mismatchFs = resolvedOutputFileSystem({ temporaryRoot, authorityRoot: otherRoot });
  assert.throws(() => __test.createResolvedConfigOutput(resolved, resolvedPathEnvironment(temporaryRoot, { RUNNER_TEMP: otherRoot }), { fs: mismatchFs.fileSystem }), /resolved_temp_root_authority_mismatch/);
  const missingAuthorityFs = resolvedOutputFileSystem({ temporaryRoot });
  assert.throws(() => __test.createResolvedConfigOutput(resolved, resolvedPathEnvironment(temporaryRoot, { RUNNER_TEMP: undefined }), { fs: missingAuthorityFs.fileSystem }), /trusted_temp_root_missing_or_invalid/);
  const nonDirectoryFs = resolvedOutputFileSystem({ temporaryRoot, authorityRoot: temporaryRoot, rootAsFile: true });
  assert.throws(() => __test.createResolvedConfigOutput(resolved, resolvedPathEnvironment(temporaryRoot), { fs: nonDirectoryFs.fileSystem }), /resolved_temp_root_type_forbidden/);
  const linkedFs = resolvedOutputFileSystem({ temporaryRoot, authorityRoot: temporaryRoot, links: [[temporaryRoot, otherRoot]] });
  assert.throws(() => __test.createResolvedConfigOutput(resolved, resolvedPathEnvironment(temporaryRoot), { fs: linkedFs.fileSystem }), /resolved_temp_root_type_forbidden/);
  const linkedChildFs = resolvedOutputFileSystem({ temporaryRoot, authorityRoot: temporaryRoot, directoryLinkTarget: otherRoot });
  assert.throws(() => __test.createResolvedConfigOutput(resolved, resolvedPathEnvironment(temporaryRoot), { fs: linkedChildFs.fileSystem }), /resolved_directory_type_forbidden|partial_resolved_directory_type_forbidden/);

  const repositoryTemporaryRoot = path.join(CONTRACT_ROOT, 'runner-temp');
  const overlapFs = resolvedOutputFileSystem({ temporaryRoot: repositoryTemporaryRoot, authorityRoot: repositoryTemporaryRoot });
  assert.throws(() => __test.createResolvedConfigOutput(resolved, resolvedPathEnvironment(repositoryTemporaryRoot), { fs: overlapFs.fileSystem }), /resolved_temp_root_inside_repository/);
  const wrongPathFs = resolvedOutputFileSystem({ temporaryRoot, authorityRoot: temporaryRoot });
  assert.throws(() => __test.createResolvedConfigOutput(resolved, resolvedPathEnvironment(temporaryRoot, { VERIFICATION_CONFIG: path.join(temporaryRoot, 'different.json') }), { fs: wrongPathFs.fileSystem }), /resolved_config_path_outside_fixed_contract/);
  const traversalPath = `${temporaryRoot}${path.sep}..${path.sep}escape${path.sep}verification-config.resolved.json`;
  assert.throws(() => __test.createResolvedConfigOutput(resolved, resolvedPathEnvironment(temporaryRoot, { VERIFICATION_CONFIG: traversalPath }), { fs: wrongPathFs.fileSystem }), /resolved_config_path_traversal_forbidden/);
});

test('resolved output uses exclusive fixed creation, test-only authority injection and verified non-recursive cleanup', () => {
  const template = templateDocument();
  const temporaryRoot = path.resolve(CONTRACT_ROOT, '..', 'isolated-test-authority');
  const environment = {
    ...bindingEnvironment(template, { includeCdn: false }),
    ...resolvedPathEnvironment(temporaryRoot, { RUNNER_TEMP: undefined }),
    VERIFICATION_CONFIG_TEMPLATE: TEMPLATE_PATH,
  };
  const state = resolvedOutputFileSystem({ temporaryRoot, templateText: JSON.stringify(template) });
  const resolved = __test.resolveConfigTemplate(environment, { fs: state.fileSystem, trustedTemporaryRoot: temporaryRoot });
  const expectedDirectory = path.join(temporaryRoot, 'release-verification-resolved');
  const expectedFile = path.join(expectedDirectory, 'verification-config.resolved.json');
  assert.deepEqual(Object.keys(resolved.environments), [ENVIRONMENT_DIGEST]);
  assert.equal(state.files.has(state.normalize(expectedFile)), true);
  assert.equal(state.calls.find((call) => call.operation === 'open' && call.path === expectedFile)?.flags, 'wx');
  const mkdirAt = state.calls.findIndex((call) => call.operation === 'mkdir' && call.path === expectedDirectory);
  const ancestorRealpathAt = state.calls.findIndex((call) => call.operation === 'realpath' && call.path === temporaryRoot);
  assert.ok(ancestorRealpathAt >= 0 && mkdirAt > ancestorRealpathAt);
  const writeAt = state.calls.findIndex((call) => call.operation === 'write' && call.path === expectedFile);
  const postCreateRealpathAt = state.calls.findIndex((call, index) => index < writeAt && call.operation === 'realpath' && call.path === expectedFile);
  assert.ok(postCreateRealpathAt >= 0 && writeAt > postCreateRealpathAt);
  assert.throws(() => __test.createResolvedConfigOutput(resolved, environment, { fs: state.fileSystem, trustedTemporaryRoot: temporaryRoot }), /resolved_directory_already_exists/);
  assert.equal(__test.cleanupResolvedConfigOutput(environment, { fs: state.fileSystem, trustedTemporaryRoot: temporaryRoot }), 'removed');
  assert.equal(state.files.has(state.normalize(expectedFile)), false);
  assert.equal(state.directories.has(state.normalize(expectedDirectory)), false);
  assert.equal(state.directories.has(state.normalize(temporaryRoot)), true);
  assert.deepEqual(state.calls.filter((call) => call.operation === 'rmdir').map((call) => call.path), [expectedDirectory]);

  const partial = resolvedOutputFileSystem({ temporaryRoot, authorityRoot: temporaryRoot, failWrite: true });
  assert.throws(() => __test.createResolvedConfigOutput(resolved, resolvedPathEnvironment(temporaryRoot), { fs: partial.fileSystem }), /injected-write-failure/);
  assert.equal(partial.files.has(partial.normalize(expectedFile)), false);
  assert.equal(partial.directories.has(partial.normalize(expectedDirectory)), false);
  assert.ok(partial.calls.some((call) => call.operation === 'unlink' && call.path === expectedFile));

  const contaminated = resolvedOutputFileSystem({ temporaryRoot, authorityRoot: temporaryRoot });
  __test.createResolvedConfigOutput(resolved, resolvedPathEnvironment(temporaryRoot), { fs: contaminated.fileSystem });
  contaminated.files.set(contaminated.normalize(path.join(expectedDirectory, 'unexpected.txt')), 'unexpected');
  assert.throws(() => __test.cleanupResolvedConfigOutput(resolvedPathEnvironment(temporaryRoot), { fs: contaminated.fileSystem }), /resolved_cleanup_unexpected_object/);

  const irregular = resolvedOutputFileSystem({ temporaryRoot, authorityRoot: temporaryRoot });
  __test.createResolvedConfigOutput(resolved, resolvedPathEnvironment(temporaryRoot), { fs: irregular.fileSystem });
  irregular.files.delete(irregular.normalize(expectedFile));
  irregular.links.set(irregular.normalize(expectedFile), path.resolve(temporaryRoot, '..', 'escaped-config.json'));
  assert.throws(() => __test.cleanupResolvedConfigOutput(resolvedPathEnvironment(temporaryRoot), { fs: irregular.fileSystem }), /resolved_cleanup_file_type_forbidden/);

  const absent = resolvedOutputFileSystem({ temporaryRoot, authorityRoot: temporaryRoot });
  assert.equal(__test.cleanupResolvedConfigOutput(resolvedPathEnvironment(temporaryRoot), { fs: absent.fileSystem }), 'absent');
});

test('workflow has one global versionless concurrency key and exactly three isolated jobs', () => {
  const workflow = workflowDocument();
  assert.match(workflow, /^permissions: \{\}$/mu);
  assert.match(workflow, /^concurrency:\n  group: release-verification-\$\{\{ github\.repository \}\}\n  cancel-in-progress: true$/mu);
  assert.equal((workflow.match(/^  (?:preflight|verify-target|manage-issue):$/gmu) ?? []).length, 3);
  assert.equal((workflow.match(/^    concurrency:/gmu) ?? []).length, 0);
  const concurrency = workflow.match(/^concurrency:[\s\S]*?^jobs:/mu)?.[0] ?? '';
  assert.doesNotMatch(concurrency, /version|target_environment/iu);

  const preflightJob = workflow.match(/^  preflight:[\s\S]*?(?=^  verify-target:)/mu)?.[0] ?? '';
  assert.match(preflightJob, /^    permissions: \{\}$/mu);
  assert.match(preflightJob, /Validate dispatch and public control-plane claims/u);
  assert.doesNotMatch(preflightJob, /target_environment|TARGET_ENVIRONMENT|\benvironment:|verify\.mjs|actions\/checkout|GITHUB_TOKEN|vars\.|secrets\./u);
});

test('workflow pins actions and uses only the closed CONFIG-R vars and secret boundaries', () => {
  const workflow = workflowDocument();
  const uses = [...workflow.matchAll(/^\s+uses:\s+([^\s#]+)/gmu)].map((match) => match[1]);
  assert.equal(uses.length, 3);
  assert.ok(uses.every((value) => /@[0-9a-f]{40}$/u.test(value)));
  assert.ok(uses.filter((value) => value.startsWith('actions/checkout@')).every((value) => value.endsWith('3d3c42e5aac5ba805825da76410c181273ba90b1')));
  assert.ok(uses.some((value) => value === 'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a'));
  assert.equal((workflow.match(/persist-credentials: false/gu) ?? []).length, 2);

  const resolver = workflow.match(/- name: Resolve Environment-bound configuration[\s\S]*?(?=\n      - name: Validate resolved)/u)?.[0] ?? '';
  const mappedVars = [...resolver.matchAll(/\$\{\{ vars\.([A-Z0-9_]+) \}\}/gu)].map((match) => match[1]).sort();
  assert.deepEqual(mappedVars, [
    'VERIFICATION_CDN_CHECK_PATH', 'VERIFICATION_CDN_ORIGIN', 'VERIFICATION_CDN_VERSION_HEADER', 'VERIFICATION_CDN_VERSION_PATH',
    'VERIFICATION_PRIMARY_CHECK_PATH', 'VERIFICATION_PRIMARY_ORIGIN', 'VERIFICATION_PRIMARY_PUBLIC_MARKER', 'VERIFICATION_PRIMARY_VERSION_HEADER',
    'VERIFICATION_PRIMARY_VERSION_PATH', 'VERIFICATION_RELEASE_ASSET_NAME_TEMPLATE',
  ]);
  assert.match(resolver, /VERIFICATION_TARGET_ENVIRONMENT: \$\{\{ inputs\.target_environment \}\}/u);
  assert.doesNotMatch(workflow, /toJSON\((?:vars|secrets)\)|toJson\((?:vars|secrets)\)/u);

  const publicStep = workflow.match(/- name: Verify public read-only target[\s\S]*?(?=\n      - name: Verify Basic-Auth)/u)?.[0] ?? '';
  const authenticatedStep = workflow.match(/- name: Verify Basic-Auth-protected read-only target[\s\S]*?(?=\n      - name: Remove resolved)/u)?.[0] ?? '';
  const targetJob = workflow.match(/^  verify-target:[\s\S]*?(?=^  # The schema-v3 MANAGEMENT_PAYLOAD)/mu)?.[0] ?? '';
  const issueJob = workflow.match(/^  manage-issue:[\s\S]*$/mu)?.[0] ?? '';
  assert.doesNotMatch(publicStep, /TARGET_BASIC_AUTH|secrets\./u);
  assert.match(authenticatedStep, /TARGET_BASIC_AUTH_USERNAME: \$\{\{ secrets\.TARGET_BASIC_AUTH_USERNAME \}\}[\s\S]*TARGET_BASIC_AUTH_PASSWORD: \$\{\{ secrets\.TARGET_BASIC_AUTH_PASSWORD \}\}/u);
  assert.equal((workflow.match(/secrets\.TARGET_BASIC_AUTH_/gu) ?? []).length, 2);
  assert.match(targetJob, /permissions:\n      contents: read\n      actions: read/u);
  assert.doesNotMatch(targetJob, /issues: write|deployments: write|contents: write/u);
  assert.doesNotMatch(issueJob, /TARGET_BASIC_AUTH|PROVENANCE_PAYLOAD|environment:\n/u);
  assert.match(issueJob, /contents: read[\s\S]*issues: write/u);
  assert.match(issueJob, /needs\.verify-target\.result != 'cancelled'[\s\S]*needs\.verify-target\.result != 'skipped'[\s\S]*needs\.verify-target\.outputs\.management_payload != ''/u);
});

test('workflow exposes dispatch only and admits schema-v3 digest evidence after exact artifact upload', () => {
  const workflow = workflowDocument();
  assert.match(workflow, /^  workflow_dispatch:/mu);
  assert.doesNotMatch(workflow, /^  workflow_call:/mu);
  assert.doesNotMatch(workflow, /^  (?:pull_request|pull_request_target|schedule|release):/mu);
  assert.match(workflow, /name: release-verification-\$\{\{ steps\.resolved-preflight\.outputs\.environment_digest \}\}-\$\{\{ github\.run_id \}\}-\$\{\{ github\.run_attempt \}\}/u);
  assert.doesNotMatch(workflow, /needs\.preflight\.outputs|outputs\.environment\b|artifact_ok/u);
  const admittedOutputs = workflow.match(/^    outputs:\n([\s\S]*?)(?=^    steps:)/mu)?.[1] ?? '';
  assert.equal((admittedOutputs.match(/^      (?:overall|management_payload):/gmu) ?? []).length, 2);
  assert.doesNotMatch(admittedOutputs, /environment|artifact|config_digest|provenance/u);

  const gate = workflow.match(/- name: Validate bounded sanitized evidence[\s\S]*?(?=\n      - name: Upload bounded)/u)?.[0] ?? '';
  assert.match(gate, /report\.schema_version !== 3/u);
  assert.match(gate, /\^\[0-9a-f\]\{64\}\$/u);
  assert.match(gate, /management\.schema_version !== 3/u);
  assert.match(gate, /environment_digest[^\n]*EXPECTED_ENVIRONMENT_DIGEST/u);
  assert.match(gate, /MAX_REPORT_BYTES = 262144[\s\S]*MAX_JUNIT_BYTES = 262144[\s\S]*MAX_COMBINED_BYTES = 262144/u);
  assert.match(gate, /expectedNames = \['junit\.xml', 'report\.json'\]/u);
  assert.match(gate, /forbiddenKeys[^\n]*'environment'/u);
  const gateOutputFormat = gate.match(/fs\.appendFileSync\(process\.env\.GITHUB_OUTPUT, `([^`]+)`/u)?.[1] ?? '';
  assert.equal((gate.match(/fs\.appendFileSync\(process\.env\.GITHUB_OUTPUT/gu) ?? []).length, 1);
  assert.equal(gateOutputFormat, 'overall=${selectedOverall}\\nmanagement_payload=${encodedManagement}\\n');

  const upload = workflow.match(/- name: Upload bounded sanitized evidence[\s\S]*?(?=\n      - name: Admit bounded)/u)?.[0] ?? '';
  assert.match(upload, /steps\.artifact-gate\.outcome == 'success'/u);
  assert.match(upload, /verification-output\/report\.json\n\s+verification-output\/junit\.xml/u);
  assert.doesNotMatch(upload, /verification-config\.resolved\.json|release-verification-resolved/u);
  const admit = workflow.match(/- name: Admit bounded management evidence[\s\S]*?(?=\n      - name: Set target)/u)?.[0] ?? '';
  assert.match(admit, /steps\.artifact-gate\.outcome == 'success'[\s\S]*steps\.artifact\.outcome == 'success'/u);
  assert.match(admit, /OVERALL: \$\{\{ steps\.artifact-gate\.outputs\.overall \}\}[\s\S]*MANAGEMENT_PAYLOAD: \$\{\{ steps\.artifact-gate\.outputs\.management_payload \}\}/u);
  assert.doesNotMatch(admit, /steps\.verify-(?:public|authenticated)\.outputs/u);
  assert.match(admit, /overall=%s[\s\S]*management_payload=%s/u);
  assert.deepEqual([...admit.matchAll(/printf '([a-z_]+)=%s\\n'/gu)].map((match) => match[1]), ['overall', 'management_payload']);
});

test('workflow owns resolve, validate, verify and cleanup in one bounded Environment job', () => {
  const workflow = workflowDocument();
  const timeouts = [...workflow.matchAll(/^    timeout-minutes: (\d+)$/gmu)].map((match) => Number(match[1]));
  assert.deepEqual(timeouts, [2, 8, 2]);
  assert.equal(timeouts.reduce((sum, value) => sum + value, 0), 12);
  assert.match(workflow, /active-execution hard bound:[\s\S]*2 \+ 8 \+ 2 = 12/u);
  assert.match(workflow, /GitHub queue time and the wait[\s\S]*Environment protection approval[\s\S]*outside[\s\S]*this bound/u);
  assert.match(workflow, /A job that never starts cannot emit a pass result or an adoption signal/u);
  const preflight = workflow.match(/^  preflight:[\s\S]*?(?=^  verify-target:)/mu)?.[0] ?? '';
  assert.doesNotMatch(preflight, /verify\.mjs|VERIFICATION_CONFIG|target_environment|TARGET_ENVIRONMENT/u);
  const target = workflow.match(/^  verify-target:[\s\S]*?(?=^  # The schema-v3 MANAGEMENT_PAYLOAD)/mu)?.[0] ?? '';
  assert.match(target, /environment:\n      name: \$\{\{ inputs\.target_environment \}\}/u);
  const resolveStep = target.match(/- name: Resolve Environment-bound configuration[\s\S]*?(?=\n      - name: Validate resolved)/u)?.[0] ?? '';
  const validateStep = target.match(/- name: Validate resolved configuration[\s\S]*?(?=\n      - name: Verify public)/u)?.[0] ?? '';
  const publicVerificationStep = target.match(/- name: Verify public read-only target[\s\S]*?(?=\n      - name: Verify Basic-Auth)/u)?.[0] ?? '';
  const authenticatedVerificationStep = target.match(/- name: Verify Basic-Auth-protected read-only target[\s\S]*?(?=\n      - name: Remove resolved)/u)?.[0] ?? '';
  assert.ok(resolveStep && validateStep && publicVerificationStep && authenticatedVerificationStep);
  assert.doesNotMatch(resolveStep, /continue-on-error|^\s+if:/mu);
  assert.doesNotMatch(validateStep, /continue-on-error|^\s+if:/mu);
  assert.match(publicVerificationStep, /continue-on-error: true/u);
  assert.match(authenticatedVerificationStep, /continue-on-error: true/u);
  assert.match(publicVerificationStep, /if: \$\{\{ steps\.resolved-preflight\.outputs\.basic_auth_required != 'true' \}\}/u);
  assert.match(authenticatedVerificationStep, /if: \$\{\{ steps\.resolved-preflight\.outputs\.basic_auth_required == 'true' \}\}/u);
  assert.doesNotMatch(`${publicVerificationStep}\n${authenticatedVerificationStep}`, /always\(|failure\(|cancelled\(/u);
  const publicVerificationId = publicVerificationStep.match(/^\s+id: ([A-Za-z0-9_-]+)$/mu)?.[1] ?? '';
  const authenticatedVerificationId = authenticatedVerificationStep.match(/^\s+id: ([A-Za-z0-9_-]+)$/mu)?.[1] ?? '';
  assert.ok(publicVerificationId && authenticatedVerificationId && publicVerificationId !== authenticatedVerificationId);
  const fixedConfig = 'VERIFICATION_CONFIG: ${{ runner.temp }}/release-verification-resolved/verification-config.resolved.json';
  assert.equal(target.split(fixedConfig).length - 1, 5);
  assert.equal((target.match(/VERIFICATION_TEMP_ROOT: \$\{\{ runner\.temp \}\}/gu) ?? []).length, 5);
  const resolveAt = target.indexOf('node tests/external/verify.mjs resolve');
  const validateAt = target.indexOf('node tests/external/verify.mjs validate');
  const verifyAt = target.indexOf('node tests/external/verify.mjs verify');
  const cleanupAt = target.indexOf('node tests/external/verify.mjs cleanup');
  assert.ok(resolveAt > 0 && validateAt > resolveAt && verifyAt > validateAt && cleanupAt > verifyAt);
  assert.equal((workflow.match(/node tests\/external\/verify\.mjs resolve/gu) ?? []).length, 1);
  assert.equal((workflow.match(/node tests\/external\/verify\.mjs validate/gu) ?? []).length, 1);
  assert.equal((workflow.match(/node tests\/external\/verify\.mjs verify/gu) ?? []).length, 2);
  assert.equal((workflow.match(/node tests\/external\/verify\.mjs cleanup/gu) ?? []).length, 1);
  assert.equal((workflow.match(/node tests\/external\/verify\.mjs manage-issue/gu) ?? []).length, 1);
  assert.match(target, /- name: Remove resolved configuration[\s\S]*?if: \$\{\{ always\(\) \}\}/u);
  assert.match(target, /steps\.resolve\.outcome == 'success'[\s\S]*steps\.resolved-preflight\.outcome == 'success'[\s\S]*steps\.cleanup-resolved-config\.outcome == 'success'/u);
  const artifactGateStep = target.match(/- name: Validate bounded sanitized evidence[\s\S]*?(?=\n      - name: Upload bounded)/u)?.[0] ?? '';
  const artifactUploadStep = target.match(/- name: Upload bounded sanitized evidence[\s\S]*?(?=\n      - name: Admit bounded)/u)?.[0] ?? '';
  const admissionStep = target.match(/- name: Admit bounded management evidence[\s\S]*?(?=\n      - name: Set target)/u)?.[0] ?? '';
  assert.ok(artifactGateStep && artifactUploadStep && admissionStep);
  assert.doesNotMatch(`${artifactGateStep}\n${artifactUploadStep}\n${admissionStep}`, /continue-on-error/u);
  assert.match(artifactGateStep, /always\(\)[\s\S]*steps\.resolve\.outcome == 'success'[\s\S]*steps\.resolved-preflight\.outcome == 'success'[\s\S]*steps\.cleanup-resolved-config\.outcome == 'success'/u);
  assert.match(artifactGateStep, /basic_auth_required == 'true'[\s\S]*basic_auth_required == 'false'/u);
  assert.match(artifactGateStep, new RegExp(`PUBLIC_OUTCOME: \\$\\{\\{ steps\\.${publicVerificationId}\\.outcome \\}\\}[\\s\\S]*PUBLIC_OVERALL: \\$\\{\\{ steps\\.${publicVerificationId}\\.outputs\\.overall \\}\\}[\\s\\S]*PUBLIC_MANAGEMENT_PAYLOAD: \\$\\{\\{ steps\\.${publicVerificationId}\\.outputs\\.management_payload \\}\\}`, 'u'));
  assert.match(artifactGateStep, new RegExp(`AUTHENTICATED_OUTCOME: \\$\\{\\{ steps\\.${authenticatedVerificationId}\\.outcome \\}\\}[\\s\\S]*AUTHENTICATED_OVERALL: \\$\\{\\{ steps\\.${authenticatedVerificationId}\\.outputs\\.overall \\}\\}[\\s\\S]*AUTHENTICATED_MANAGEMENT_PAYLOAD: \\$\\{\\{ steps\\.${authenticatedVerificationId}\\.outputs\\.management_payload \\}\\}`, 'u'));
  assert.match(artifactGateStep, /basicAuthRequired !== 'true' && basicAuthRequired !== 'false'/u);
  assert.match(artifactGateStep, /const selected = basicAuthRequired === 'true' \? authenticatedResult : publicResult[\s\S]*const unselected = basicAuthRequired === 'true' \? publicResult : authenticatedResult/u);
  assert.match(artifactGateStep, /unselected\.outcome !== 'skipped' \|\| unselected\.overall !== '' \|\| unselected\.managementPayload !== ''/u);
  assert.match(artifactGateStep, /new Set\(\['fail', 'blocked', 'not_observable_read_only'\]\)[\s\S]*selected\.outcome === 'success' && selected\.overall === 'pass'[\s\S]*selected\.outcome === 'failure' && allowedNonPass\.has\(selected\.overall\)[\s\S]*selected\.managementPayload === ''/u);
  assert.match(artifactGateStep, /report\.overall !== selectedOverall[\s\S]*management\.overall !== report\.overall/u);
  assert.match(artifactUploadStep, /always\(\)[\s\S]*steps\.artifact-gate\.outcome == 'success'/u);
  assert.match(admissionStep, /always\(\)[\s\S]*steps\.artifact-gate\.outcome == 'success'[\s\S]*steps\.artifact\.outcome == 'success'/u);
  assert.match(admissionStep, /steps\.artifact-gate\.outputs\.overall[\s\S]*steps\.artifact-gate\.outputs\.management_payload/u);
  assert.doesNotMatch(admissionStep, /steps\.verify-(?:public|authenticated)\.outputs/u);

  const emptyBranch = Object.freeze({ outcome: 'skipped', overall: '', managementPayload: '' });
  const matrixAccepted = ({ basicAuthRequired, publicResult, authenticatedResult }) => {
    if (basicAuthRequired !== 'true' && basicAuthRequired !== 'false') return false;
    const selected = basicAuthRequired === 'true' ? authenticatedResult : publicResult;
    const unselected = basicAuthRequired === 'true' ? publicResult : authenticatedResult;
    if (unselected.outcome !== 'skipped' || unselected.overall !== '' || unselected.managementPayload !== '') return false;
    return selected.managementPayload !== '' && ((selected.outcome === 'success' && selected.overall === 'pass') || (selected.outcome === 'failure' && ['fail', 'blocked', 'not_observable_read_only'].includes(selected.overall)));
  };
  const matrixCase = (basicAuthRequired, selected, unselected = emptyBranch) => basicAuthRequired === 'true'
    ? { basicAuthRequired, publicResult: unselected, authenticatedResult: selected }
    : { basicAuthRequired, publicResult: selected, authenticatedResult: unselected };
  const nonPassResults = ['fail', 'blocked', 'not_observable_read_only'];
  for (const basicAuthRequired of ['false', 'true']) {
    assert.equal(matrixAccepted(matrixCase(basicAuthRequired, { outcome: 'success', overall: 'pass', managementPayload: 'accepted' })), true);
    for (const overall of nonPassResults) {
      assert.equal(matrixAccepted(matrixCase(basicAuthRequired, { outcome: 'failure', overall, managementPayload: 'accepted' })), true);
      assert.equal(matrixAccepted(matrixCase(basicAuthRequired, { outcome: 'success', overall, managementPayload: 'accepted' })), false);
    }
    for (const outcome of ['cancelled', 'skipped', '']) assert.equal(matrixAccepted(matrixCase(basicAuthRequired, { outcome, overall: 'pass', managementPayload: 'accepted' })), false);
    assert.equal(matrixAccepted(matrixCase(basicAuthRequired, { outcome: 'failure', overall: 'pass', managementPayload: 'accepted' })), false);
    assert.equal(matrixAccepted(matrixCase(basicAuthRequired, { outcome: 'success', overall: 'pass', managementPayload: '' })), false);
    assert.equal(matrixAccepted(matrixCase(basicAuthRequired, { outcome: 'success', overall: 'pass', managementPayload: 'accepted' }, { outcome: 'success', overall: 'pass', managementPayload: 'other' })), false);
    assert.equal(matrixAccepted(matrixCase(basicAuthRequired, { outcome: 'skipped', overall: '', managementPayload: '' })), false);
    assert.equal(matrixAccepted(matrixCase(basicAuthRequired, { outcome: 'success', overall: 'pass', managementPayload: 'accepted' }, { outcome: 'skipped', overall: 'pass', managementPayload: '' })), false);
    assert.equal(matrixAccepted(matrixCase(basicAuthRequired, { outcome: 'success', overall: 'pass', managementPayload: 'accepted' }, { outcome: 'skipped', overall: '', managementPayload: 'other' })), false);
  }
  for (const malformedAuth of ['', 'TRUE', '1']) assert.equal(matrixAccepted(matrixCase(malformedAuth, { outcome: 'success', overall: 'pass', managementPayload: 'accepted' })), false);
  assert.doesNotMatch(workflow, /node --test tests\/external\/verify\.test\.mjs/u);
  assert.doesNotMatch(target, /VERIFICATION_CONFIG: tests\/external\/verification-config\.json/u);
  assert.equal((target.match(/VERIFIER_COMMIT_SHA: \$\{\{ github\.sha \}\}/gu) ?? []).length, 3);
  assert.doesNotMatch(workflow, /github\.job_workflow_sha|^\s+ref:|trustedTemporaryRoot/mu);
  const conclusion = target.match(/- name: Set target verification conclusion[\s\S]*$/u)?.[0] ?? '';
  assert.ok(target.indexOf('- name: Validate bounded sanitized evidence') < target.indexOf('- name: Upload bounded sanitized evidence'));
  assert.ok(target.indexOf('- name: Upload bounded sanitized evidence') < target.indexOf('- name: Admit bounded management evidence'));
  assert.ok(target.indexOf('- name: Admit bounded management evidence') < target.indexOf('- name: Set target verification conclusion'));
  assert.match(conclusion, /RESOLVE_OUTCOME[\s\S]*PREFLIGHT_OUTCOME[\s\S]*CLEANUP_OUTCOME[\s\S]*ARTIFACT_GATE_OUTCOME[\s\S]*ARTIFACT_OUTCOME[\s\S]*ADMISSION_OUTCOME/u);
  assert.match(conclusion, /RESOLVE_OUTCOME: \$\{\{ steps\.resolve\.outcome \}\}[\s\S]*PREFLIGHT_OUTCOME: \$\{\{ steps\.resolved-preflight\.outcome \}\}/u);
  assert.match(conclusion, /\[ "\$RESOLVE_OUTCOME" != "success" \][\s\S]*\[ "\$PREFLIGHT_OUTCOME" != "success" \][\s\S]*exit 1/u);
  const conclusionRun = conclusion.match(/\n\s+run: \|([\s\S]*)$/u)?.[1] ?? '';
  assert.ok(conclusionRun);
  assert.match(conclusion, /BASIC_AUTH_REQUIRED: \$\{\{ steps\.resolved-preflight\.outputs\.basic_auth_required \}\}/u);
  assert.match(conclusionRun, /if \[ "\$BASIC_AUTH_REQUIRED" = "true" \][\s\S]*elif \[ "\$BASIC_AUTH_REQUIRED" = "false" \][\s\S]*verification_selection_invalid/u);
  assert.match(conclusionRun, /\$PUBLIC_OUTCOME" != "skipped" \] \|\| \[ -n "\$PUBLIC_OVERALL" \] \|\| \[ -n "\$PUBLIC_MANAGEMENT_PAYLOAD" \]/u);
  assert.match(conclusionRun, /\$AUTHENTICATED_OUTCOME" != "skipped" \] \|\| \[ -n "\$AUTHENTICATED_OVERALL" \] \|\| \[ -n "\$AUTHENTICATED_MANAGEMENT_PAYLOAD" \]/u);
  assert.match(conclusionRun, /success:pass\|failure:fail\|failure:blocked\|failure:not_observable_read_only/u);
  assert.match(conclusionRun, /\[ -z "\$SELECTED_MANAGEMENT_PAYLOAD" \][\s\S]*\[ "\$ARTIFACT_GATE_OUTCOME" != "success" \][\s\S]*\[ "\$ARTIFACT_OUTCOME" != "success" \]/u);
  assert.match(conclusionRun, /\$ADMISSION_OUTCOME" != "success"[\s\S]*\$ADMITTED_OVERALL" != "\$SELECTED_OVERALL"[\s\S]*\$ADMITTED_MANAGEMENT_PAYLOAD" != "\$SELECTED_MANAGEMENT_PAYLOAD"/u);
  assert.match(conclusionRun, /\[ "\$ADMITTED_OVERALL" != "pass" \][\s\S]*exit 1/u);
  const issueJob = workflow.match(/^  manage-issue:[\s\S]*$/mu)?.[0] ?? '';
  assert.match(issueJob, /needs\.verify-target\.outputs\.management_payload/u);
  assert.doesNotMatch(issueJob, /verify-(?:public|authenticated)|PUBLIC_OUTCOME|AUTHENTICATED_OUTCOME|steps\.artifact-gate/u);
  const config = templateDocument();
  assert.equal(config.template.limits.phase_timeout_ms, 360000);
});

test('template inventory is exactly the four contract files and contains no runtime language', () => {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
  const files = [];
  const walk = (directory) => fs.readdirSync(directory, { withFileTypes: true }).forEach((entry) => entry.isDirectory() ? walk(path.join(directory, entry.name)) : files.push(path.relative(root, path.join(directory, entry.name)).replaceAll('\\', '/')));
  walk(root);
  assert.deepEqual(files.sort(), ['.github/workflows/release-verification.yml', 'tests/external/verification-config.json', 'tests/external/verify.mjs', 'tests/external/verify.test.mjs']);
  assert.equal(files.some((name) => /\.(?:php|zip)$/iu.test(name)), false);
});

test('page and asset contracts classify every observable outcome without leaking content', async () => {
  const config = validated();
  const target = config.environment.targets.primary;
  const base = { targets: config.environment.targets, performRequest: async () => response(200, 'Ready') };
  const check = { id: 'x', target: 'primary', type: 'page', path: '/', method: 'GET', expected_status: 200, required: true, fatal_signatures: true, required_text: ['Ready'], forbidden_text: ['Forbidden'], observable: true };
  assert.equal((await __test.runCheck({ ...check, observable: false }, base)).status, 'not_observable_read_only');
  const cases = [
    [response(401), 'target_contract:unexpected_auth_status'],
    [response(500), 'target_contract:http_5xx'],
    [response(404), 'target_contract:unexpected_status'],
    [response(200, 'Fatal error: hidden'), 'target_content:fatal_signature'],
    [response(200, 'Different'), 'target_content:required_marker_missing'],
    [response(200, 'Ready Forbidden'), 'target_content:forbidden_marker_present'],
  ];
  for (const [outcome, code] of cases) {
    const result = await __test.runCheck(check, { ...base, performRequest: async () => outcome });
    assert.equal(result.status, 'fail'); assert.equal(result.code, code);
  }
  const authResult = await __test.runCheck(check, { ...base, targets: { ...config.environment.targets, primary: { ...target, basic_auth: true } }, performRequest: async () => response(403) });
  assert.equal(authResult.status, 'blocked'); assert.equal(authResult.code, 'blocked_target_auth');
});

test('all declarative version source modes and bounded failures are executable', async () => {
  const config = validated();
  const context = { targets: config.environment.targets, performRequest: async () => response(200, '') };
  const textSource = { id: 'text', target: 'primary', type: 'text_marker', path: '/', required: true, prefix: 'v=', suffix: ';' };
  assert.equal((await __test.observeVersion(textSource, '1.2.3', { ...context, performRequest: async () => response(200, 'v=1.2.3;') })).status, 'pass');
  assert.equal((await __test.observeVersion(textSource, '1.2.3', context)).code, 'target_version:prefix_missing');
  assert.equal((await __test.observeVersion(textSource, '1.2.3', { ...context, performRequest: async () => response(200, 'v=1.2.3') })).code, 'target_version:suffix_missing');
  const jsonSource = { id: 'json', target: 'primary', type: 'json_manifest', path: '/manifest.json', required: true, json_pointer: '/release/version' };
  assert.equal((await __test.observeVersion(jsonSource, '1.2.3', { ...context, performRequest: async () => response(200, '{"release":{"version":"1.2.3"}}') })).status, 'pass');
  assert.equal((await __test.observeVersion(jsonSource, '1.2.3', { ...context, performRequest: async () => response(200, '{') })).code, 'target_version:invalid_json_manifest');
  assert.equal((await __test.observeVersion(jsonSource, '1.2.3', { ...context, performRequest: async () => response(200, '{}') })).code, 'target_version:json_pointer_missing');
  const headerSource = { id: 'header', target: 'primary', type: 'response_header', path: '/', required: true, header_name: 'x-version' };
  assert.equal((await __test.observeVersion(headerSource, '1.2.3', { ...context, performRequest: async () => response(200, '', { 'x-version': '1.2.3' }) })).status, 'pass');
  assert.equal((await __test.observeVersion(headerSource, '1.2.3', { ...context, performRequest: async () => ({ ...response(200, '', { 'x-version': '1.2.3' }), headerCounts: new Map([['x-version', 2]]) }) })).code, 'target_version:header_missing_or_repeated');
  assert.equal((await __test.observeVersion(headerSource, '1.2.3', { ...context, performRequest: async () => response(200, '', { 'x-version': 'bad value' }) })).code, 'target_version:observed_value_invalid');
  assert.equal((await __test.observeVersion(headerSource, '1.2.3', { ...context, performRequest: async () => response(204) })).code, 'target_version:unexpected_status');
});

test('config validation covers optional observability, HEAD assets and JSON manifests', () => {
  const raw = rawConfig({
    checks: [{ id: 'asset', target: 'cdn', type: 'asset', path: '/plugin.css', method: 'HEAD', expected_status: 200, required: false, fatal_signatures: false, required_text: [], forbidden_text: [], observable: false }],
    versionSources: [{ id: 'manifest', target: 'primary', type: 'json_manifest', path: '/manifest.json', required: true, json_pointer: '/version' }],
  });
  assert.equal(validateConfig(raw, 'preview').environment.checks[0].observable, false);
  const mutations = [
    (copy) => { copy.environments.preview.checks[0].fatal_signatures = true; },
    (copy) => { copy.environments.preview.checks[0].required_text = ['marker']; },
    (copy) => { copy.environments.preview.version_sources[0].json_pointer = 'version'; },
    (copy) => { copy.environments.preview.version_sources[0].json_pointer = '/bad~0'; },
    (copy) => { copy.environments.preview.version_sources[0] = { id: 'header', target: 'primary', type: 'response_header', path: '/', required: true, header_name: 'set-cookie' }; },
  ];
  for (const mutate of mutations) { const copy = structuredClone(raw); mutate(copy); assert.throws(() => validateConfig(copy, 'preview')); }
});

test('gzip, deflate and Brotli decoding share the post-decompression body bound', async () => {
  for (const [encoding, encoded] of [['gzip', gzipSync('ok')], ['deflate', deflateSync('ok')], ['br', brotliCompressSync('ok')]]) {
    const stream = new PassThrough(); stream.headers = { 'content-encoding': encoding };
    const promise = __test.readDecodedBody(stream, 'GET', LIMITS); stream.end(encoded);
    assert.equal(await promise, 'ok');
  }
});

test('error normalization and GitHub failure classification are finite and sanitized', () => {
  assert.equal(__test.cleanError(Object.assign(new Error('details'), { code: 'ECONNREFUSED' })).code, 'target_network:econnrefused');
  assert.equal(__test.cleanError(Object.assign(new Error('details'), { code: 'HPE_HEADER_OVERFLOW' })).code, 'target_protocol:headers_too_large');
  assert.equal(__test.cleanError(new Error('private details')).code, 'internal:unexpected_error');
  assert.equal(__test.githubFailure({ status: 403, headers: {} }, 'environment').code, 'github_control:environment_permission_denied');
  assert.equal(__test.githubFailure({ status: 502, headers: {} }, 'environment').code, 'github_control:environment_api_error');
  assert.equal(__test.githubFailure({ status: 404, headers: {} }, 'environment').code, 'github_control:environment_unexpected_response');
});

test('strict management handles ineligible, not-observable, duplicate and invalid provenance payloads', () => {
  const ineligible = { ...management(), management_eligible: false, overall: 'blocked', code: 'config:setup_blocked', incident: false, incident_fingerprints: [], observations: { observed_version: null, provenance: null } };
  assert.equal(parseManagementPayload(encode(ineligible)).management_eligible, false);
  assert.equal(parseManagementPayload(encode({ ...ineligible, environment_digest: null })).environment_digest, null);
  assert.throws(() => parseManagementPayload(encode({ ...ineligible, environment_digest: 'bad' })), /management_ineligible_environment_digest_invalid/);
  const missingIdentity = { ...ineligible }; delete missingIdentity.environment_digest;
  assert.throws(() => parseManagementPayload(encode(missingIdentity)), /management_ineligible_environment_digest_invalid/);
  assert.throws(() => parseManagementPayload(encode({ ...ineligible, incident: true })), /management_ineligible_incident_forbidden/);
  assert.throws(() => parseManagementPayload(encode({ ...ineligible, run_id: 'bad' })), /management_ineligible_run_id_invalid/);
  assert.throws(() => parseManagementPayload(encode({ ...ineligible, run_url: 'https://github.com/owner/plugin/actions/runs/999' })), /management_ineligible_run_url_mismatch/);
  assert.throws(() => parseManagementPayload(encode({ ...ineligible, config_digest: 'bad' })), /management_ineligible_config_digest_invalid/);
  assert.throws(() => parseManagementPayload(encode({ ...ineligible, completed_at: 'tomorrow' })), /management_ineligible_completed_at_invalid/);
  assert.throws(() => parseManagementPayload(encode({ ...ineligible, overall: 'pass' })), /management_ineligible_result_invalid/);
  assert.throws(() => parseManagementPayload(encode({ ...ineligible, observations: { observed_version: null, provenance: provenanceClaims } })), /management_ineligible_observations_invalid/);
  assert.throws(() => parseManagementPayload(encode({ ...ineligible, incident_fingerprints: ['b'.repeat(24)] })), /management_ineligible_incident_forbidden/);
  assert.throws(() => parseManagementPayload(encode(management({ incident_fingerprints: ['b'.repeat(24), 'b'.repeat(24)] }))), /management_incident_fingerprints_invalid/);
  const noObservation = management({ overall: 'not_observable_read_only', code: 'requires_session_or_write', incident: false, incident_fingerprints: [] });
  assert.equal(parseManagementPayload(encode(noObservation)).overall, 'not_observable_read_only');
  assert.throws(() => __test.validateProvenance({ ...provenanceClaims, status: 'verified' }), /provenance_claims_only_invalid/);
  assert.throws(() => __test.parseProvenancePayload('%%%'), /provenance_payload_invalid/);
});

test('issue ordering, update, reopen, duplicate detection and version ordering are deterministic', async () => {
  const older = management();
  const current = management({ run_id: '101', run_url: 'https://github.com/owner/plugin/actions/runs/101', completed_at: '2026-08-26T12:05:00.000Z' });
  assert.equal(__test.compareOrder(current, older), 1);
  assert.equal(__test.compareOrder(older, current), -1);
  assert.equal(__test.newerStableVersion('2.0.0', '1.9.9'), true);
  assert.equal(__test.newerStableVersion('1.0.0-beta', '1.0.0'), false);
  const marked = { number: 12, state: 'closed', body: __test.issueBody(older, 'b'.repeat(24)) };
  const writes = [];
  assert.equal(await manageIssue(current, async (method, endpoint, body) => { if (method === 'GET') return searchResult([marked]); writes.push({ method, endpoint, body }); return { status: 200, body: {}, headers: {} }; }), 'changed');
  assert.equal(writes[0].method, 'PATCH'); assert.equal(writes[0].body.state, 'open');
  await assert.rejects(manageIssue(current, async (method) => method === 'GET' ? searchResult([marked, { ...marked, number: 13 }]) : { status: 200, body: {}, headers: {} }), /duplicate_marked_issues/);
});

test('verified provenance validation enforces every asset identity and digest field', () => {
  const value = { mode: 'github_release_required', status: 'verified', github_release_id: '77', release_tag_commit_sha: '1'.repeat(40), asset: { id: '88', name: 'plugin-1.2.3.zip', size: 1234, digest: `sha256:${'a'.repeat(64)}` } };
  assert.deepEqual(__test.validateProvenance(structuredClone(value)), value);
  const mutations = [
    (copy) => { copy.github_release_id = 'bad'; },
    (copy) => { copy.release_tag_commit_sha = 'bad'; },
    (copy) => { copy.asset.id = 'bad'; },
    (copy) => { copy.asset.name = '../bad.zip'; },
    (copy) => { copy.asset.size = -1; },
    (copy) => { copy.asset.digest = null; },
    (copy) => { delete copy.asset.digest; },
    (copy) => { copy.asset.digest = 'sha256:bad'; },
    (copy) => { copy.asset.extra = true; },
  ];
  for (const mutate of mutations) { const copy = structuredClone(value); mutate(copy); assert.throws(() => __test.validateProvenance(copy)); }
});

test('config loader bounds bytes, rejects malformed JSON and binds its digest', () => {
  const resolved = structuredClone(rawConfig());
  resolved.environments = { [ENVIRONMENT_DIGEST]: resolved.environments.preview };
  const raw = Buffer.from(JSON.stringify(resolved), 'utf8');
  const loaded = __test.loadConfig('ignored', 'preview', { readFileSync: () => raw });
  assert.match(loaded.configDigest, /^[0-9a-f]{64}$/u);
  assert.equal(loaded.selectedEnvironment, 'preview');
  assert.deepEqual(Object.keys(loaded.environments), [ENVIRONMENT_DIGEST]);
  assert.throws(() => __test.loadConfig('ignored', 'preview', { readFileSync: () => Buffer.from('{') }), /invalid_json/);
  assert.throws(() => __test.loadConfig('ignored', 'preview', { readFileSync: () => Buffer.alloc(131073) }), /config_too_large/);
  const unresolved = Buffer.from(JSON.stringify(rawConfig()), 'utf8');
  assert.throws(() => __test.loadConfig('ignored', 'preview', { readFileSync: () => unresolved }), /selected_environment_not_declared/);
});

test('authenticated verification accepts bounded credentials without exposing them', async () => {
  const output = outputFileSystem();
  const summaryPath = path.resolve(process.cwd(), 'github-step-summary.txt');
  const githubOutputPath = path.resolve(process.cwd(), 'github-output.txt');
  await withEnv({ ...baseEnv, TARGET_BASIC_AUTH_USERNAME: 'user', TARGET_BASIC_AUTH_PASSWORD: 'private-password', GITHUB_STEP_SUMMARY: summaryPath, GITHUB_OUTPUT: githubOutputPath }, async () => {
    const report = await verify(validated({ basicAuth: true }), {
      now: () => Date.parse('2026-08-26T12:00:00Z'), sleep: async () => {}, provenance: provenanceClaims,
      performRequest: async (url, method, context) => {
        assert.deepEqual(context.auth, { username: 'user', password: 'private-password' });
        return successTarget(url, method);
      },
      fs: output.fileSystem,
    });
    assert.equal(report.overall, 'pass');
    assert.doesNotMatch(JSON.stringify(report), /private-password|"username"/u);
    const emittedEvidence = [...output.files.values()].join('\n');
    assert.doesNotMatch(emittedEvidence, /private-password|dXNlcjpwcml2YXRlLXBhc3N3b3Jk|"username"/u);

    const failedOutput = outputFileSystem();
    const failed = await verify(validated({ basicAuth: true }), {
      now: () => Date.parse('2026-08-26T12:00:00Z'), sleep: async () => {}, provenance: provenanceClaims,
      performRequest: async () => { throw new Error('Authorization: Basic dXNlcjpwcml2YXRlLXBhc3N3b3Jk; password=private-password'); },
      fs: failedOutput.fileSystem,
    });
    assert.notEqual(failed.overall, 'pass');
    assert.doesNotMatch(`${JSON.stringify(failed)}\n${[...failedOutput.files.values()].join('\n')}`, /private-password|dXNlcjpwcml2YXRlLXBhc3N3b3Jk|Authorization:/u);
  });
});

test('ordering uses run, attempt, completion time and stable semantic precedence', () => {
  const base = management();
  const laterAttempt = { ...base, run_attempt: '2' };
  const laterTime = { ...base, completed_at: '2026-08-26T12:00:01.000Z' };
  assert.equal(__test.compareOrder(laterAttempt, base), 1);
  assert.equal(__test.compareOrder(laterTime, base), 1);
  assert.equal(__test.compareOrder(base, base), 0);
  assert.equal(__test.newerStableVersion('1.2.2', '1.2.3'), false);
  assert.equal(__test.newerStableVersion('1.2.3', '1.2.3'), false);
});

test('URL, path, identity and collection validation reject every unsafe declarative shape', () => {
  const mutations = [
    (copy) => { copy.environments.preview.targets.primary.base_url = 'http://public.example.com/base/'; },
    (copy) => { copy.environments.preview.targets.primary.base_url = 'https://user:pass@public.example.com/base/'; },
    (copy) => { copy.environments.preview.targets.primary.base_url = 'https://public.example.com/base/?x=1'; },
    (copy) => { copy.environments.preview.targets.primary.base_url = 'https://localhost/base/'; },
    (copy) => { copy.environments.preview.targets.primary.base_url = 'https://public.example.com:22/base/'; },
    (copy) => { copy.environments.preview.targets.primary.base_url = 'https://public.example.com/base/%2e%2e/'; },
    (copy) => { copy.environments.preview.checks[0].path = '//evil.example/'; },
    (copy) => { copy.environments.preview.checks[0].path = '/x?secret=1'; },
    (copy) => { copy.environments.preview.checks[0].path = '/%2e%2e/x'; },
    (copy) => { copy.environments.preview.checks[0].id = 'Bad ID'; },
    (copy) => { copy.environments.preview.checks[0].target = 'missing'; },
    (copy) => { copy.environments.preview.checks[0].type = 'admin'; },
    (copy) => { copy.environments.preview.checks[0].required = 'true'; },
    (copy) => { copy.environments.preview.checks.push(structuredClone(copy.environments.preview.checks[0])); },
    (copy) => { copy.environments.preview.version_sources.push(structuredClone(copy.environments.preview.version_sources[0])); },
    (copy) => { copy.environments.preview.allowed_redirects = [{ from: 'https://public.example.com/base/a', to: 'https://cdn.example.com/assets/a' }, { from: 'https://public.example.com/base/a', to: 'https://cdn.example.com/assets/b' }]; },
    (copy) => { copy.provenance.mode = 'unsupported'; },
    (copy) => { copy.provenance.release_asset_name = 'plugin.zip'; },
    (copy) => { copy.schema_version = 3; },
    (copy) => { copy.environments = {}; },
    (copy) => { copy.limits.evidence_reserve_ms = copy.limits.phase_timeout_ms; },
  ];
  for (const mutate of mutations) { const copy = rawConfig(); mutate(copy); assert.throws(() => validateConfig(copy, 'preview')); }
  assert.throws(() => validateConfig(rawConfig(), 'missing'), /selected_environment_not_declared/);
  assert.throws(() => validateConfig(rawConfig(), 'bad\nenvironment'), /selected_environment_invalid/);
});

test('special-use IPv4 ranges and malformed addresses remain non-public-unicast', () => {
  for (const address of ['0.0.0.0', '100.64.0.1', '172.16.0.1', '192.0.0.1', '192.0.2.1', '192.31.196.1', '192.52.193.1', '192.88.99.1', '192.175.48.1', '198.18.0.1', '198.51.100.1', '203.0.113.1', '224.0.0.1', '999.1.1.1', 'not-an-ip']) assert.equal(isUnsafeIp(address), true, address);
});

test('HEAD asset verification passes end to end through the required evidence path', async () => {
  await withEnv(baseEnv, async () => {
    const methods = [];
    const report = await verify(validated({ checks: [{ id: 'asset', target: 'cdn', type: 'asset', path: '/plugin.css', method: 'HEAD', expected_status: 200, required: true, fatal_signatures: false, required_text: [], forbidden_text: [] }], versionSources: [PRIMARY_VERSION_SOURCE] }), {
      now: () => Date.parse('2026-08-26T12:00:00Z'),
      performRequest: async (url, method, context) => { context.totalRequests += 1; context.attemptRequests += 1; methods.push(method); return successTarget(url, method); },
      sleep: async () => {}, provenance: provenanceClaims,
      fs: outputFileSystem().fileSystem,
    });
    assert.equal(report.overall, 'pass');
    assert.equal(report.attempts.length, 2);
    assert.deepEqual(report.attempts[0].checks, [{ id: 'asset', required: true, status: 'pass', code: 'observed_as_required', fingerprint: null }]);
    assert.deepEqual(methods, ['HEAD', 'GET', 'HEAD', 'GET']);
    assert.equal(report.budgets.requests_used, 4);
  });
});

test('a hanging DNS lookup inside boundedRequest is cut by the request timeout with default timers', async () => {
  const config = validated();
  const context = { targets: config.environment.targets, allowedRedirects: config.environment.allowedRedirects, auth: null, limits: { ...LIMITS, request_timeout_ms: 25 }, totalRequests: 0, attemptRequests: 0, phaseDeadline: 100000, now: () => 0, dependencies: {}, resolvePublic: () => new Promise(() => {}) };
  await assert.rejects(__test.boundedRequest(new URL('https://public.example.com/base/'), 'GET', context), /target_network:etimedout/);
  assert.equal(context.totalRequests, 1);
});

test('a silent HTTPS exchange is destroyed by the requestOnce timer and maps to etimedout', async () => {
  const silent = () => { const request = new EventEmitter(); request.write = () => {}; request.destroy = (error) => { if (error) queueMicrotask(() => request.emit('error', error)); }; request.end = () => {}; return request; };
  await assert.rejects(__test.requestOnce(new URL('https://public.example.com/base/'), 'GET', null, { ...LIMITS, request_timeout_ms: 25 }, [{ address: '93.184.216.34', family: 4 }], { httpsRequest: silent, setTimeout, clearTimeout }), /target_network:etimedout/);
});

test('request concurrency actually overlaps checks yet never exceeds the configured cap', async () => {
  await withEnv(baseEnv, async () => {
    let inflight = 0; let peak = 0;
    const checks = Array.from({ length: 4 }, (_, index) => ({ id: `asset-${index + 1}`, target: 'cdn', type: 'asset', path: `/plugin-${index + 1}.css`, method: 'GET', expected_status: 200, required: true, fatal_signatures: false, required_text: [], forbidden_text: [] }));
    const report = await verify(validated({ checks, versionSources: [PRIMARY_VERSION_SOURCE] }), {
      now: () => Date.parse('2026-08-26T12:00:00Z'), sleep: async () => {}, provenance: provenanceClaims,
      performRequest: async (url, method) => { inflight += 1; peak = Math.max(peak, inflight); await new Promise((resolve) => setTimeout(resolve, 10)); inflight -= 1; return successTarget(url, method); },
      fs: outputFileSystem().fileSystem,
    });
    assert.equal(report.overall, 'pass');
    assert.ok(peak > 1);
    assert.ok(peak <= 2);
  });
});

test('the Basic Authorization header reaches the wire only for the authenticated call', async () => {
  const responder = fakeHttpsResponse({ status: 200, body: 'ok', headers: {} });
  const records = [{ address: '93.184.216.34', family: 4 }];
  let authHeaders;
  const authenticated = await __test.requestOnce(new URL('https://public.example.com/base/'), 'GET', { username: 'u', password: 'p' }, LIMITS, records, { httpsRequest: (url, options) => { authHeaders = options.headers; return responder(url, options); }, setTimeout, clearTimeout });
  assert.equal(authenticated.body, 'ok');
  assert.equal(authHeaders.authorization, `Basic ${Buffer.from('u:p', 'utf8').toString('base64')}`);
  let anonymousHeaders;
  await __test.requestOnce(new URL('https://public.example.com/base/'), 'GET', null, LIMITS, records, { httpsRequest: (url, options) => { anonymousHeaders = options.headers; return responder(url, options); }, setTimeout, clearTimeout });
  assert.equal('authorization' in anonymousHeaders, false);
});

test('a failing optional check never downgrades the verdict while a failing required check does', async () => {
  const config = validated({ checks: [
    { id: 'flaky-asset', target: 'cdn', type: 'asset', path: '/flaky.css', method: 'GET', expected_status: 200, required: false, fatal_signatures: false, required_text: [], forbidden_text: [] },
    { id: 'home', target: 'primary', type: 'page', path: '/', method: 'GET', expected_status: 200, required: true, fatal_signatures: true, required_text: ['Ready'], forbidden_text: ['Never'] },
  ], versionSources: [PRIMARY_VERSION_SOURCE] });
  const options = (primaryFails) => ({ now: () => Date.parse('2026-08-26T12:00:00Z'), sleep: async () => {}, provenance: provenanceClaims, performRequest: async (url, method) => url.hostname === 'cdn.example.com' || primaryFails ? response(500) : successTarget(url, method), fs: outputFileSystem().fileSystem });
  await withEnv(baseEnv, async () => {
    const optionalOnly = await verify(config, options(false));
    assert.equal(optionalOnly.overall, 'pass');
    assert.equal(optionalOnly.attempts[0].checks.find((item) => item.id === 'flaky-asset').status, 'fail');
    assert.equal(optionalOnly.attempts[0].checks.find((item) => item.id === 'flaky-asset').code, 'target_contract:http_5xx');
    const requiredFails = await verify(config, options(true));
    assert.equal(requiredFails.overall, 'fail');
    assert.equal(requiredFails.attempts[0].checks.find((item) => item.id === 'home').code, 'target_contract:http_5xx');
  });
});

test('provenance observation enforces draft, prerelease, asset identity, digest and commit policies', async () => {
  const config = validated({ provenanceMode: 'github_release_required' });
  const metadata = { repository: 'owner/plugin', claims: { release_id: { value: 'v1.2.3' }, expected_version: { value: '1.2.3' }, deployment_commit_sha: { value: '1'.repeat(40) } } };
  const asset = (overrides = {}) => ({ id: 88, name: 'plugin-1.2.3.zip', size: 1234, digest: `sha256:${'a'.repeat(64)}`, ...overrides });
  const release = (assets, overrides = {}) => ({ id: 77, tag_name: 'v1.2.3', draft: false, prerelease: false, assets, ...overrides });
  const github = (body, commitSha = '1'.repeat(40)) => async (method, endpoint) => {
    assert.equal(method, 'GET');
    if (endpoint.includes('/releases/tags/')) return { status: 200, body, headers: {} };
    if (endpoint.includes('/git/ref/tags/')) return { status: 200, body: { object: { type: 'tag', sha: '4'.repeat(40) } }, headers: {} };
    if (endpoint.includes('/git/tags/')) return { status: 200, body: { object: { type: 'commit', sha: commitSha } }, headers: {} };
    assert.fail(endpoint);
  };
  const stable = await __test.observeProvenance(config, metadata, github(release([asset()])));
  assert.equal(stable.status, 'verified');
  assert.equal(stable.github_release_id, '77');
  assert.equal(stable.release_tag_commit_sha, '1'.repeat(40));
  assert.equal(stable.asset.name, 'plugin-1.2.3.zip');
  assert.equal(stable.asset.digest, `sha256:${'a'.repeat(64)}`);
  const prerelease = await __test.observeProvenance(config, metadata, github(release([asset({ digest: `sha256:${'A'.repeat(64)}` })], { prerelease: true })));
  assert.equal(prerelease.status, 'verified');
  assert.equal(prerelease.asset.digest, `sha256:${'A'.repeat(64)}`);
  await assert.rejects(__test.observeProvenance(config, metadata, github(release([asset()], { draft: true }))), /provenance_release_contract_invalid/);
  await assert.rejects(__test.observeProvenance(config, metadata, github(release([asset()], { prerelease: undefined }))), /provenance_release_contract_invalid/);
  await assert.rejects(__test.observeProvenance(config, metadata, github(release([asset()], { prerelease: 'false' }))), /provenance_release_contract_invalid/);
  await assert.rejects(__test.observeProvenance(config, metadata, github(release([]))), /provenance_release_asset_missing_or_duplicate/);
  await assert.rejects(__test.observeProvenance(config, metadata, github(release([asset(), asset({ id: 89 })]))), /provenance_release_asset_missing_or_duplicate/);
  await assert.rejects(__test.observeProvenance(config, metadata, github(release([asset({ name: 'other-1.2.3.zip' })]))), /provenance_release_asset_missing_or_duplicate/);
  await assert.rejects(__test.observeProvenance(config, metadata, github(release([asset({ digest: undefined })]))), /provenance_asset_digest_invalid/);
  await assert.rejects(__test.observeProvenance(config, metadata, github(release([asset({ digest: 'sha256:zz' })]))), /provenance_asset_digest_invalid/);
  await assert.rejects(__test.observeProvenance(config, metadata, github(release([asset()], { tag_name: 'v9.9.9' }))), /provenance_release_contract_invalid/);
  await assert.rejects(__test.observeProvenance(config, metadata, github(release([asset()]), '9'.repeat(40))), /provenance_deployment_commit_mismatch/);
});

test('JUnit reports exact counts for the four outcomes and XML-escapes names and codes', () => {
  const report = { attempts: [{ number: 1, checks: [
    { id: `edge<&>'"`, required: true, status: 'pass', code: 'observed_as_required', fingerprint: null },
    { id: 'failing', required: true, status: 'fail', code: 'target_content:<bad>&', fingerprint: 'f'.repeat(24) },
    { id: 'blocked-one', required: true, status: 'blocked', code: 'blocked_target_auth', fingerprint: null },
    { id: 'readonly-one', required: false, status: 'not_observable_read_only', code: 'requires_session_or_write', fingerprint: null },
  ], versionObservations: [] }] };
  const xml = __test.junitXml(report);
  assert.match(xml, /tests="4" failures="1" errors="2"/u);
  assert.ok(xml.includes(`name="attempt-1:edge&lt;&amp;&gt;'&quot;"`));
  assert.ok(xml.includes('message="target_content:&lt;bad&gt;&amp;"'));
  assert.ok(!xml.includes(`edge<&>'"`));
  assert.ok(!xml.includes('<bad>'));
});
