#!/usr/bin/env node

import crypto from 'node:crypto';
import dns from 'node:dns/promises';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import https from 'node:https';
import net from 'node:net';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { createBrotliDecompress, createGunzip, createInflate } from 'node:zlib';

const DEFAULT_LIMITS = Object.freeze({
  max_attempts: 3,
  consecutive_successes: 2,
  incident_repeat_count: 2,
  max_requests_per_attempt: 10,
  max_total_requests: 30,
  request_concurrency: 2,
  request_timeout_ms: 10_000,
  phase_timeout_ms: 360_000,
  evidence_reserve_ms: 30_000,
  retry_delay_ms: 1_000,
  max_redirect_hops: 3,
  max_response_headers: 64,
  max_header_bytes: 32_768,
  max_body_bytes: 1_048_576,
  max_artifact_bytes: 262_144,
});

const LIMIT_RANGES = Object.freeze({
  max_attempts: [1, 3],
  consecutive_successes: [2, 2],
  incident_repeat_count: [2, 2],
  max_requests_per_attempt: [1, 10],
  max_total_requests: [1, 30],
  request_concurrency: [1, 2],
  request_timeout_ms: [1_000, 10_000],
  phase_timeout_ms: [60_000, 360_000],
  evidence_reserve_ms: [10_000, 120_000],
  retry_delay_ms: [100, 5_000],
  max_redirect_hops: [0, 5],
  max_response_headers: [1, 64],
  max_header_bytes: [1_024, 32_768],
  max_body_bytes: [1_024, 1_048_576],
  max_artifact_bytes: [16_384, 262_144],
});

const FATAL_MARKERS = Object.freeze([
  'fatal error:', 'uncaught error:', 'uncaught exception:', 'parse error:', 'wordpress database error',
]);
const REDIRECT_CODES = new Set([301, 302, 303, 307, 308]);
const SENSITIVE_HEADERS = new Set([
  'authorization', 'cookie', 'set-cookie', 'proxy-authenticate', 'proxy-authorization',
  'www-authenticate', 'x-api-key', 'x-auth-token',
]);
const SAFE_ID = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const SAFE_ENVIRONMENT = /^[A-Za-z0-9][A-Za-z0-9._ /-]{0,127}$/;
const SHA_PATTERN = /^[0-9a-f]{40}$/;
const HEX64_PATTERN = /^[0-9a-f]{64}$/;
const VERSION_PATTERN = /^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$/;
const RELEASE_PATTERN = /^[0-9A-Za-z][0-9A-Za-z._:-]{0,127}$/;
const RUN_PATTERN = /^(0|[1-9]\d{0,19})$/;
const CODE_PATTERN = /^[a-z0-9][a-z0-9_.:|-]{0,511}$/;
const BINDING_ENVIRONMENT_VARIABLE_PATTERN = /^[A-Z][A-Z0-9_]{0,127}$/;
const ENVIRONMENT_DIGEST_DOMAIN = 'hal-release-verification:environment:v1\0';
const CLAIM_SOURCES = new Set(['manual_operator', 'deployment_caller']);
const PROVENANCE_MODES = new Set(['claims_only', 'github_release_required']);
const RELEASE_ASSET_DIGEST_PATTERN = /^sha256:[0-9A-Fa-f]{64}$/u;
const OUTPUT_DIRECTORY_NAME = 'verification-output';
const OUTPUT_FILE_NAMES = Object.freeze(['report.json', 'junit.xml']);
const TEMPLATE_DOCUMENT_KIND = 'verification-config-template';
const TEMPLATE_SCHEMA_VERSION = 1;
const RESOLVED_SCHEMA_VERSION = 2;
const RESOLVED_CONFIG_DIRECTORY_NAME = 'release-verification-resolved';
const RESOLVED_CONFIG_FILE_NAME = 'verification-config.resolved.json';
const MODULE_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const COMMITTED_TEMPLATE_PATH = path.join(MODULE_DIRECTORY, 'verification-config.json');
const REPOSITORY_ROOT = path.resolve(MODULE_DIRECTORY, '..', '..');
const TEMPLATE_BINDINGS = Object.freeze({
  target_environment: Object.freeze({ environment_variable: 'VERIFICATION_TARGET_ENVIRONMENT', value_type: 'environment_name', required: true, sensitive: false }),
  release_asset_name_template: Object.freeze({ environment_variable: 'VERIFICATION_RELEASE_ASSET_NAME_TEMPLATE', value_type: 'release_asset_name_template', required: true, sensitive: false }),
  primary_origin: Object.freeze({ environment_variable: 'VERIFICATION_PRIMARY_ORIGIN', value_type: 'https_origin', required: true, sensitive: false }),
  primary_check_path: Object.freeze({ environment_variable: 'VERIFICATION_PRIMARY_CHECK_PATH', value_type: 'relative_request_path', required: true, sensitive: false }),
  primary_public_marker: Object.freeze({ environment_variable: 'VERIFICATION_PRIMARY_PUBLIC_MARKER', value_type: 'literal_text', required: true, sensitive: false }),
  primary_version_path: Object.freeze({ environment_variable: 'VERIFICATION_PRIMARY_VERSION_PATH', value_type: 'relative_request_path', required: true, sensitive: false }),
  primary_version_header: Object.freeze({ environment_variable: 'VERIFICATION_PRIMARY_VERSION_HEADER', value_type: 'http_header_name', required: true, sensitive: false }),
  cdn_origin: Object.freeze({ environment_variable: 'VERIFICATION_CDN_ORIGIN', value_type: 'https_origin', required: false, sensitive: false, on_missing: 'remove_target_and_dependents' }),
  cdn_check_path: Object.freeze({ environment_variable: 'VERIFICATION_CDN_CHECK_PATH', value_type: 'relative_request_path', required: false, required_when_binding_present: 'cdn_origin', sensitive: false }),
  cdn_version_path: Object.freeze({ environment_variable: 'VERIFICATION_CDN_VERSION_PATH', value_type: 'relative_request_path', required: false, required_when_binding_present: 'cdn_origin', sensitive: false }),
  cdn_version_header: Object.freeze({ environment_variable: 'VERIFICATION_CDN_VERSION_HEADER', value_type: 'http_header_name', required: false, required_when_binding_present: 'cdn_origin', sensitive: false }),
});
const RESERVED_RUNTIME_VARIABLES = new Set([
  'VERIFICATION_CONFIG_TEMPLATE', 'VERIFICATION_TEMP_ROOT', 'VERIFICATION_CONFIG', 'TARGET_ENVIRONMENT',
  'TARGET_BASIC_AUTH_USERNAME', 'TARGET_BASIC_AUTH_PASSWORD', 'GITHUB_TOKEN', 'NODE_OPTIONS',
]);
const DEFAULT_TIMERS = Object.freeze({ setTimeout: globalThis.setTimeout, clearTimeout: globalThis.clearTimeout });

class VerificationError extends Error {
  constructor(code, status = 'blocked', incidentEligible = false) {
    const normalized = normalizeCode(code);
    super(normalized);
    this.name = 'VerificationError';
    this.code = normalized;
    this.status = ['fail', 'blocked', 'not_observable_read_only'].includes(status) ? status : 'blocked';
    this.incidentEligible = incidentEligible === true;
  }
}

function normalizeCode(value) {
  const normalized = String(value ?? 'unexpected_error').toLowerCase().replace(/[^a-z0-9_.:|-]+/gu, '_').replace(/^_+|_+$/gu, '').slice(0, 512);
  return normalized && CODE_PATTERN.test(normalized) ? normalized : 'unexpected_error';
}

function digest(value, length = 16) {
  return crypto.createHash('sha256').update(String(value)).digest('hex').slice(0, length);
}

export function environmentDigest(selectedEnvironment) {
  invariant(typeof selectedEnvironment === 'string' && SAFE_ENVIRONMENT.test(selectedEnvironment), 'environment_digest_source_invalid');
  return crypto.createHash('sha256').update(`${ENVIRONMENT_DIGEST_DOMAIN}${selectedEnvironment}`, 'utf8').digest('hex');
}

function invariant(value, code) {
  if (!value) throw new VerificationError(`config:${code}`, 'blocked', false);
}

function exactKeys(object, allowed, label) {
  invariant(object && typeof object === 'object' && !Array.isArray(object), `${label}_must_be_object`);
  for (const key of Object.keys(object)) invariant(allowed.includes(key), `${label}_unknown_key`);
}

function literal(value, label, maximum = 512) {
  invariant(typeof value === 'string' && value.length > 0 && value.length <= maximum, `${label}_invalid`);
  invariant(!/[\u0000-\u001f\u007f]/u.test(value), `${label}_control_character`);
  return value;
}

function contentLiteral(value, label, maximum = 512) {
  invariant(typeof value === 'string' && value.length > 0 && value.length <= maximum, `${label}_invalid`);
  invariant(!/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value), `${label}_control_character`);
  return value;
}

function boolean(value, label) {
  invariant(typeof value === 'boolean', `${label}_must_be_boolean`);
  return value;
}

function normalizedHostname(url) {
  return url.hostname.replace(/^\[|\]$/gu, '').replace(/\.$/u, '').toLowerCase();
}

function isUnsafeIpv4(address) {
  const octets = address.split('.').map(Number);
  if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return true;
  const [a, b, c] = octets;
  return a === 0 || a === 10 || a === 127 ||
    (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 0 && c === 0) ||
    (a === 192 && b === 0 && c === 2) || (a === 192 && b === 31 && c === 196) ||
    (a === 192 && b === 52 && c === 193) || (a === 192 && b === 88 && c === 99) ||
    (a === 192 && b === 168) || (a === 192 && b === 175 && c === 48) ||
    (a === 198 && (b === 18 || b === 19)) || (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113) || a >= 224;
}

function isUnsafeIpv6(address) {
  const normalized = address.toLowerCase().split('%')[0];
  if (!/^[23][0-9a-f]{0,3}:/u.test(normalized)) return true;
  const special = new net.BlockList();
  special.addSubnet('2001::', 23, 'ipv6');
  special.addSubnet('2001:db8::', 32, 'ipv6');
  special.addSubnet('2002::', 16, 'ipv6');
  special.addSubnet('3fff::', 20, 'ipv6');
  return special.check(normalized, 'ipv6');
}

export function isUnsafeIp(address) {
  const family = net.isIP(address);
  return family === 4 ? isUnsafeIpv4(address) : family === 6 ? isUnsafeIpv6(address) : true;
}

function canonicalOrigin(url) {
  return `${url.protocol}//${normalizedHostname(url)}:${url.port || '443'}`;
}

function rejectAmbiguousPathEncoding(raw, label) {
  invariant(typeof raw === 'string' && !raw.includes('\\'), `${label}_backslash_forbidden`);
  let value = raw;
  for (let depth = 0; depth < 3; depth += 1) {
    invariant(!/%(?:2f|5c)/iu.test(value), `${label}_encoded_separator_forbidden`);
    let decoded;
    try { decoded = decodeURIComponent(value); } catch { throw new VerificationError(`config:${label}_invalid_url_encoding`); }
    invariant(!decoded.includes('\\'), `${label}_backslash_forbidden`);
    invariant(!decoded.split('/').includes('..'), `${label}_traversal_forbidden`);
    if (decoded === value) return;
    value = decoded;
  }
  try {
    invariant(decodeURIComponent(value) === value, `${label}_encoding_depth_exceeded`);
  } catch (error) {
    if (error instanceof VerificationError) throw error;
    throw new VerificationError(`config:${label}_invalid_url_encoding`);
  }
}

function validateHttpsUrl(raw, label, requireRootPath = false) {
  rejectAmbiguousPathEncoding(raw, label);
  let url;
  try { url = new URL(raw); } catch { throw new VerificationError(`config:${label}_invalid_url`); }
  invariant(url.protocol === 'https:', `${label}_https_required`);
  invariant(!url.username && !url.password, `${label}_userinfo_forbidden`);
  invariant(!url.search && !url.hash, `${label}_query_or_fragment_forbidden`);
  const hostname = normalizedHostname(url);
  invariant(hostname && !net.isIP(hostname), `${label}_ip_literal_forbidden`);
  invariant(!['localhost', 'localhost.localdomain'].includes(hostname), `${label}_localhost_forbidden`);
  invariant(!url.port || Number(url.port) === 443 || (Number(url.port) >= 1024 && Number(url.port) <= 65_535), `${label}_port_forbidden`);
  if (requireRootPath) invariant(url.pathname === '/', `${label}_must_be_origin_only`);
  return url;
}

function validateTargetUrl(raw, label) {
  const url = validateHttpsUrl(raw, label);
  invariant(url.pathname.endsWith('/'), `${label}_base_path_must_end_slash`);
  return url;
}

function validatePath(raw, label) {
  literal(raw, label, 1_024);
  rejectAmbiguousPathEncoding(raw, label);
  invariant(raw.startsWith('/') && !raw.startsWith('//'), `${label}_must_be_root_relative`);
  invariant(!raw.includes('?') && !raw.includes('#') && !raw.includes('\\'), `${label}_query_fragment_or_backslash_forbidden`);
  invariant(!decodeURIComponent(raw).split('/').includes('..'), `${label}_traversal_forbidden`);
  return raw;
}

function pathWithin(baseUrl, url) {
  const basePath = baseUrl.pathname;
  return canonicalOrigin(baseUrl) === canonicalOrigin(url) && (url.pathname === basePath.slice(0, -1) || url.pathname.startsWith(basePath));
}

function composeTargetUrl(target, requestPath) {
  const url = new URL(requestPath.slice(1), target.baseUrl);
  if (!pathWithin(target.baseUrl, url)) throw new VerificationError('config:target_path_escape');
  return url;
}

function validateLiteralArray(value, label) {
  invariant(Array.isArray(value) && value.length <= 16, `${label}_must_be_small_array`);
  return value.map((item, index) => contentLiteral(item, `${label}_${index}`, 256));
}

function validateCheck(raw, index, targets) {
  exactKeys(raw, ['id', 'target', 'type', 'path', 'method', 'expected_status', 'required', 'fatal_signatures', 'required_text', 'forbidden_text', 'observable'], `check_${index}`);
  invariant(typeof raw.id === 'string' && SAFE_ID.test(raw.id), `check_${index}_id_invalid`);
  invariant(typeof raw.target === 'string' && Object.hasOwn(targets, raw.target), `check_${index}_target_invalid`);
  invariant(['page', 'asset'].includes(raw.type), `check_${index}_type_invalid`);
  validatePath(raw.path, `check_${index}_path`);
  invariant(['GET', 'HEAD'].includes(raw.method), `check_${index}_method_not_read_only`);
  invariant(Number.isInteger(raw.expected_status) && raw.expected_status >= 200 && raw.expected_status < 500 && !REDIRECT_CODES.has(raw.expected_status) && ![401, 403].includes(raw.expected_status), `check_${index}_status_contract_forbidden`);
  boolean(raw.required, `check_${index}_required`);
  boolean(raw.fatal_signatures, `check_${index}_fatal_signatures`);
  invariant(!raw.fatal_signatures || (raw.type === 'page' && raw.method === 'GET'), `check_${index}_fatal_signatures_page_get_only`);
  const observable = raw.observable === undefined ? true : boolean(raw.observable, `check_${index}_observable`);
  const requiredText = validateLiteralArray(raw.required_text, `check_${index}_required_text`);
  const forbiddenText = validateLiteralArray(raw.forbidden_text, `check_${index}_forbidden_text`);
  invariant(raw.method === 'GET' || (requiredText.length === 0 && forbiddenText.length === 0), `check_${index}_head_cannot_have_markers`);
  return { ...raw, observable, required_text: requiredText, forbidden_text: forbiddenText };
}

function validateVersionSource(raw, index, targets) {
  exactKeys(raw, ['id', 'target', 'type', 'path', 'required', 'prefix', 'suffix', 'json_pointer', 'header_name'], `version_source_${index}`);
  invariant(typeof raw.id === 'string' && SAFE_ID.test(raw.id), `version_source_${index}_id_invalid`);
  invariant(typeof raw.target === 'string' && Object.hasOwn(targets, raw.target), `version_source_${index}_target_invalid`);
  invariant(['text_marker', 'json_manifest', 'response_header'].includes(raw.type), `version_source_${index}_type_invalid`);
  validatePath(raw.path, `version_source_${index}_path`);
  boolean(raw.required, `version_source_${index}_required`);
  if (raw.type === 'text_marker') {
    exactKeys(raw, ['id', 'target', 'type', 'path', 'required', 'prefix', 'suffix'], `version_source_${index}`);
    contentLiteral(raw.prefix, `version_source_${index}_prefix`, 128);
    contentLiteral(raw.suffix, `version_source_${index}_suffix`, 128);
  } else if (raw.type === 'json_manifest') {
    exactKeys(raw, ['id', 'target', 'type', 'path', 'required', 'json_pointer'], `version_source_${index}`);
    literal(raw.json_pointer, `version_source_${index}_json_pointer`, 128);
    invariant(raw.json_pointer.startsWith('/') && !raw.json_pointer.includes('~'), `version_source_${index}_json_pointer_simple_only`);
  } else {
    exactKeys(raw, ['id', 'target', 'type', 'path', 'required', 'header_name'], `version_source_${index}`);
    literal(raw.header_name, `version_source_${index}_header_name`, 64);
    const header = raw.header_name.toLowerCase();
    invariant(/^[a-z0-9-]+$/u.test(header) && !SENSITIVE_HEADERS.has(header), `version_source_${index}_header_forbidden`);
  }
  return { ...raw };
}

function targetContainingUrl(targets, url) {
  const matches = Object.entries(targets).filter(([, target]) => pathWithin(target.baseUrl, url));
  return matches.length === 1 ? matches[0][0] : null;
}

function validateEnvironment(environment, label, limits) {
  exactKeys(environment, ['targets', 'allowed_redirects', 'checks', 'version_sources'], label);
  invariant(environment.targets && typeof environment.targets === 'object' && !Array.isArray(environment.targets), `${label}_targets_invalid`);
  const targetEntries = Object.entries(environment.targets);
  invariant(targetEntries.length >= 1 && targetEntries.length <= 8 && Object.hasOwn(environment.targets, 'primary'), `${label}_targets_count_or_primary_invalid`);
  const targets = {};
  const origins = new Set();
  for (const [id, raw] of targetEntries) {
    invariant(SAFE_ID.test(id), `${label}_target_id_invalid`);
    exactKeys(raw, ['base_url', 'basic_auth'], `${label}_target_${id}`);
    const baseUrl = validateTargetUrl(raw.base_url, `${label}_target_${id}_base_url`);
    boolean(raw.basic_auth, `${label}_target_${id}_basic_auth`);
    invariant(id === 'primary' || raw.basic_auth === false, `${label}_basic_auth_primary_only`);
    const origin = canonicalOrigin(baseUrl);
    invariant(!origins.has(origin), `${label}_duplicate_target_origin`);
    origins.add(origin);
    targets[id] = { ...raw, baseUrl, origin };
  }
  invariant(Array.isArray(environment.allowed_redirects) && environment.allowed_redirects.length <= 16, `${label}_allowed_redirects_invalid`);
  const allowedRedirects = new Map();
  for (const [index, redirect] of environment.allowed_redirects.entries()) {
    exactKeys(redirect, ['from', 'to'], `${label}_redirect_${index}`);
    const from = validateHttpsUrl(redirect.from, `${label}_redirect_${index}_from`);
    const to = validateHttpsUrl(redirect.to, `${label}_redirect_${index}_to`);
    invariant(targetContainingUrl(targets, from) && targetContainingUrl(targets, to), `${label}_redirect_${index}_outside_target_base_path`);
    const fromKey = `${canonicalOrigin(from)}${from.pathname}`;
    const toKey = `${canonicalOrigin(to)}${to.pathname}`;
    invariant(!allowedRedirects.has(fromKey), `${label}_redirect_${index}_duplicate_from`);
    allowedRedirects.set(fromKey, toKey);
  }
  invariant(Array.isArray(environment.checks) && environment.checks.length >= 1 && environment.checks.length <= 10, `${label}_checks_count_invalid`);
  const checks = environment.checks.map((check, index) => validateCheck(check, index, targets));
  invariant(new Set(checks.map((check) => check.id)).size === checks.length, `${label}_check_ids_duplicate`);
  invariant(Array.isArray(environment.version_sources) && environment.version_sources.length <= 4, `${label}_version_sources_invalid`);
  const versionSources = environment.version_sources.map((source, index) => validateVersionSource(source, index, targets));
  invariant(new Set(versionSources.map((source) => source.id)).size === versionSources.length, `${label}_version_source_ids_duplicate`);
  invariant(versionSources.some((source) => source.required), `${label}_required_observable_version_source_missing`);
  const minimumRequests = checks.filter((check) => check.observable).length + versionSources.length;
  invariant(minimumRequests <= limits.max_requests_per_attempt, `${label}_minimum_requests_exceed_attempt_budget`);
  invariant(minimumRequests * limits.max_attempts <= limits.max_total_requests, `${label}_minimum_requests_exceed_total_budget`);
  const minimumTime = Math.ceil(minimumRequests / limits.request_concurrency) * limits.request_timeout_ms * limits.max_attempts +
    limits.retry_delay_ms * (limits.max_attempts - 1) + limits.evidence_reserve_ms;
  invariant(minimumTime <= limits.phase_timeout_ms, `${label}_minimum_time_exceeds_phase_budget`);
  return { targets, allowedRedirects, checks, versionSources };
}

function validateLimits(raw) {
  exactKeys(raw.limits, Object.keys(DEFAULT_LIMITS), 'limits');
  const limits = { ...DEFAULT_LIMITS, ...raw.limits };
  for (const [name, [minimum, maximum]] of Object.entries(LIMIT_RANGES)) {
    invariant(Number.isInteger(limits[name]) && limits[name] >= minimum && limits[name] <= maximum, `limit_${name}_out_of_range`);
  }
  invariant(limits.max_attempts >= limits.consecutive_successes, 'max_attempts_below_success_requirement');
  invariant(limits.max_attempts >= limits.incident_repeat_count, 'max_attempts_below_incident_requirement');
  invariant(limits.evidence_reserve_ms < limits.phase_timeout_ms, 'evidence_reserve_must_fit_phase');
  return limits;
}

export function validateConfig(raw, selectedEnvironment) {
  exactKeys(raw, ['schema_version', 'provenance', 'environments', 'limits'], 'root');
  invariant(raw.schema_version === RESOLVED_SCHEMA_VERSION, 'schema_version_unsupported');
  exactKeys(raw.provenance, ['mode', 'release_asset_name'], 'provenance');
  invariant(PROVENANCE_MODES.has(raw.provenance.mode), 'provenance_mode_invalid');
  literal(raw.provenance.release_asset_name, 'provenance_release_asset_name', 200);
  invariant((raw.provenance.release_asset_name.match(/\{version\}/gu) ?? []).length === 1, 'provenance_asset_requires_one_version_token');
  invariant(/^[A-Za-z0-9._+{}-]+\.zip$/u.test(raw.provenance.release_asset_name), 'provenance_asset_name_invalid');
  invariant(raw.environments && typeof raw.environments === 'object' && !Array.isArray(raw.environments), 'environments_invalid');
  const names = Object.keys(raw.environments);
  invariant(names.length >= 1 && names.length <= 32, 'environment_count_invalid');
  invariant(typeof selectedEnvironment === 'string' && SAFE_ENVIRONMENT.test(selectedEnvironment), 'selected_environment_invalid');
  invariant(Object.hasOwn(raw.environments, selectedEnvironment), 'selected_environment_not_declared');
  const limits = validateLimits(raw);
  const environments = {};
  const environmentNames = new Set();
  const targetOrigins = new Set();
  for (const [index, [name, environment]] of Object.entries(raw.environments).entries()) {
    invariant(SAFE_ENVIRONMENT.test(name), `environment_${index}_name_invalid`);
    invariant(!environmentNames.has(name.toLowerCase()), 'duplicate_environment_name_case_insensitive');
    environmentNames.add(name.toLowerCase());
    environments[name] = validateEnvironment(environment, `environment_${index}`, limits);
    for (const target of Object.values(environments[name].targets)) {
      invariant(!targetOrigins.has(target.origin), 'duplicate_target_instance');
      targetOrigins.add(target.origin);
    }
  }
  const environment = environments[selectedEnvironment];
  return {
    schema_version: RESOLVED_SCHEMA_VERSION,
    selectedEnvironment,
    provenance: { ...raw.provenance },
    environments,
    environment,
    limits,
    primaryOrigin: environment.targets.primary.origin,
    basicAuthRequired: environment.targets.primary.basic_auth,
  };
}

function sameArray(actual, expected, label) {
  invariant(Array.isArray(actual) && actual.length === expected.length, `${label}_invalid`);
  for (let index = 0; index < expected.length; index += 1) invariant(actual[index] === expected[index], `${label}_${index}_invalid`);
}

function bindingReference(raw, expected, label) {
  exactKeys(raw, ['binding'], label);
  invariant(raw.binding === expected, `${label}_invalid`);
}

function containsRawInterpolation(value) {
  if (typeof value === 'string') return /\$\{[^}]*\}/u.test(value);
  if (Array.isArray(value)) return value.some(containsRawInterpolation);
  if (value && typeof value === 'object') return Object.values(value).some(containsRawInterpolation);
  return false;
}

function assertUniqueJsonObjectKeys(text, label) {
  let offset = 0;
  const skipWhitespace = () => { while (/\s/u.test(text[offset] ?? '')) offset += 1; };
  const readString = () => {
    const start = offset;
    offset += 1;
    while (offset < text.length) {
      if (text[offset] === '\\') offset += 2;
      else if (text[offset] === '"') { offset += 1; break; }
      else offset += 1;
    }
    return JSON.parse(text.slice(start, offset));
  };
  const walk = () => {
    skipWhitespace();
    if (text[offset] === '{') {
      offset += 1;
      const keys = new Set();
      skipWhitespace();
      if (text[offset] === '}') { offset += 1; return; }
      while (offset < text.length) {
        skipWhitespace();
        const key = readString();
        invariant(!keys.has(key), `${label}_duplicate_key`);
        keys.add(key);
        skipWhitespace();
        offset += 1;
        walk();
        skipWhitespace();
        if (text[offset] === '}') { offset += 1; return; }
        offset += 1;
      }
      return;
    }
    if (text[offset] === '[') {
      offset += 1;
      skipWhitespace();
      if (text[offset] === ']') { offset += 1; return; }
      while (offset < text.length) {
        walk();
        skipWhitespace();
        if (text[offset] === ']') { offset += 1; return; }
        offset += 1;
      }
      return;
    }
    if (text[offset] === '"') { readString(); return; }
    while (offset < text.length && !/[\s,}\]]/u.test(text[offset])) offset += 1;
  };
  walk();
  skipWhitespace();
  invariant(offset === text.length, `${label}_trailing_content`);
}

function parseJsonDocument(bytes, label) {
  invariant(bytes.length <= 131_072, `${label}_too_large`);
  const text = bytes.toString('utf8');
  let raw;
  try { raw = JSON.parse(text); } catch { throw new VerificationError(`config:${label}_invalid_json`); }
  assertUniqueJsonObjectKeys(text, label);
  invariant(!containsRawInterpolation(raw), `${label}_raw_interpolation_forbidden`);
  return raw;
}

function validateTemplateCheck(raw, id) {
  const conditional = id === 'cdn-public';
  exactKeys(raw, conditional ?
    ['id', 'include_when_binding_present', 'target', 'type', 'path', 'method', 'expected_status', 'required', 'fatal_signatures', 'required_text', 'forbidden_text'] :
    ['id', 'target', 'type', 'path', 'method', 'expected_status', 'required', 'fatal_signatures', 'required_text', 'forbidden_text'], `template_check_${id}`);
  invariant(raw.id === id, `template_check_${id}_id_invalid`);
  invariant(raw.target === (conditional ? 'cdn' : 'primary'), `template_check_${id}_target_invalid`);
  invariant(raw.type === (conditional ? 'asset' : 'page'), `template_check_${id}_type_invalid`);
  bindingReference(raw.path, conditional ? 'cdn_check_path' : 'primary_check_path', `template_check_${id}_path`);
  invariant(raw.method === (conditional ? 'HEAD' : 'GET'), `template_check_${id}_method_invalid`);
  invariant(raw.expected_status === 200 && raw.required === true, `template_check_${id}_required_contract_invalid`);
  invariant(raw.fatal_signatures === !conditional, `template_check_${id}_fatal_contract_invalid`);
  if (conditional) {
    invariant(raw.include_when_binding_present === 'cdn_origin', `template_check_${id}_condition_invalid`);
    sameArray(raw.required_text, [], `template_check_${id}_required_text`);
  } else {
    invariant(Array.isArray(raw.required_text) && raw.required_text.length === 1, `template_check_${id}_required_text_invalid`);
    bindingReference(raw.required_text[0], 'primary_public_marker', `template_check_${id}_public_marker`);
  }
  sameArray(raw.forbidden_text, [], `template_check_${id}_forbidden_text`);
}

function validateTemplateVersionSource(raw, id) {
  const conditional = id === 'cdn-version';
  exactKeys(raw, conditional ?
    ['id', 'include_when_binding_present', 'target', 'type', 'path', 'required', 'header_name'] :
    ['id', 'target', 'type', 'path', 'required', 'header_name'], `template_version_source_${id}`);
  invariant(raw.id === id, `template_version_source_${id}_id_invalid`);
  invariant(raw.target === (conditional ? 'cdn' : 'primary'), `template_version_source_${id}_target_invalid`);
  invariant(raw.type === 'response_header' && raw.required === true, `template_version_source_${id}_contract_invalid`);
  bindingReference(raw.path, conditional ? 'cdn_version_path' : 'primary_version_path', `template_version_source_${id}_path`);
  bindingReference(raw.header_name, conditional ? 'cdn_version_header' : 'primary_version_header', `template_version_source_${id}_header`);
  if (conditional) invariant(raw.include_when_binding_present === 'cdn_origin', `template_version_source_${id}_condition_invalid`);
}

export function validateConfigTemplate(raw) {
  exactKeys(raw, ['document_kind', 'template_schema_version', 'resolved_schema_version', 'validation_contract', 'resolution_contract', 'bindings', 'template'], 'template_root');
  invariant(!containsRawInterpolation(raw), 'template_raw_interpolation_forbidden');
  invariant(raw.document_kind === TEMPLATE_DOCUMENT_KIND, 'template_document_kind_invalid');
  invariant(raw.template_schema_version === TEMPLATE_SCHEMA_VERSION, 'template_schema_version_unsupported');
  invariant(raw.resolved_schema_version === RESOLVED_SCHEMA_VERSION, 'template_resolved_schema_version_unsupported');

  exactKeys(raw.validation_contract, ['template_validation', 'resolved_validation', 'template_is_resolved_config'], 'template_validation_contract');
  invariant(raw.validation_contract.template_validation === 'binding_metadata_only', 'template_validation_contract_invalid');
  invariant(raw.validation_contract.resolved_validation === 'engine_schema_v2', 'resolved_validation_contract_invalid');
  invariant(raw.validation_contract.template_is_resolved_config === false, 'template_must_not_be_resolved');

  exactKeys(raw.resolution_contract, ['unknown_input_policy', 'missing_required_input_policy', 'invalid_input_policy', 'resolved_environment_key_binding', 'optional_targets'], 'template_resolution_contract');
  invariant(raw.resolution_contract.unknown_input_policy === 'reject', 'template_unknown_input_policy_invalid');
  invariant(raw.resolution_contract.missing_required_input_policy === 'reject', 'template_missing_input_policy_invalid');
  invariant(raw.resolution_contract.invalid_input_policy === 'reject', 'template_invalid_input_policy_invalid');
  invariant(raw.resolution_contract.resolved_environment_key_binding === 'target_environment', 'template_environment_key_binding_invalid');
  exactKeys(raw.resolution_contract.optional_targets, ['cdn'], 'template_optional_targets');
  const optionalCdn = raw.resolution_contract.optional_targets.cdn;
  exactKeys(optionalCdn, ['binding', 'on_missing', 'dependent_check_ids', 'dependent_version_source_ids'], 'template_optional_target_cdn');
  invariant(optionalCdn.binding === 'cdn_origin' && optionalCdn.on_missing === 'remove_target_and_dependents', 'template_optional_target_cdn_contract_invalid');
  sameArray(optionalCdn.dependent_check_ids, ['cdn-public'], 'template_optional_target_cdn_checks');
  sameArray(optionalCdn.dependent_version_source_ids, ['cdn-version'], 'template_optional_target_cdn_sources');

  exactKeys(raw.bindings, Object.keys(TEMPLATE_BINDINGS), 'template_bindings');
  const environmentVariables = new Set();
  for (const [key, expected] of Object.entries(TEMPLATE_BINDINGS)) {
    const binding = raw.bindings[key];
    exactKeys(binding, Object.keys(expected), `template_binding_${key}`);
    for (const [field, value] of Object.entries(expected)) {
      if (field !== 'environment_variable') invariant(binding[field] === value, `template_binding_${key}_${field}_invalid`);
    }
    invariant(typeof binding.environment_variable === 'string' && BINDING_ENVIRONMENT_VARIABLE_PATTERN.test(binding.environment_variable), `template_binding_${key}_environment_variable_invalid`);
    invariant(!environmentVariables.has(binding.environment_variable), `template_binding_${key}_environment_variable_duplicate`);
    invariant(!RESERVED_RUNTIME_VARIABLES.has(binding.environment_variable), `template_binding_${key}_uses_reserved_runtime_variable`);
    invariant(!/^(?:GITHUB_|RUNNER_|ACTIONS_)/u.test(binding.environment_variable), `template_binding_${key}_uses_reserved_platform_prefix`);
    environmentVariables.add(binding.environment_variable);
  }

  exactKeys(raw.template, ['schema_version', 'provenance', 'environment', 'limits'], 'template_body');
  invariant(raw.template.schema_version === RESOLVED_SCHEMA_VERSION, 'template_body_schema_version_invalid');
  exactKeys(raw.template.provenance, ['mode', 'release_asset_name'], 'template_provenance');
  invariant(raw.template.provenance.mode === 'github_release_required', 'template_provenance_mode_invalid');
  bindingReference(raw.template.provenance.release_asset_name, 'release_asset_name_template', 'template_release_asset_name');

  const environment = raw.template.environment;
  exactKeys(environment, ['name', 'targets', 'allowed_redirects', 'checks', 'version_sources'], 'template_environment');
  bindingReference(environment.name, 'target_environment', 'template_environment_name');
  exactKeys(environment.targets, ['primary', 'cdn'], 'template_targets');
  exactKeys(environment.targets.primary, ['base_url', 'basic_auth'], 'template_target_primary');
  bindingReference(environment.targets.primary.base_url, 'primary_origin', 'template_target_primary_base_url');
  invariant(environment.targets.primary.basic_auth === false, 'template_target_primary_basic_auth_default_invalid');
  exactKeys(environment.targets.cdn, ['include_when_binding_present', 'base_url', 'basic_auth'], 'template_target_cdn');
  invariant(environment.targets.cdn.include_when_binding_present === 'cdn_origin', 'template_target_cdn_condition_invalid');
  bindingReference(environment.targets.cdn.base_url, 'cdn_origin', 'template_target_cdn_base_url');
  invariant(environment.targets.cdn.basic_auth === false, 'template_target_cdn_basic_auth_default_invalid');
  sameArray(environment.allowed_redirects, [], 'template_allowed_redirects');

  invariant(Array.isArray(environment.checks) && environment.checks.length === 2, 'template_checks_invalid');
  const checks = new Map(environment.checks.map((check) => [check?.id, check]));
  invariant(checks.size === 2 && checks.has('primary-public') && checks.has('cdn-public'), 'template_check_ids_invalid');
  validateTemplateCheck(checks.get('primary-public'), 'primary-public');
  validateTemplateCheck(checks.get('cdn-public'), 'cdn-public');

  invariant(Array.isArray(environment.version_sources) && environment.version_sources.length === 2, 'template_version_sources_invalid');
  const sources = new Map(environment.version_sources.map((source) => [source?.id, source]));
  invariant(sources.size === 2 && sources.has('primary-version') && sources.has('cdn-version'), 'template_version_source_ids_invalid');
  validateTemplateVersionSource(sources.get('primary-version'), 'primary-version');
  validateTemplateVersionSource(sources.get('cdn-version'), 'cdn-version');
  validateLimits(raw.template);
  return raw;
}

function validateBindingValue(key, metadata, value) {
  invariant(typeof value === 'string' && value.length > 0 && value.length <= 1_024, `binding_${key}_missing_or_invalid`);
  invariant(!/\$\{[^}]*\}/u.test(value), `binding_${key}_raw_interpolation_forbidden`);
  if (metadata.value_type === 'environment_name') {
    invariant(SAFE_ENVIRONMENT.test(value), `binding_${key}_invalid`);
    return value;
  }
  if (metadata.value_type === 'release_asset_name_template') {
    invariant(value.length <= 200 && (value.match(/\{version\}/gu) ?? []).length === 1, `binding_${key}_invalid`);
    invariant(/^[A-Za-z0-9._+{}-]+\.zip$/u.test(value), `binding_${key}_invalid`);
    return value;
  }
  if (metadata.value_type === 'https_origin') return validateHttpsUrl(value, `binding_${key}`, true).href;
  if (metadata.value_type === 'relative_request_path') return validatePath(value, `binding_${key}`);
  if (metadata.value_type === 'literal_text') return contentLiteral(value, `binding_${key}`, 256);
  if (metadata.value_type === 'http_header_name') {
    literal(value, `binding_${key}`, 64);
    const header = value.toLowerCase();
    invariant(/^[a-z0-9-]+$/u.test(header) && !SENSITIVE_HEADERS.has(header), `binding_${key}_invalid`);
    return header;
  }
  throw new VerificationError(`config:binding_${key}_value_type_unsupported`);
}

function resolvedBindingValues(template, environment) {
  const values = new Map();
  for (const [key, metadata] of Object.entries(template.bindings)) {
    const rawValue = environment[metadata.environment_variable];
    if (rawValue === undefined) {
      invariant(metadata.required === false, `binding_${key}_missing`);
      continue;
    }
    values.set(key, validateBindingValue(key, metadata, rawValue));
  }
  for (const [key, metadata] of Object.entries(template.bindings)) {
    const dependency = metadata.required_when_binding_present;
    if (!dependency) continue;
    if (values.has(dependency)) invariant(values.has(key), `binding_${key}_required_by_${dependency}`);
    else invariant(!values.has(key), `binding_${key}_without_${dependency}`);
  }
  invariant(typeof environment.TARGET_ENVIRONMENT === 'string' && environment.TARGET_ENVIRONMENT.length > 0, 'target_environment_control_missing');
  invariant(environment.TARGET_ENVIRONMENT === values.get('target_environment'), 'target_environment_control_mismatch');
  return values;
}

const OMIT_TEMPLATE_NODE = Symbol('omit-template-node');

function materializeTemplateNode(node, values, counts) {
  if (Array.isArray(node)) {
    const result = [];
    for (const item of node) {
      const materialized = materializeTemplateNode(item, values, counts);
      if (materialized !== OMIT_TEMPLATE_NODE) result.push(materialized);
    }
    return result;
  }
  if (!node || typeof node !== 'object') return node;
  if (Object.hasOwn(node, 'binding')) {
    exactKeys(node, ['binding'], 'template_runtime_binding_reference');
    invariant(Object.hasOwn(TEMPLATE_BINDINGS, node.binding), 'template_runtime_binding_unknown');
    invariant(values.has(node.binding), `binding_${node.binding}_unresolved`);
    counts.set(node.binding, (counts.get(node.binding) ?? 0) + 1);
    invariant(counts.get(node.binding) === 1, `binding_${node.binding}_resolved_more_than_once`);
    return values.get(node.binding);
  }
  if (Object.hasOwn(node, 'include_when_binding_present') && !values.has(node.include_when_binding_present)) return OMIT_TEMPLATE_NODE;
  const result = {};
  for (const [key, value] of Object.entries(node)) {
    if (key === 'include_when_binding_present') continue;
    const materialized = materializeTemplateNode(value, values, counts);
    if (materialized !== OMIT_TEMPLATE_NODE) result[key] = materialized;
  }
  return result;
}

export function validateResolvedConfig(raw, selectedEnvironment) {
  invariant(raw?.document_kind !== TEMPLATE_DOCUMENT_KIND, 'resolved_config_must_not_be_template');
  invariant(!containsRawInterpolation(raw), 'resolved_config_raw_interpolation_forbidden');
  return validateConfig(raw, selectedEnvironment);
}

export function resolveConfigBindings(rawTemplate, environment = process.env) {
  const template = validateConfigTemplate(rawTemplate);
  const values = resolvedBindingValues(template, environment);
  const counts = new Map();
  const materialized = materializeTemplateNode(template.template, values, counts);
  const environmentName = materialized.environment.name;
  const { name: discardedName, ...resolvedEnvironment } = materialized.environment;
  void discardedName;
  const resolved = {
    schema_version: materialized.schema_version,
    provenance: materialized.provenance,
    environments: { [environmentDigest(environmentName)]: resolvedEnvironment },
    limits: materialized.limits,
  };
  for (const key of Object.keys(TEMPLATE_BINDINGS)) {
    invariant((counts.get(key) ?? 0) === (values.has(key) ? 1 : 0), `binding_${key}_resolution_count_invalid`);
  }
  validateResolvedConfig(resolved, environmentDigest(environmentName));
  return resolved;
}

function loadConfig(configPath, selectedEnvironment, fileSystem = fs) {
  const bytes = fileSystem.readFileSync(configPath);
  const raw = parseJsonDocument(bytes, 'resolved_config');
  const validated = validateResolvedConfig(raw, environmentDigest(selectedEnvironment));
  invariant(Object.keys(validated.environments).length === 1, 'resolved_environment_count_invalid');
  return { ...validated, selectedEnvironment, configDigest: crypto.createHash('sha256').update(bytes).digest('hex') };
}

function cleanError(error) {
  if (error instanceof VerificationError) return error;
  const code = normalizeCode(error?.code ?? 'unexpected_error');
  if (['econnreset', 'econnrefused', 'etimedout', 'ehostunreach', 'enetunreach', 'enotfound', 'eai_again'].includes(code)) {
    return new VerificationError(`target_network:${code}`, 'blocked', true);
  }
  if (code === 'hpe_header_overflow') return new VerificationError('target_protocol:headers_too_large', 'fail', true);
  return new VerificationError('internal:unexpected_error', 'blocked', false);
}

function faultFingerprint(id, status, code) {
  return digest(`${id}\0${status}\0${normalizeCode(code)}`, 24);
}

function withDefaultTimers(dependencies = {}) {
  return {
    ...dependencies,
    setTimeout: dependencies.setTimeout ?? DEFAULT_TIMERS.setTimeout,
    clearTimeout: dependencies.clearTimeout ?? DEFAULT_TIMERS.clearTimeout,
  };
}

function withTimeout(promise, milliseconds, timers = DEFAULT_TIMERS) {
  invariant(typeof timers.setTimeout === 'function' && typeof timers.clearTimeout === 'function', 'timers_invalid');
  return new Promise((resolve, reject) => {
    const timer = timers.setTimeout(() => reject(new VerificationError('target_network:etimedout', 'blocked', true)), milliseconds);
    promise.then(
      (value) => { timers.clearTimeout(timer); resolve(value); },
      (error) => { timers.clearTimeout(timer); reject(error); },
    );
  });
}

async function resolvePublic(hostname, dependencies = {}) {
  let records;
  try { records = await (dependencies.dnsLookup ?? dns.lookup)(hostname, { all: true, verbatim: true }); }
  catch (error) { throw cleanError(error); }
  if (!records.length) throw new VerificationError('target_network:dns_empty', 'blocked', true);
  if (records.some((record) => isUnsafeIp(record.address))) throw new VerificationError('target_network:dns_non_public', 'blocked', true);
  return records;
}

function inspectHeaders(rawHeaders, limits) {
  if (rawHeaders.length / 2 > limits.max_response_headers) throw new VerificationError('target_protocol:too_many_headers', 'fail', true);
  let total = 0;
  const counts = new Map();
  for (let index = 0; index < rawHeaders.length; index += 2) {
    const name = String(rawHeaders[index]).toLowerCase();
    const value = String(rawHeaders[index + 1] ?? '');
    total += Buffer.byteLength(name) + Buffer.byteLength(value) + 4;
    counts.set(name, (counts.get(name) ?? 0) + 1);
  }
  if (total > limits.max_header_bytes) throw new VerificationError('target_protocol:headers_too_large', 'fail', true);
  return counts;
}

function decoderFor(encoding) {
  if (!encoding || encoding === 'identity') return null;
  if (encoding === 'gzip' || encoding === 'x-gzip') return createGunzip();
  if (encoding === 'deflate') return createInflate();
  if (encoding === 'br') return createBrotliDecompress();
  throw new VerificationError('target_protocol:unsupported_content_encoding', 'fail', true);
}

async function readDecodedBody(response, method, limits) {
  if (method === 'HEAD') { response.resume(); return ''; }
  let decoder;
  try { decoder = decoderFor(String(response.headers['content-encoding'] ?? '').toLowerCase().trim()); }
  catch (error) { response.destroy(); throw error; }
  const stream = decoder ? response.pipe(decoder) : response;
  const chunks = [];
  let size = 0;
  try {
    for await (const chunk of stream) {
      size += chunk.length;
      if (size > limits.max_body_bytes) throw new VerificationError('target_protocol:decoded_body_too_large', 'fail', true);
      chunks.push(chunk);
    }
  } catch (error) {
    response.destroy();
    decoder?.destroy();
    if (error instanceof VerificationError) throw error;
    throw new VerificationError('target_protocol:decompression_failed', 'fail', true);
  }
  return Buffer.concat(chunks, size).toString('utf8');
}

function requestOnce(url, method, auth, limits, records, dependencies = {}) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const allowed = new Set(records.map((record) => record.address));
    const chosen = records[0];
    const headers = {
      accept: '*/*',
      'accept-encoding': 'gzip, deflate, br',
      'cache-control': 'no-cache',
      pragma: 'no-cache',
      'user-agent': 'time-bounded-read-only-release-verifier/2',
    };
    if (auth) headers.authorization = `Basic ${Buffer.from(`${auth.username}:${auth.password}`, 'utf8').toString('base64')}`;
    const finish = (callback, value) => { if (!settled) { settled = true; callback(value); } };
    const requestImpl = dependencies.httpsRequest ?? https.request;
    const request = requestImpl(url, {
      method,
      headers,
      servername: normalizedHostname(url),
      lookup: (_hostname, _options, callback) => callback(null, chosen.address, chosen.family),
      timeout: limits.request_timeout_ms,
      maxHeaderSize: limits.max_header_bytes,
      agent: false,
    });
    const timer = (dependencies.setTimeout ?? setTimeout)(() => request.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })), limits.request_timeout_ms);
    request.once('socket', (socket) => socket.once('secureConnect', () => {
      const remote = socket.remoteAddress?.split('%')[0];
      if (!remote || !allowed.has(remote) || isUnsafeIp(remote)) socket.destroy(new VerificationError('target_network:dns_rebinding_detected', 'blocked', true));
    }));
    request.once('response', async (response) => {
      try {
        const headerCounts = inspectHeaders(response.rawHeaders, limits);
        const body = await readDecodedBody(response, method, limits);
        (dependencies.clearTimeout ?? clearTimeout)(timer);
        finish(resolve, { statusCode: response.statusCode ?? 0, headers: response.headers, headerCounts, body });
      } catch (error) {
        response.destroy();
        request.destroy();
        (dependencies.clearTimeout ?? clearTimeout)(timer);
        finish(reject, cleanError(error));
      }
    });
    request.once('error', (error) => {
      (dependencies.clearTimeout ?? clearTimeout)(timer);
      finish(reject, cleanError(error));
    });
    request.end();
  });
}

async function boundedRequest(startUrl, method, context) {
  let url = new URL(startUrl);
  const visited = new Set();
  const dependencies = withDefaultTimers(context.dependencies);
  for (let hop = 0; ; hop += 1) {
    if (context.phaseDeadline - context.now() <= context.limits.evidence_reserve_ms) throw new VerificationError('target_budget:phase_deadline', 'blocked', true);
    if (context.attemptRequests >= context.limits.max_requests_per_attempt || context.totalRequests >= context.limits.max_total_requests) {
      throw new VerificationError('target_budget:request_limit', 'blocked', false);
    }
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || net.isIP(normalizedHostname(url))) {
      throw new VerificationError('target_redirect:unsafe_url', 'fail', true);
    }
    const targetId = targetContainingUrl(context.targets, url);
    if (!targetId) throw new VerificationError('target_redirect:outside_target_base_path', 'fail', true);
    const key = `${canonicalOrigin(url)}${url.pathname}`;
    if (visited.has(key)) throw new VerificationError('target_redirect:loop', 'fail', true);
    visited.add(key);
    context.attemptRequests += 1;
    context.totalRequests += 1;
    const deadline = context.now() + context.limits.request_timeout_ms;
    const records = await withTimeout(
      (context.resolvePublic ?? resolvePublic)(normalizedHostname(url), dependencies),
      context.limits.request_timeout_ms,
      dependencies,
    );
    const remaining = deadline - context.now();
    if (remaining <= 0) throw new VerificationError('target_network:etimedout', 'blocked', true);
    const auth = targetId === 'primary' ? context.auth : null;
    const response = await (context.requestOnce ?? requestOnce)(url, method, auth, { ...context.limits, request_timeout_ms: remaining }, records, dependencies);
    if (!REDIRECT_CODES.has(response.statusCode)) return { ...response, targetId, finalPath: url.pathname, hops: hop };
    if (hop >= context.limits.max_redirect_hops) throw new VerificationError('target_redirect:max_hops', 'fail', true);
    const location = response.headers.location;
    if (Array.isArray(location) || typeof location !== 'string' || !location) throw new VerificationError('target_redirect:invalid_location', 'fail', true);
    let next;
    try { next = new URL(location, url); } catch { throw new VerificationError('target_redirect:invalid_location', 'fail', true); }
    if (next.protocol !== 'https:') throw new VerificationError('target_redirect:https_downgrade', 'fail', true);
    const destination = `${canonicalOrigin(next)}${next.pathname}`;
    if (context.allowedRedirects.get(key) !== destination) throw new VerificationError('target_redirect:undeclared_transition', 'fail', true);
    if (!targetContainingUrl(context.targets, next)) throw new VerificationError('target_redirect:outside_target_base_path', 'fail', true);
    url = next;
  }
}

function failureResult(id, required, error) {
  const clean = cleanError(error);
  return {
    id, required, status: clean.status, code: clean.code,
    fingerprint: faultFingerprint(id, clean.status, clean.code),
    incident_eligible: clean.incidentEligible,
  };
}

function validateTargetResponse(response, basicAuth) {
  if ([401, 403].includes(response.statusCode)) {
    if (basicAuth) throw new VerificationError('blocked_target_auth', 'blocked', true);
    throw new VerificationError('target_contract:unexpected_auth_status', 'fail', true);
  }
  if (response.statusCode >= 500) throw new VerificationError('target_contract:http_5xx', 'fail', true);
}

async function runCheck(check, context) {
  if (!check.observable) return { id: check.id, required: check.required, status: 'not_observable_read_only', code: 'requires_session_or_write', fingerprint: null, incident_eligible: false };
  try {
    const target = context.targets[check.target];
    const response = await context.performRequest(composeTargetUrl(target, check.path), check.method, context);
    validateTargetResponse(response, check.target === 'primary' && target.basic_auth);
    if (response.statusCode !== check.expected_status) throw new VerificationError('target_contract:unexpected_status', 'fail', true);
    if (check.fatal_signatures && FATAL_MARKERS.some((marker) => response.body.toLowerCase().includes(marker))) {
      throw new VerificationError('target_content:fatal_signature', 'fail', true);
    }
    for (const marker of check.required_text) if (!response.body.includes(marker)) throw new VerificationError('target_content:required_marker_missing', 'fail', true);
    for (const marker of check.forbidden_text) if (response.body.includes(marker)) throw new VerificationError('target_content:forbidden_marker_present', 'fail', true);
    return { id: check.id, required: check.required, status: 'pass', code: 'observed_as_required', fingerprint: null, incident_eligible: false };
  } catch (error) { return failureResult(check.id, check.required, error); }
}

function jsonPointer(document, pointer) {
  let value = document;
  for (const segment of pointer.slice(1).split('/')) {
    if (!value || typeof value !== 'object' || !Object.hasOwn(value, segment)) throw new VerificationError('target_version:json_pointer_missing', 'fail', true);
    value = value[segment];
  }
  return value;
}

async function observeVersion(source, expectedVersion, context) {
  const id = `version:${source.id}`;
  try {
    const target = context.targets[source.target];
    const response = await context.performRequest(composeTargetUrl(target, source.path), 'GET', context);
    validateTargetResponse(response, source.target === 'primary' && target.basic_auth);
    if (response.statusCode !== 200) throw new VerificationError('target_version:unexpected_status', 'fail', true);
    let observed;
    if (source.type === 'text_marker') {
      const start = response.body.indexOf(source.prefix);
      if (start < 0) throw new VerificationError('target_version:prefix_missing', 'fail', true);
      const valueStart = start + source.prefix.length;
      const end = response.body.indexOf(source.suffix, valueStart);
      if (end < 0) throw new VerificationError('target_version:suffix_missing', 'fail', true);
      observed = response.body.slice(valueStart, end);
    } else if (source.type === 'json_manifest') {
      let document;
      try { document = JSON.parse(response.body); } catch { throw new VerificationError('target_version:invalid_json_manifest', 'fail', true); }
      observed = jsonPointer(document, source.json_pointer);
    } else {
      const header = source.header_name.toLowerCase();
      if (response.headerCounts.get(header) !== 1) throw new VerificationError('target_version:header_missing_or_repeated', 'fail', true);
      observed = response.headers[header];
    }
    if (typeof observed !== 'string' || observed.length > 64 || !VERSION_PATTERN.test(observed)) throw new VerificationError('target_version:observed_value_invalid', 'fail', true);
    if (observed !== expectedVersion) {
      const failed = failureResult(id, source.required, new VerificationError('target_version:mismatch', 'fail', true));
      return { ...failed, _observed: observed };
    }
    return { id, required: source.required, status: 'pass', code: 'expected_version_observed', fingerprint: null, incident_eligible: false, _observed: observed };
  } catch (error) { return failureResult(id, source.required, error); }
}

async function mapLimited(items, limit, task) {
  const results = new Array(items.length);
  let cursor = 0;
  async function worker() {
    while (cursor < items.length) {
      const index = cursor++;
      results[index] = await task(items[index]);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, Math.max(items.length, 1)) }, worker));
  return results;
}

function classifyAttempt(checks, versions) {
  const results = [...checks, ...versions];
  const requiredVersions = versions.filter((item) => item.required && typeof item._observed === 'string');
  if (new Set(requiredVersions.map((item) => item._observed)).size > 1) {
    results.push(failureResult('version-consistency', true, new VerificationError('target_version:mixed_versions', 'fail', true)));
  }
  const required = results.filter((item) => item.required);
  let status = 'pass';
  if (required.some((item) => item.status === 'fail')) status = 'fail';
  else if (required.some((item) => item.status === 'blocked')) status = 'blocked';
  else if (required.some((item) => item.status === 'not_observable_read_only')) status = 'not_observable_read_only';
  const failures = required.filter((item) => item.status !== 'pass');
  const codes = [...new Set(failures.map((item) => item.code))];
  const code = status === 'pass' ? 'all_required_checks_passed' : codes.length === 1 ? codes[0] : 'multiple_required_failures';
  const incidentFingerprints = [...new Set(failures.filter((item) => item.incident_eligible && item.fingerprint).map((item) => item.fingerprint))].sort();
  return { status, code, incidentFingerprints, results };
}

export function decideAttempts(attempts, limits = DEFAULT_LIMITS) {
  let consecutivePasses = 0;
  for (const attempt of attempts) consecutivePasses = attempt.status === 'pass' ? consecutivePasses + 1 : 0;
  if (consecutivePasses >= limits.consecutive_successes) return { overall: 'pass', code: 'stable_pass', incident: false, incidentFingerprints: [] };
  if (attempts.length === 1 && attempts[0].status === 'not_observable_read_only') {
    return { overall: 'not_observable_read_only', code: 'required_check_not_observable_read_only', incident: false, incidentFingerprints: [] };
  }
  const counts = new Map();
  for (const attempt of attempts) {
    for (const fingerprint of new Set(attempt.incidentFingerprints ?? [])) counts.set(fingerprint, (counts.get(fingerprint) ?? 0) + 1);
  }
  const repeated = [...counts.entries()].filter(([, count]) => count >= limits.incident_repeat_count).map(([value]) => value).sort();
  const statuses = attempts.map((attempt) => attempt.status).join(',');
  if (statuses === 'pass,fail,pass') return { overall: 'fail', code: 'stability_requirement_not_met', incident: false, incidentFingerprints: [] };
  const overall = attempts.some((attempt) => attempt.status === 'fail') ? 'fail' :
    attempts.some((attempt) => attempt.status === 'blocked') ? 'blocked' : 'not_observable_read_only';
  return {
    overall,
    code: repeated.length ? 'repeated_incident_fingerprint' : 'no_repeated_incident_fingerprint',
    incident: repeated.length > 0,
    incidentFingerprints: repeated,
  };
}

function strictEnv(name, pattern) {
  const value = process.env[name] ?? '';
  invariant(pattern.test(value), `input_${name.toLowerCase()}_invalid`);
  return value;
}

function isoTime(value, label) {
  invariant(typeof value === 'string' && !Number.isNaN(Date.parse(value)) && new Date(value).toISOString() === value, `${label}_invalid`);
  return value;
}

function claim(value, source) { return { value, source }; }

function claimsFromEnvironment() {
  const source = strictEnv('CLAIM_SOURCE', /^(manual_operator|deployment_caller)$/u);
  return {
    expected_version: claim(strictEnv('EXPECTED_VERSION', VERSION_PATTERN), source),
    deployment_commit_sha: claim(strictEnv('DEPLOYMENT_COMMIT_SHA', SHA_PATTERN), source),
    release_id: claim(strictEnv('RELEASE_ID', RELEASE_PATTERN), source),
  };
}

function runMetadata(configDigest, provenance) {
  const repository = strictEnv('GITHUB_REPOSITORY', /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u);
  const runId = strictEnv('GITHUB_RUN_ID', RUN_PATTERN);
  return {
    claims: claimsFromEnvironment(),
    observations: { observed_version: null, provenance },
    verifier_commit_sha: strictEnv('VERIFIER_COMMIT_SHA', SHA_PATTERN),
    workflow_sha: strictEnv('WORKFLOW_SHA', SHA_PATTERN),
    repository,
    run_id: runId,
    run_attempt: strictEnv('GITHUB_RUN_ATTEMPT', RUN_PATTERN),
    run_url: `https://github.com/${repository}/actions/runs/${runId}`,
    config_digest: configDigest,
  };
}

function safeValue(name, pattern) {
  const value = process.env[name] ?? '';
  return pattern.test(value) ? value : null;
}

function fallbackMetadata(configDigest = null) {
  const source = CLAIM_SOURCES.has(process.env.CLAIM_SOURCE) ? process.env.CLAIM_SOURCE : 'manual_operator';
  const repository = safeValue('GITHUB_REPOSITORY', /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u);
  const runId = safeValue('GITHUB_RUN_ID', RUN_PATTERN);
  return {
    claims: {
      expected_version: claim(safeValue('EXPECTED_VERSION', VERSION_PATTERN), source),
      deployment_commit_sha: claim(safeValue('DEPLOYMENT_COMMIT_SHA', SHA_PATTERN), source),
      release_id: claim(safeValue('RELEASE_ID', RELEASE_PATTERN), source),
    },
    observations: { observed_version: null, provenance: null },
    verifier_commit_sha: safeValue('VERIFIER_COMMIT_SHA', SHA_PATTERN),
    workflow_sha: safeValue('WORKFLOW_SHA', SHA_PATTERN),
    repository,
    run_id: runId,
    run_attempt: safeValue('GITHUB_RUN_ATTEMPT', RUN_PATTERN),
    run_url: repository && runId ? `https://github.com/${repository}/actions/runs/${runId}` : null,
    config_digest: HEX64_PATTERN.test(configDigest ?? '') ? configDigest : null,
  };
}

function credentialsFor(environment) {
  if (!environment.targets.primary.basic_auth) return null;
  const username = process.env.TARGET_BASIC_AUTH_USERNAME;
  const password = process.env.TARGET_BASIC_AUTH_PASSWORD;
  if (!username || !password || username.length > 256 || password.length > 512) throw new VerificationError('config:target_basic_auth_missing_or_invalid');
  return { username, password };
}

function publicResult(item) {
  return { id: item.id, required: item.required, status: item.status, code: item.code, fingerprint: item.fingerprint ?? null };
}

function stableObservedVersion(attempts, decision, requiredSourceCount, expectedVersion, consecutiveRequired) {
  if (decision.overall !== 'pass' || requiredSourceCount === 0) return null;
  const tail = attempts.slice(-consecutiveRequired);
  const stable = tail.length === consecutiveRequired && tail.every((attempt) =>
    attempt.versionObservations.filter((item) => item.required).length === requiredSourceCount &&
    attempt.versionObservations.filter((item) => item.required).every((item) => item.status === 'pass'));
  return stable ? expectedVersion : null;
}

function sleep(milliseconds) { return new Promise((resolve) => setTimeout(resolve, milliseconds)); }

export async function verify(config, dependencies = {}) {
  const runtimeDependencies = withDefaultTimers(dependencies);
  invariant(config.environment.versionSources.some((source) => source.required), 'required_observable_version_source_missing');
  const now = runtimeDependencies.now ?? Date.now;
  const provenance = runtimeDependencies.provenance ?? parseProvenancePayload(process.env.PROVENANCE_PAYLOAD ?? '');
  const metadata = runMetadata(config.configDigest, provenance);
  const startMs = now();
  const context = {
    targets: config.environment.targets,
    allowedRedirects: config.environment.allowedRedirects,
    auth: credentialsFor(config.environment),
    limits: config.limits,
    totalRequests: 0,
    attemptRequests: 0,
    phaseDeadline: startMs + config.limits.phase_timeout_ms,
    now,
    dependencies: runtimeDependencies,
    performRequest: runtimeDependencies.performRequest ?? boundedRequest,
    resolvePublic: runtimeDependencies.resolvePublic,
    requestOnce: runtimeDependencies.requestOnce,
  };
  const attempts = [];
  for (let number = 1; number <= config.limits.max_attempts; number += 1) {
    context.attemptRequests = 0;
    const checks = await mapLimited(config.environment.checks, config.limits.request_concurrency, (check) => runCheck(check, context));
    const versions = await mapLimited(config.environment.versionSources, config.limits.request_concurrency, (source) => observeVersion(source, metadata.claims.expected_version.value, context));
    const classification = classifyAttempt(checks, versions);
    attempts.push({
      number,
      status: classification.status,
      code: classification.code,
      incidentFingerprints: classification.incidentFingerprints,
      requests: context.attemptRequests,
      checks: classification.results.filter((item) => !item.id.startsWith('version:')).map(publicResult),
      versionObservations: versions.map(publicResult),
    });
    const provisional = decideAttempts(attempts, config.limits);
    if (provisional.overall === 'pass' || provisional.incident || classification.status === 'not_observable_read_only') break;
    if (number < config.limits.max_attempts) {
      if (context.phaseDeadline - now() <= config.limits.evidence_reserve_ms + config.limits.retry_delay_ms) break;
      await (runtimeDependencies.sleep ?? sleep)(config.limits.retry_delay_ms);
    }
  }
  const decision = decideAttempts(attempts, config.limits);
  metadata.observations.observed_version = stableObservedVersion(
    attempts,
    decision,
    config.environment.versionSources.filter((source) => source.required).length,
    metadata.claims.expected_version.value,
    config.limits.consecutive_successes,
  );
  const report = {
    schema_version: 3,
    overall: decision.overall,
    code: decision.code,
    incident: decision.incident,
    incident_fingerprints: decision.incidentFingerprints,
    management_eligible: true,
    environment_digest: environmentDigest(config.selectedEnvironment),
    metadata,
    started_at: new Date(startMs).toISOString(),
    completed_at: new Date(now()).toISOString(),
    budgets: { ...config.limits, requests_used: context.totalRequests },
    attempts,
    scope_notice: 'Public read-only evidence only; no admin, login, migration, database, write behavior, ZIP integrity, lint, secret scan, or human stable-release decision is asserted.',
  };
  emitReport(report, config.limits, runtimeDependencies);
  return report;
}

function blockedReport(error, config, dependencies = {}) {
  const now = dependencies.now ?? Date.now;
  const timestamp = new Date(now()).toISOString();
  const clean = cleanError(error);
  const environmentIdentity = typeof config?.selectedEnvironment === 'string' && SAFE_ENVIRONMENT.test(config.selectedEnvironment) ? environmentDigest(config.selectedEnvironment) : null;
  return {
    schema_version: 3,
    overall: 'blocked',
    code: clean.code,
    incident: false,
    incident_fingerprints: [],
    management_eligible: false,
    environment_digest: environmentIdentity,
    metadata: fallbackMetadata(config?.configDigest),
    started_at: timestamp,
    completed_at: timestamp,
    budgets: { ...(config?.limits ?? DEFAULT_LIMITS), requests_used: 0 },
    attempts: [{ number: 0, status: 'blocked', code: clean.code, incidentFingerprints: [], requests: 0, checks: [{ id: 'verify-setup', required: true, status: 'blocked', code: clean.code, fingerprint: null }], versionObservations: [] }],
    scope_notice: 'Verification setup was blocked before target observation; no target behavior is asserted.',
  };
}

function xmlEscape(value) {
  return String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');
}

function junitXml(report) {
  const cases = report.attempts.flatMap((attempt) => [...attempt.checks, ...attempt.versionObservations].map((item) => ({ attempt: attempt.number, ...item })));
  let failures = 0;
  let errors = 0;
  const elements = cases.map((item) => {
    const name = xmlEscape(`attempt-${item.attempt}:${item.id}`);
    if (item.status === 'pass') return `  <testcase classname="release-verification" name="${name}"/>`;
    const tag = item.status === 'fail' ? 'failure' : 'error';
    if (tag === 'failure') failures += 1; else errors += 1;
    return `  <testcase classname="release-verification" name="${name}"><${tag} message="${xmlEscape(item.code)}"/></testcase>`;
  });
  return `<?xml version="1.0" encoding="UTF-8"?>\n<testsuite name="release-verification" tests="${cases.length}" failures="${failures}" errors="${errors}">\n${elements.join('\n')}\n</testsuite>\n`;
}

function managementPayload(report) {
  return {
    schema_version: 3,
    management_eligible: report.management_eligible,
    environment_digest: report.environment_digest,
    claims: report.metadata.claims,
    observations: report.metadata.observations,
    verifier_commit_sha: report.metadata.verifier_commit_sha,
    workflow_sha: report.metadata.workflow_sha,
    repository: report.metadata.repository,
    run_id: report.metadata.run_id,
    run_attempt: report.metadata.run_attempt,
    run_url: report.metadata.run_url,
    config_digest: report.metadata.config_digest,
    overall: report.overall,
    code: report.code,
    incident: report.incident,
    incident_fingerprints: report.incident_fingerprints,
    completed_at: report.completed_at,
  };
}

function writeGithubOutput(name, value, fileSystem = fs) {
  invariant(/^[a-z_]+$/u.test(name), 'github_output_name_invalid');
  invariant(typeof value === 'string' && !value.includes('\n') && value.length <= 32_768, 'github_output_value_invalid');
  if (process.env.GITHUB_OUTPUT) fileSystem.appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${value}\n`, { encoding: 'utf8' });
}

function appendSummary(markdown, fileSystem = fs) {
  if (process.env.GITHUB_STEP_SUMMARY) fileSystem.appendFileSync(process.env.GITHUB_STEP_SUMMARY, markdown, { encoding: 'utf8' });
}

function pathsEqual(left, right) {
  const normalize = (value) => process.platform === 'win32' ? path.resolve(value).toLowerCase() : path.resolve(value);
  return normalize(left) === normalize(right);
}

function realPath(candidate, fileSystem) {
  const implementation = fileSystem.realpathSync?.native ?? fileSystem.realpathSync;
  invariant(typeof implementation === 'function', 'output_realpath_unavailable');
  return implementation(candidate);
}

function nearestExistingAncestor(candidate, fileSystem) {
  let current = candidate;
  while (!fileSystem.existsSync(current)) {
    const parent = path.dirname(current);
    invariant(parent !== current, 'output_existing_ancestor_missing');
    current = parent;
  }
  return current;
}

function filesystemPathWithin(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

function absoluteControlPath(value, label) {
  invariant(typeof value === 'string' && value.length > 0 && value.length <= 4_096, `${label}_missing_or_invalid`);
  invariant(path.isAbsolute(value), `${label}_must_be_absolute`);
  invariant(!value.split(/[\\/]+/u).includes('..'), `${label}_traversal_forbidden`);
  return path.resolve(value);
}

function regularNonLink(candidate, fileSystem, label) {
  const status = fileSystem.lstatSync(candidate);
  invariant(status.isFile() && !status.isSymbolicLink(), `${label}_type_forbidden`);
}

function directoryNonLink(candidate, fileSystem, label) {
  const status = fileSystem.lstatSync(candidate);
  invariant(status.isDirectory() && !status.isSymbolicLink(), `${label}_type_forbidden`);
}

function resolvedRuntimePaths(environment, fileSystem, trustedTemporaryRoot = undefined) {
  const temporaryRoot = absoluteControlPath(environment.VERIFICATION_TEMP_ROOT, 'resolved_temp_root');
  const authorityRoot = absoluteControlPath(trustedTemporaryRoot ?? environment.RUNNER_TEMP, 'trusted_temp_root');
  const resolvedFile = absoluteControlPath(environment.VERIFICATION_CONFIG, 'resolved_config_path');
  const expectedDirectory = path.join(temporaryRoot, RESOLVED_CONFIG_DIRECTORY_NAME);
  const expectedFile = path.join(expectedDirectory, RESOLVED_CONFIG_FILE_NAME);
  invariant(pathsEqual(resolvedFile, expectedFile), 'resolved_config_path_outside_fixed_contract');
  invariant(!pathsEqual(expectedFile, COMMITTED_TEMPLATE_PATH), 'resolved_config_must_differ_from_template');

  directoryNonLink(temporaryRoot, fileSystem, 'resolved_temp_root');
  directoryNonLink(authorityRoot, fileSystem, 'trusted_temp_root');
  const canonicalRoot = realPath(temporaryRoot, fileSystem);
  const canonicalAuthorityRoot = realPath(authorityRoot, fileSystem);
  invariant(pathsEqual(canonicalRoot, canonicalAuthorityRoot), 'resolved_temp_root_authority_mismatch');
  const canonicalRepository = realPath(REPOSITORY_ROOT, fileSystem);
  invariant(!filesystemPathWithin(canonicalRepository, canonicalRoot), 'resolved_temp_root_inside_repository');
  invariant(!filesystemPathWithin(canonicalRoot, canonicalRepository), 'resolved_temp_root_contains_repository');

  const ancestor = nearestExistingAncestor(expectedDirectory, fileSystem);
  const projectedDirectory = path.resolve(realPath(ancestor, fileSystem), path.relative(ancestor, expectedDirectory));
  const canonicalExpectedDirectory = path.join(canonicalRoot, RESOLVED_CONFIG_DIRECTORY_NAME);
  invariant(pathsEqual(projectedDirectory, canonicalExpectedDirectory), 'resolved_directory_ancestor_escape');
  return { temporaryRoot, canonicalRoot, expectedDirectory, canonicalExpectedDirectory, expectedFile };
}

function committedTemplatePath(environment, fileSystem) {
  const candidate = absoluteControlPath(environment.VERIFICATION_CONFIG_TEMPLATE, 'config_template_path');
  invariant(pathsEqual(candidate, COMMITTED_TEMPLATE_PATH), 'config_template_path_outside_contract');
  regularNonLink(candidate, fileSystem, 'config_template');
  invariant(pathsEqual(realPath(candidate, fileSystem), realPath(COMMITTED_TEMPLATE_PATH, fileSystem)), 'config_template_path_escape');
  return candidate;
}

function removePartialResolvedOutput(paths, fileSystem) {
  if (fileSystem.existsSync(paths.expectedFile)) {
    regularNonLink(paths.expectedFile, fileSystem, 'partial_resolved_config');
    invariant(pathsEqual(realPath(paths.expectedFile, fileSystem), path.join(paths.canonicalExpectedDirectory, RESOLVED_CONFIG_FILE_NAME)), 'partial_resolved_config_escape');
    fileSystem.unlinkSync(paths.expectedFile);
  }
  if (fileSystem.existsSync(paths.expectedDirectory)) {
    directoryNonLink(paths.expectedDirectory, fileSystem, 'partial_resolved_directory');
    invariant(pathsEqual(realPath(paths.expectedDirectory, fileSystem), paths.canonicalExpectedDirectory), 'partial_resolved_directory_escape');
    invariant(fileSystem.readdirSync(paths.expectedDirectory).length === 0, 'partial_resolved_directory_not_empty');
    fileSystem.rmdirSync(paths.expectedDirectory);
  }
}

export function createResolvedConfigOutput(resolved, environment = process.env, dependencies = {}) {
  const fileSystem = dependencies.fs ?? fs;
  const environmentNames = Object.keys(resolved?.environments ?? {});
  invariant(environmentNames.length === 1, 'resolved_output_environment_count_invalid');
  invariant(environmentNames[0] === environmentDigest(environment.TARGET_ENVIRONMENT), 'resolved_output_environment_control_mismatch');
  validateResolvedConfig(resolved, environmentNames[0]);
  const content = `${JSON.stringify(resolved, null, 2)}\n`;
  invariant(Buffer.byteLength(content) <= 131_072, 'resolved_output_too_large');
  const paths = resolvedRuntimePaths(environment, fileSystem, dependencies.trustedTemporaryRoot);
  invariant(!fileSystem.existsSync(paths.expectedDirectory), 'resolved_directory_already_exists');

  let descriptor;
  let directoryCreated = false;
  try {
    fileSystem.mkdirSync(paths.expectedDirectory, { recursive: false, mode: 0o700 });
    directoryCreated = true;
    directoryNonLink(paths.expectedDirectory, fileSystem, 'resolved_directory');
    invariant(pathsEqual(realPath(paths.expectedDirectory, fileSystem), paths.canonicalExpectedDirectory), 'resolved_directory_escape');

    const fileAncestor = nearestExistingAncestor(paths.expectedFile, fileSystem);
    const projectedFile = path.resolve(realPath(fileAncestor, fileSystem), path.relative(fileAncestor, paths.expectedFile));
    invariant(pathsEqual(projectedFile, path.join(paths.canonicalExpectedDirectory, RESOLVED_CONFIG_FILE_NAME)), 'resolved_file_ancestor_escape');
    descriptor = fileSystem.openSync(paths.expectedFile, 'wx', 0o600);
    regularNonLink(paths.expectedFile, fileSystem, 'resolved_config');
    invariant(pathsEqual(realPath(paths.expectedFile, fileSystem), path.join(paths.canonicalExpectedDirectory, RESOLVED_CONFIG_FILE_NAME)), 'resolved_config_escape');
    fileSystem.writeFileSync(descriptor, content, { encoding: 'utf8' });
    fileSystem.closeSync(descriptor);
    descriptor = undefined;
    if (typeof fileSystem.chmodSync === 'function') {
      fileSystem.chmodSync(paths.expectedDirectory, 0o700);
      fileSystem.chmodSync(paths.expectedFile, 0o600);
    }
    return paths.expectedFile;
  } catch (error) {
    if (descriptor !== undefined) {
      try { fileSystem.closeSync(descriptor); } catch { /* preserve the original sanitized failure */ }
    }
    if (directoryCreated) removePartialResolvedOutput(paths, fileSystem);
    throw error;
  }
}

export function cleanupResolvedConfigOutput(environment = process.env, dependencies = {}) {
  const fileSystem = dependencies.fs ?? fs;
  const paths = resolvedRuntimePaths(environment, fileSystem, dependencies.trustedTemporaryRoot);
  if (!fileSystem.existsSync(paths.expectedDirectory)) return 'absent';
  directoryNonLink(paths.expectedDirectory, fileSystem, 'resolved_cleanup_directory');
  invariant(pathsEqual(realPath(paths.expectedDirectory, fileSystem), paths.canonicalExpectedDirectory), 'resolved_cleanup_directory_escape');
  const entries = fileSystem.readdirSync(paths.expectedDirectory);
  invariant(entries.length <= 1 && entries.every((name) => name === RESOLVED_CONFIG_FILE_NAME), 'resolved_cleanup_unexpected_object');
  if (entries.length === 1) {
    regularNonLink(paths.expectedFile, fileSystem, 'resolved_cleanup_file');
    invariant(pathsEqual(realPath(paths.expectedFile, fileSystem), path.join(paths.canonicalExpectedDirectory, RESOLVED_CONFIG_FILE_NAME)), 'resolved_cleanup_file_escape');
    fileSystem.unlinkSync(paths.expectedFile);
  }
  invariant(fileSystem.readdirSync(paths.expectedDirectory).length === 0, 'resolved_cleanup_directory_not_empty');
  fileSystem.rmdirSync(paths.expectedDirectory);
  return 'removed';
}

export function resolveConfigTemplate(environment = process.env, dependencies = {}) {
  const fileSystem = dependencies.fs ?? fs;
  const templatePath = committedTemplatePath(environment, fileSystem);
  const template = parseJsonDocument(fileSystem.readFileSync(templatePath), 'config_template');
  const resolved = resolveConfigBindings(template, environment);
  createResolvedConfigOutput(resolved, environment, dependencies);
  return resolved;
}

function explicitResolvedConfigPath(environment, fileSystem, trustedTemporaryRoot = undefined) {
  const paths = resolvedRuntimePaths(environment, fileSystem, trustedTemporaryRoot);
  invariant(fileSystem.existsSync(paths.expectedDirectory), 'resolved_directory_missing');
  directoryNonLink(paths.expectedDirectory, fileSystem, 'resolved_directory');
  invariant(pathsEqual(realPath(paths.expectedDirectory, fileSystem), paths.canonicalExpectedDirectory), 'resolved_directory_escape');
  regularNonLink(paths.expectedFile, fileSystem, 'resolved_config');
  invariant(pathsEqual(realPath(paths.expectedFile, fileSystem), path.join(paths.canonicalExpectedDirectory, RESOLVED_CONFIG_FILE_NAME)), 'resolved_config_escape');
  return paths.expectedFile;
}

function resolveOutputDirectory(fileSystem) {
  const workingDirectory = path.resolve(process.cwd());
  const directory = path.resolve(workingDirectory, OUTPUT_DIRECTORY_NAME);
  const override = process.env.OUTPUT_DIR;
  if (override !== undefined) {
    invariant(override.length > 0 && !path.isAbsolute(override), 'output_override_must_be_relative');
    invariant(!override.split(/[\\/]+/u).includes('..'), 'output_traversal_forbidden');
    invariant(pathsEqual(path.resolve(workingDirectory, override), directory), 'output_override_outside_contract');
  }

  const canonicalWorkingDirectory = realPath(workingDirectory, fileSystem);
  const ancestor = nearestExistingAncestor(directory, fileSystem);
  const projectedDirectory = path.resolve(realPath(ancestor, fileSystem), path.relative(ancestor, directory));
  const expectedCanonicalDirectory = path.resolve(canonicalWorkingDirectory, OUTPUT_DIRECTORY_NAME);
  invariant(pathsEqual(projectedDirectory, expectedCanonicalDirectory), 'output_ancestor_escape');

  fileSystem.mkdirSync(directory, { recursive: true });
  const canonicalDirectory = realPath(directory, fileSystem);
  invariant(pathsEqual(canonicalDirectory, expectedCanonicalDirectory), 'output_directory_escape');
  return { directory, canonicalDirectory };
}

function prepareOutputFile(directory, canonicalDirectory, name, fileSystem) {
  invariant(OUTPUT_FILE_NAMES.includes(name), 'output_file_not_allowed');
  const candidate = path.join(directory, name);
  const ancestor = nearestExistingAncestor(candidate, fileSystem);
  const projectedCandidate = path.resolve(realPath(ancestor, fileSystem), path.relative(ancestor, candidate));
  invariant(pathsEqual(path.dirname(projectedCandidate), canonicalDirectory), 'output_file_ancestor_escape');

  if (!fileSystem.existsSync(candidate)) {
    const descriptor = fileSystem.openSync(candidate, 'wx', 0o600);
    fileSystem.closeSync(descriptor);
  }
  const status = fileSystem.lstatSync(candidate);
  invariant(status.isFile() && !status.isSymbolicLink(), 'output_file_type_forbidden');
  const canonicalCandidate = realPath(candidate, fileSystem);
  invariant(pathsEqual(path.dirname(canonicalCandidate), canonicalDirectory), 'output_file_escape');
  return candidate;
}

function outputFiles(report, limits, dependencies = {}) {
  const fileSystem = dependencies.fs ?? fs;
  const reportJson = `${JSON.stringify(report, null, 2)}\n`;
  const junit = junitXml(report);
  invariant(Buffer.byteLength(reportJson) + Buffer.byteLength(junit) <= limits.max_artifact_bytes, 'artifact_size_limit_exceeded');
  const { directory, canonicalDirectory } = resolveOutputDirectory(fileSystem);
  const reportPath = prepareOutputFile(directory, canonicalDirectory, 'report.json', fileSystem);
  const junitPath = prepareOutputFile(directory, canonicalDirectory, 'junit.xml', fileSystem);
  fileSystem.writeFileSync(reportPath, reportJson, { encoding: 'utf8', mode: 0o600 });
  fileSystem.writeFileSync(junitPath, junit, { encoding: 'utf8', mode: 0o600 });
}

function emitReport(report, limits, dependencies = {}) {
  outputFiles(report, limits, dependencies);
  const encoded = Buffer.from(JSON.stringify(managementPayload(report)), 'utf8').toString('base64url');
  writeGithubOutput('overall', report.overall, dependencies.fs ?? fs);
  writeGithubOutput('management_payload', encoded, dependencies.fs ?? fs);
  const observed = report.metadata.observations.observed_version ?? 'not observed';
  const environmentIdentity = report.environment_digest ?? 'unavailable';
  appendSummary(`## Release verification: ${report.overall}\n\nEnvironment digest: \`${environmentIdentity}\`  \nClaimed version: \`${report.metadata.claims.expected_version.value ?? 'invalid'}\` (${report.metadata.claims.expected_version.source})  \nObserved stable version: \`${observed}\`  \nAttempts: ${report.attempts.length}  \nRequests: ${report.budgets.requests_used}/${report.budgets.max_total_requests}\n\nNo response bodies, raw headers, query strings, cookies, credentials, stack traces, or client data are included.\n`, dependencies.fs ?? fs);
}

export async function runVerifyMode(dependencies = {}) {
  let config;
  try {
    const fileSystem = dependencies.fs ?? fs;
    const configPath = explicitResolvedConfigPath(process.env, fileSystem, dependencies.trustedTemporaryRoot);
    config = (dependencies.loadConfig ?? loadConfig)(configPath, process.env.TARGET_ENVIRONMENT ?? '', fileSystem);
    return await verify(config, dependencies);
  } catch (error) {
    const report = blockedReport(error, config, dependencies);
    emitReport(report, config?.limits ?? DEFAULT_LIMITS, dependencies);
    return report;
  }
}

function selectedRateHeaders(headers) {
  const selected = {};
  for (const name of ['retry-after', 'x-ratelimit-remaining', 'x-ratelimit-reset', 'x-ratelimit-resource']) {
    const value = headers?.[name];
    if (typeof value === 'string' && value.length <= 128 && /^[A-Za-z0-9 ._:-]+$/u.test(value)) selected[name] = value;
  }
  return selected;
}

export function githubRequest(method, endpoint, body = undefined, dependencies = {}) {
  const token = process.env.GITHUB_TOKEN;
  if (!token) return Promise.reject(new VerificationError('github_control:token_missing'));
  invariant(['GET', 'POST', 'PATCH'].includes(method), 'github_method_invalid');
  const url = new URL(endpoint, 'https://api.github.com');
  invariant(url.origin === 'https://api.github.com' && !url.username && !url.password, 'github_endpoint_invalid');
  const payload = body === undefined ? null : Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const request = (dependencies.httpsRequest ?? https.request)(url, {
      method,
      headers: {
        accept: 'application/vnd.github+json',
        authorization: `Bearer ${token}`,
        'user-agent': 'time-bounded-read-only-release-verifier/2',
        'x-github-api-version': '2022-11-28',
        ...(payload ? { 'content-type': 'application/json', 'content-length': String(payload.length) } : {}),
      },
      timeout: 10_000,
      maxHeaderSize: 32_768,
    });
    request.once('response', async (response) => {
      let text = '';
      try {
        for await (const chunk of response) {
          text += chunk;
          if (text.length > 262_144) throw new VerificationError('github_control:response_too_large');
        }
        let parsed = null;
        if (text) { try { parsed = JSON.parse(text); } catch { /* status is still authoritative */ } }
        resolve({ status: response.statusCode ?? 0, body: parsed, headers: selectedRateHeaders(response.headers) });
      } catch (error) { response.destroy(); request.destroy(); reject(cleanError(error)); }
    });
    request.once('timeout', () => request.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })));
    request.once('error', () => reject(new VerificationError('github_control:network_error')));
    if (payload) request.write(payload);
    request.end();
  });
}

function githubFailure(response, scope) {
  if (response.status === 429 || response.headers?.['retry-after'] || response.headers?.['x-ratelimit-remaining'] === '0') {
    return new VerificationError(`github_control:${scope}_rate_limit`);
  }
  if ([401, 403].includes(response.status)) return new VerificationError(`github_control:${scope}_permission_denied`);
  if (response.status >= 500) return new VerificationError(`github_control:${scope}_api_error`);
  return new VerificationError(`github_control:${scope}_unexpected_response`);
}

function validateInvocation() {
  const event = process.env.GITHUB_EVENT_NAME ?? '';
  if (['pull_request', 'pull_request_target'].includes(event)) throw new VerificationError('github_control:untrusted_pr_event_forbidden');
  invariant(['dispatch', 'call'].includes(process.env.INVOCATION_KIND), 'invocation_kind_invalid');
  if (process.env.INVOCATION_KIND === 'dispatch') invariant(process.env.MANUAL_INSTALL_CONFIRMED === 'true', 'manual_install_not_confirmed');
  else invariant(process.env.DEPLOYMENT_CONCLUSION === 'success', 'deployment_not_successful');
}

function expectedAssetName(template, version) { return template.replace('{version}', version); }

async function resolveTagCommit(repository, tag, request) {
  let response = await request('GET', `/repos/${repository}/git/ref/tags/${encodeURIComponent(tag)}`);
  if (response.status !== 200) throw githubFailure(response, 'tag_ref');
  let object = response.body?.object;
  invariant(object && ['commit', 'tag'].includes(object.type) && SHA_PATTERN.test(object.sha), 'provenance_tag_object_invalid');
  for (let depth = 0; object.type === 'tag' && depth < 4; depth += 1) {
    response = await request('GET', `/repos/${repository}/git/tags/${object.sha}`);
    if (response.status !== 200) throw githubFailure(response, 'annotated_tag');
    object = response.body?.object;
    invariant(object && ['commit', 'tag'].includes(object.type) && SHA_PATTERN.test(object.sha), 'provenance_annotated_tag_invalid');
  }
  invariant(object.type === 'commit', 'provenance_tag_chain_too_deep');
  return object.sha;
}

async function observeProvenance(config, metadata, request) {
  if (config.provenance.mode === 'claims_only') {
    return { mode: 'claims_only', status: 'owner_assertion', github_release_id: null, release_tag_commit_sha: null, asset: null };
  }
  const repository = metadata.repository;
  const tag = metadata.claims.release_id.value;
  const releaseResponse = await request('GET', `/repos/${repository}/releases/tags/${encodeURIComponent(tag)}`);
  if (releaseResponse.status !== 200) throw githubFailure(releaseResponse, 'release');
  const release = releaseResponse.body;
  invariant(release && String(release.tag_name) === tag && release.draft === false && typeof release.prerelease === 'boolean', 'provenance_release_contract_invalid');
  invariant(Number.isInteger(release.id) && release.id > 0 && Array.isArray(release.assets), 'provenance_release_shape_invalid');
  const assetName = expectedAssetName(config.provenance.release_asset_name, metadata.claims.expected_version.value);
  const matches = release.assets.filter((asset) => asset?.name === assetName);
  invariant(matches.length === 1, 'provenance_release_asset_missing_or_duplicate');
  const asset = matches[0];
  invariant(Number.isInteger(asset.id) && asset.id > 0 && Number.isInteger(asset.size) && asset.size >= 0, 'provenance_release_asset_invalid');
  const tagCommit = await resolveTagCommit(repository, tag, request);
  invariant(tagCommit === metadata.claims.deployment_commit_sha.value, 'provenance_deployment_commit_mismatch');
  invariant(typeof asset.digest === 'string' && RELEASE_ASSET_DIGEST_PATTERN.test(asset.digest), 'provenance_asset_digest_invalid');
  return {
    mode: 'github_release_required',
    status: 'verified',
    github_release_id: String(release.id),
    release_tag_commit_sha: tagCommit,
    asset: { id: String(asset.id), name: assetName, size: asset.size, digest: asset.digest },
  };
}

function encodeProvenancePayload(provenance) { return Buffer.from(JSON.stringify(provenance), 'utf8').toString('base64url'); }

function validateProvenance(provenance) {
  exactKeys(provenance, ['mode', 'status', 'github_release_id', 'release_tag_commit_sha', 'asset'], 'provenance_observation');
  invariant(PROVENANCE_MODES.has(provenance.mode), 'provenance_observation_mode_invalid');
  if (provenance.mode === 'claims_only') {
    invariant(provenance.status === 'owner_assertion' && provenance.github_release_id === null && provenance.release_tag_commit_sha === null && provenance.asset === null, 'provenance_claims_only_invalid');
  } else {
    invariant(provenance.status === 'verified' && RUN_PATTERN.test(provenance.github_release_id) && SHA_PATTERN.test(provenance.release_tag_commit_sha), 'provenance_verified_identity_invalid');
    exactKeys(provenance.asset, ['id', 'name', 'size', 'digest'], 'provenance_asset');
    invariant(RUN_PATTERN.test(provenance.asset.id) && /^[A-Za-z0-9._+-]+\.zip$/u.test(provenance.asset.name), 'provenance_asset_identity_invalid');
    invariant(Number.isInteger(provenance.asset.size) && provenance.asset.size >= 0, 'provenance_asset_size_invalid');
    invariant(typeof provenance.asset.digest === 'string' && RELEASE_ASSET_DIGEST_PATTERN.test(provenance.asset.digest), 'provenance_asset_digest_invalid');
  }
  return provenance;
}

function parseProvenancePayload(encoded) {
  invariant(/^[A-Za-z0-9_-]{1,8192}$/u.test(encoded), 'provenance_payload_invalid');
  let provenance;
  try { provenance = parseJsonDocument(Buffer.from(encoded, 'base64url'), 'provenance_payload'); } catch { throw new VerificationError('config:provenance_payload_invalid'); }
  return validateProvenance(provenance);
}

export async function preflight(config, request = githubRequest) {
  validateInvocation();
  const metadata = runMetadata(config.configDigest, { mode: 'claims_only', status: 'owner_assertion', github_release_id: null, release_tag_commit_sha: null, asset: null });
  const repositoryResponse = await request('GET', `/repos/${metadata.repository}`);
  if (repositoryResponse.status !== 200) throw githubFailure(repositoryResponse, 'repository');
  invariant(repositoryResponse.body?.visibility === 'public' && repositoryResponse.body?.private === false, 'repository_must_be_public');
  const environmentResponse = await request('GET', `/repos/${metadata.repository}/environments/${encodeURIComponent(config.selectedEnvironment)}`);
  if (environmentResponse.status === 404) throw new VerificationError('github_control:environment_not_found_or_inaccessible');
  if (environmentResponse.status !== 200) throw githubFailure(environmentResponse, 'environment');
  const provenance = await observeProvenance(config, metadata, request);
  return { provenance, basicAuthRequired: config.basicAuthRequired, environment_digest: environmentDigest(config.selectedEnvironment) };
}

function validateClaimObject(object, label, pattern) {
  exactKeys(object, ['value', 'source'], label);
  invariant(typeof object.value === 'string' && pattern.test(object.value), `${label}_value_invalid`);
  invariant(CLAIM_SOURCES.has(object.source), `${label}_source_invalid`);
  return object;
}

export function parseManagementPayload(encoded = process.env.MANAGEMENT_PAYLOAD ?? '') {
  invariant(/^[A-Za-z0-9_-]{1,32768}$/u.test(encoded), 'management_payload_invalid');
  let payload;
  try { payload = parseJsonDocument(Buffer.from(encoded, 'base64url'), 'management_payload'); } catch { throw new VerificationError('config:management_payload_invalid'); }
  exactKeys(payload, ['schema_version', 'management_eligible', 'environment_digest', 'claims', 'observations', 'verifier_commit_sha', 'workflow_sha', 'repository', 'run_id', 'run_attempt', 'run_url', 'config_digest', 'overall', 'code', 'incident', 'incident_fingerprints', 'completed_at'], 'management_payload');
  invariant(payload.schema_version === 3 && typeof payload.management_eligible === 'boolean', 'management_payload_schema_invalid');
  if (!payload.management_eligible) {
    invariant(payload.environment_digest === null || (typeof payload.environment_digest === 'string' && HEX64_PATTERN.test(payload.environment_digest)), 'management_ineligible_environment_digest_invalid');
    exactKeys(payload.claims, ['expected_version', 'deployment_commit_sha', 'release_id'], 'management_ineligible_claims');
    for (const [name, pattern] of [['expected_version', VERSION_PATTERN], ['deployment_commit_sha', SHA_PATTERN], ['release_id', RELEASE_PATTERN]]) {
      const item = payload.claims[name];
      exactKeys(item, ['value', 'source'], `management_ineligible_${name}_claim`);
      invariant(item.value === null || (typeof item.value === 'string' && pattern.test(item.value)), `management_ineligible_${name}_value_invalid`);
      invariant(CLAIM_SOURCES.has(item.source), `management_ineligible_${name}_source_invalid`);
    }
    exactKeys(payload.observations, ['observed_version', 'provenance'], 'management_ineligible_observations');
    invariant(payload.observations.observed_version === null && payload.observations.provenance === null, 'management_ineligible_observations_invalid');
    invariant(payload.verifier_commit_sha === null || SHA_PATTERN.test(payload.verifier_commit_sha), 'management_ineligible_verifier_sha_invalid');
    invariant(payload.workflow_sha === null || SHA_PATTERN.test(payload.workflow_sha), 'management_ineligible_workflow_sha_invalid');
    invariant(payload.repository === null || /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(payload.repository), 'management_ineligible_repository_invalid');
    invariant(payload.run_id === null || RUN_PATTERN.test(payload.run_id), 'management_ineligible_run_id_invalid');
    invariant(payload.run_attempt === null || RUN_PATTERN.test(payload.run_attempt), 'management_ineligible_run_attempt_invalid');
    const expectedRunUrl = payload.repository && payload.run_id ? `https://github.com/${payload.repository}/actions/runs/${payload.run_id}` : null;
    invariant(payload.run_url === expectedRunUrl, 'management_ineligible_run_url_mismatch');
    invariant(payload.config_digest === null || HEX64_PATTERN.test(payload.config_digest), 'management_ineligible_config_digest_invalid');
    invariant(payload.overall === 'blocked' && CODE_PATTERN.test(payload.code), 'management_ineligible_result_invalid');
    invariant(payload.incident === false && Array.isArray(payload.incident_fingerprints) && payload.incident_fingerprints.length === 0, 'management_ineligible_incident_forbidden');
    isoTime(payload.completed_at, 'management_ineligible_completed_at');
    return payload;
  }
  invariant(typeof payload.environment_digest === 'string' && HEX64_PATTERN.test(payload.environment_digest), 'management_environment_digest_invalid');
  exactKeys(payload.claims, ['expected_version', 'deployment_commit_sha', 'release_id'], 'management_claims');
  validateClaimObject(payload.claims.expected_version, 'management_expected_version_claim', VERSION_PATTERN);
  validateClaimObject(payload.claims.deployment_commit_sha, 'management_deployment_sha_claim', SHA_PATTERN);
  validateClaimObject(payload.claims.release_id, 'management_release_id_claim', RELEASE_PATTERN);
  exactKeys(payload.observations, ['observed_version', 'provenance'], 'management_observations');
  invariant(payload.observations.observed_version === null || VERSION_PATTERN.test(payload.observations.observed_version), 'management_observed_version_invalid');
  validateProvenance(payload.observations.provenance);
  invariant(SHA_PATTERN.test(payload.verifier_commit_sha) && SHA_PATTERN.test(payload.workflow_sha), 'management_workflow_identity_invalid');
  invariant(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(payload.repository), 'management_repository_invalid');
  invariant(RUN_PATTERN.test(payload.run_id) && RUN_PATTERN.test(payload.run_attempt), 'management_run_identity_invalid');
  invariant(payload.run_url === `https://github.com/${payload.repository}/actions/runs/${payload.run_id}`, 'management_run_url_mismatch');
  invariant(HEX64_PATTERN.test(payload.config_digest), 'management_config_digest_invalid');
  invariant(['pass', 'fail', 'blocked', 'not_observable_read_only'].includes(payload.overall) && CODE_PATTERN.test(payload.code), 'management_result_invalid');
  invariant(typeof payload.incident === 'boolean' && Array.isArray(payload.incident_fingerprints) && payload.incident_fingerprints.length <= 16, 'management_incident_shape_invalid');
  invariant(payload.incident_fingerprints.every((value) => /^[0-9a-f]{24}$/u.test(value)) && new Set(payload.incident_fingerprints).size === payload.incident_fingerprints.length, 'management_incident_fingerprints_invalid');
  isoTime(payload.completed_at, 'management_completed_at');
  if (payload.overall === 'pass') invariant(!payload.incident && payload.incident_fingerprints.length === 0 && payload.code === 'stable_pass', 'management_pass_inconsistent');
  if (payload.incident) invariant(['fail', 'blocked'].includes(payload.overall) && payload.incident_fingerprints.length > 0, 'management_incident_inconsistent');
  else invariant(payload.incident_fingerprints.length === 0, 'management_nonincident_fingerprint_forbidden');
  if (payload.overall === 'not_observable_read_only') invariant(!payload.incident, 'management_not_observable_incident_forbidden');
  return payload;
}

function issueGroupIdentity(environmentDigestValue, version) { return digest(`${environmentDigestValue}\0${version}`, 32); }
function issueIdentity(environmentDigestValue, version, fingerprint) { return digest(`${environmentDigestValue}\0${version}\0${fingerprint}`, 32); }
function groupMarker(payload) { return `<!-- release-verification-group:${issueGroupIdentity(payload.environment_digest, payload.claims.expected_version.value)} -->`; }
function issueMarker(payload, fingerprint) { return `<!-- release-verification:${issueIdentity(payload.environment_digest, payload.claims.expected_version.value, fingerprint)} -->`; }

function issueRecord(payload, fingerprint) {
  const record = { ...payload, current_fingerprint: fingerprint };
  return `<!-- release-verification-record:${Buffer.from(JSON.stringify(record), 'utf8').toString('base64url')} -->`;
}

function parseIssueRecord(body) {
  const match = typeof body === 'string' ? body.match(/<!-- release-verification-record:([A-Za-z0-9_-]{1,32768}) -->/u) : null;
  if (!match) return null;
  try {
    const record = parseJsonDocument(Buffer.from(match[1], 'base64url'), 'issue_record');
    const fingerprint = record.current_fingerprint;
    delete record.current_fingerprint;
    const payload = parseManagementPayload(Buffer.from(JSON.stringify(record), 'utf8').toString('base64url'));
    invariant(/^[0-9a-f]{24}$/u.test(fingerprint), 'issue_record_fingerprint_invalid');
    return { payload, fingerprint };
  } catch { return null; }
}

function trustedAutomationIssue(issue) {
  return issue?.user?.login === 'github-actions[bot]' && (issue.user.type === undefined || issue.user.type === 'Bot');
}

function compareOrder(candidate, previous) {
  const run = BigInt(candidate.run_id) - BigInt(previous.run_id);
  if (run !== 0n) return run > 0n ? 1 : -1;
  const attempt = BigInt(candidate.run_attempt) - BigInt(previous.run_attempt);
  if (attempt !== 0n) return attempt > 0n ? 1 : -1;
  return Date.parse(candidate.completed_at) === Date.parse(previous.completed_at) ? 0 : Date.parse(candidate.completed_at) > Date.parse(previous.completed_at) ? 1 : -1;
}

function stableSemver(value) {
  const match = value.match(/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/u);
  return match ? match.slice(1).map(BigInt) : null;
}

function newerStableVersion(candidate, previous) {
  const next = stableSemver(candidate);
  const old = stableSemver(previous);
  if (!next || !old) return false;
  for (let index = 0; index < 3; index += 1) {
    if (next[index] > old[index]) return true;
    if (next[index] < old[index]) return false;
  }
  return false;
}

function issueTitle(payload, fingerprint) {
  return `[Release verification] ${payload.environment_digest} ${payload.claims.expected_version.value} ${fingerprint}`;
}

function issueBody(payload, fingerprint) {
  const observed = payload.observations.observed_version ?? 'not observed';
  const provenance = payload.observations.provenance.status;
  return `${issueMarker(payload, fingerprint)}\n${groupMarker(payload)}\n${issueRecord(payload, fingerprint)}\nTime-bounded public read-only release verification detected a repeated incident.\n\n### Claims\n\n- Expected version: \`${payload.claims.expected_version.value}\` (${payload.claims.expected_version.source})\n- Deployment commit: \`${payload.claims.deployment_commit_sha.value}\` (${payload.claims.deployment_commit_sha.source})\n- Release identifier: \`${payload.claims.release_id.value}\` (${payload.claims.release_id.source})\n\n### Observations\n\n- Environment digest: \`${payload.environment_digest}\`\n- Stable observed version: \`${observed}\`\n- Provenance status: \`${provenance}\`\n- Classification: \`${payload.overall}:${payload.code}\`\n- Check fingerprint: \`${fingerprint}\`\n- Verifier commit: \`${payload.verifier_commit_sha}\`\n- Workflow commit: \`${payload.workflow_sha}\`\n- Config digest: \`${payload.config_digest}\`\n- Run: ${payload.run_url} (attempt ${payload.run_attempt})\n- Completed: \`${payload.completed_at}\`\n\nNo response body, raw header, query string, cookie, credential, stack trace, or client data is included.\n`;
}

function recoveryBody(record, recovery) {
  return `${issueRecord(recovery, record.fingerprint)}\n${issueBody(record.payload, record.fingerprint)}\n### Recovery\n\nObserved stable recovery in ${recovery.run_url} (attempt ${recovery.run_attempt}) at \`${recovery.completed_at}\`. The original incident evidence above is preserved.\n`;
}

async function searchIssues(payload, scope, request) {
  const version = scope === 'all_versions' ? '' : ` ${payload.claims.expected_version.value}`;
  const query = `repo:${payload.repository} is:issue author:app/github-actions in:title "[Release verification] ${payload.environment_digest}${version}"`;
  const found = [];
  for (let page = 1; page <= 2; page += 1) {
    const endpoint = `/search/issues?q=${encodeURIComponent(query)}&per_page=100&page=${page}&sort=updated&order=desc`;
    const response = await request('GET', endpoint);
    if (response.status !== 200 || !Array.isArray(response.body?.items)) throw githubFailure(response, 'issue_search');
    for (const issue of response.body.items) {
      if (issue.pull_request || !trustedAutomationIssue(issue)) continue;
      if (found.length >= 120) throw new VerificationError('github_control:trusted_issue_search_limit');
      found.push(issue);
    }
    if (response.body.items.length < 100) break;
  }
  return found;
}

export async function manageIssue(payload = parseManagementPayload(), request = githubRequest) {
  payload = parseManagementPayload(Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url'));
  if (!payload.management_eligible) return 'no_issue';
  if (payload.overall !== 'pass' && !payload.incident) return 'no_issue';
  const issues = await searchIssues(payload, 'version', request);
  const group = groupMarker(payload);
  const records = issues.filter(trustedAutomationIssue).map((issue) => ({ issue, record: parseIssueRecord(issue.body) })).filter((entry) =>
    entry.record && entry.record.payload.environment_digest === payload.environment_digest && entry.issue.body.includes(group));
  if (payload.overall === 'pass') {
    for (const { issue, record } of records) {
      if (issue.state === 'closed' || compareOrder(payload, record.payload) <= 0) continue;
      const response = await request('PATCH', `/repos/${payload.repository}/issues/${issue.number}`, { state: 'closed', state_reason: 'completed', body: recoveryBody(record, payload) });
      if (response.status !== 200) throw githubFailure(response, 'issue_recovery');
    }
    if (payload.observations.observed_version === payload.claims.expected_version.value && payload.observations.provenance.status === 'verified') {
      const environmentIssues = await searchIssues(payload, 'all_versions', request);
      for (const issue of environmentIssues.filter(trustedAutomationIssue)) {
        if (issue.state === 'closed' || issue.pull_request) continue;
        const record = parseIssueRecord(issue.body);
        if (!record || record.payload.environment_digest !== payload.environment_digest || compareOrder(payload, record.payload) <= 0) continue;
        if (!newerStableVersion(payload.claims.expected_version.value, record.payload.claims.expected_version.value)) continue;
        const body = `${issueRecord(payload, record.fingerprint)}\n${issueBody(record.payload, record.fingerprint)}\n### Superseded\n\nA newer stable release was both provenance-verified and observed on target in ${payload.run_url}. The original incident evidence above is preserved.\n`;
        const response = await request('PATCH', `/repos/${payload.repository}/issues/${issue.number}`, { state: 'closed', state_reason: 'not_planned', body });
        if (response.status !== 200) throw githubFailure(response, 'issue_supersede');
      }
    }
    return 'recovered';
  }
  let changed = false;
  for (const fingerprint of payload.incident_fingerprints) {
    const marker = issueMarker(payload, fingerprint);
    const exact = records.filter((entry) => entry.issue.body.includes(marker));
    if (exact.length > 1) throw new VerificationError('github_control:duplicate_marked_issues');
    const newest = records.map((entry) => entry.record.payload).sort((a, b) => compareOrder(b, a))[0];
    if (newest && compareOrder(payload, newest) <= 0) continue;
    const existing = exact[0];
    const body = issueBody(payload, fingerprint);
    if (existing) {
      if (compareOrder(payload, existing.record.payload) <= 0) continue;
      const response = await request('PATCH', `/repos/${payload.repository}/issues/${existing.issue.number}`, { title: issueTitle(payload, fingerprint), body, state: 'open' });
      if (response.status !== 200) throw githubFailure(response, 'issue_update');
    } else {
      const response = await request('POST', `/repos/${payload.repository}/issues`, { title: issueTitle(payload, fingerprint), body });
      if (response.status !== 201) throw githubFailure(response, 'issue_create');
    }
    changed = true;
  }
  return changed ? 'changed' : 'stale_noop';
}

async function main() {
  const mode = process.argv[2];
  invariant(['resolve', 'cleanup', 'validate', 'verify', 'manage-issue'].includes(mode), 'mode_invalid');
  if (mode === 'resolve') {
    resolveConfigTemplate();
    return;
  }
  if (mode === 'cleanup') {
    cleanupResolvedConfigOutput();
    return;
  }
  if (mode === 'manage-issue') {
    const result = await manageIssue();
    appendSummary(`## Incident issue management\n\nResult: \`${result}\`. Ordering and exact hidden markers were enforced.\n`);
    return;
  }
  if (mode === 'verify') {
    const report = await runVerifyMode();
    if (report.overall !== 'pass') process.exitCode = 1;
    return;
  }
  const configPath = explicitResolvedConfigPath(process.env, fs);
  const config = loadConfig(configPath, process.env.TARGET_ENVIRONMENT ?? '');
  const result = await preflight(config);
  writeGithubOutput('environment_digest', result.environment_digest);
  writeGithubOutput('basic_auth_required', String(result.basicAuthRequired));
  writeGithubOutput('config_digest', config.configDigest);
  writeGithubOutput('provenance_payload', encodeProvenancePayload(result.provenance));
  appendSummary(`## Preflight: pass\n\nRepository is public; the exact Environment exists; configuration, budgets, claims, and provenance policy are valid. Environment and target identities are emitted only as digests.\n`);
}

function directInvocation() {
  if (!process.argv[1]) return false;
  const normalized = path.resolve(process.argv[1]).replaceAll('\\', '/');
  return decodeURIComponent(new URL(import.meta.url).pathname).replace(/^\/(?:([A-Za-z]:))/u, '$1') === normalized;
}

if (directInvocation()) {
  main().catch((error) => {
    const clean = cleanError(error);
    console.error(`release-verification:${clean.status}:${clean.code}`);
    process.exitCode = 1;
  });
}

export const __test = Object.freeze({
  blockedReport,
  boundedRequest,
  canonicalOrigin,
  cleanError,
  classifyAttempt,
  compareOrder,
  composeTargetUrl,
  createResolvedConfigOutput,
  cleanupResolvedConfigOutput,
  environmentDigest,
  emitReport,
  failureResult,
  faultFingerprint,
  githubFailure,
  groupMarker,
  inspectHeaders,
  issueBody,
  issueMarker,
  issueRecord,
  junitXml,
  managementPayload,
  newerStableVersion,
  normalizeCode,
  observeProvenance,
  observeVersion,
  outputFiles,
  parseIssueRecord,
  parseProvenancePayload,
  readDecodedBody,
  requestOnce,
  resolvePublic,
  resolveConfigBindings,
  resolveConfigTemplate,
  runCheck,
  searchIssues,
  stableObservedVersion,
  loadConfig,
  validateInvocation,
  validateConfigTemplate,
  validateResolvedConfig,
  validateProvenance,
});
