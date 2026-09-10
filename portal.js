"use strict";

const EXPECTED_PROJECT = "trading-ai";
const EXPECTED_REPOSITORY = "mauropavei/Trading-AI";
const RP_ID = "mauropavei.github.io";
const EXPECTED_ORIGIN = "https://mauropavei.github.io";
const REQUIRED_FIELDS = [
  "action_id",
  "artifact_digest",
  "authority_effect",
  "authority_surface_manifest_digest",
  "base_sha",
  "exact_pr_head_sha",
  "exact_source_sha",
  "expires_at",
  "issued_at",
  "nonce",
  "policy_digest",
  "pr_number",
  "prior_owner_trust_digest",
  "prior_registry_digest",
  "project_id",
  "repository"
];

function b64urlToBytes(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("request fragment must be canonical unpadded base64url");
  }
  const padded = value + "=".repeat((4 - (value.length % 4)) % 4);
  const binary = atob(padded.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(binary, ch => ch.charCodeAt(0));
}

function bytesToB64url(bytes) {
  let binary = "";
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function canonicalJson(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return JSON.stringify(value);
  }
  const keys = Object.keys(value).sort();
  return "{" + keys.map(key => JSON.stringify(key) + ":" + canonicalJson(value[key])).join(",") + "}";
}

function parseRequestFragment() {
  if (!window.location.hash.startsWith("#request=")) {
    throw new Error("missing #request fragment");
  }
  const encoded = window.location.hash.slice("#request=".length);
  const bytes = b64urlToBytes(encoded);
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  const request = JSON.parse(text);
  if (request === null || typeof request !== "object" || Array.isArray(request)) {
    throw new Error("request must be an object");
  }
  const fields = Object.keys(request).sort();
  if (JSON.stringify(fields) !== JSON.stringify(REQUIRED_FIELDS)) {
    throw new Error("authorization request field set mismatch");
  }
  if (request.project_id !== EXPECTED_PROJECT || request.repository !== EXPECTED_REPOSITORY) {
    throw new Error("wrong project or repository");
  }
  const canonical = canonicalJson(request);
  if (canonical !== text) {
    throw new Error("request bytes are not canonical JSON");
  }
  return { request, bytes: new TextEncoder().encode(canonical) };
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

async function createEvidence() {
  if (window.location.origin !== EXPECTED_ORIGIN) {
    throw new Error("owner approval portal must run only on the frozen HTTPS origin");
  }
  const { request, bytes } = parseRequestFragment();
  const challenge = await sha256(bytes);
  const credential = await navigator.credentials.get({
    publicKey: {
      challenge,
      rpId: RP_ID,
      userVerification: "required",
      timeout: 60000
    }
  });
  if (!credential || credential.type !== "public-key") {
    throw new Error("WebAuthn public-key assertion unavailable");
  }
  const response = credential.response;
  const requestDigest = "sha256:" + Array.from(challenge).map(b => b.toString(16).padStart(2, "0")).join("");
  const evidence = {
    schema_version: "1.0.0",
    project_id: EXPECTED_PROJECT,
    repository: EXPECTED_REPOSITORY,
    action_id: request.action_id,
    request_digest: requestDigest,
    challenge_b64url: bytesToB64url(challenge),
    credential_id_b64url: bytesToB64url(credential.rawId),
    client_data_json_b64url: bytesToB64url(response.clientDataJSON),
    authenticator_data_b64url: bytesToB64url(response.authenticatorData),
    signature_b64url: bytesToB64url(response.signature),
    user_handle_b64url: response.userHandle ? bytesToB64url(response.userHandle) : null,
    credential_class: document.getElementById("credential-class").value,
    origin: window.location.origin,
    rp_id: RP_ID,
    user_verification: "REQUIRED_VERIFIED",
    exact_pr_head_sha: request.exact_pr_head_sha,
    exact_source_sha: request.exact_source_sha,
    evidence_state: "PUBLIC_CANDIDATE_UNVERIFIED_C3A",
    private_material_included: false,
    authority_granted_by_shape_validation: false
  };
  document.getElementById("evidence").value = canonicalJson(evidence);
  document.getElementById("state").textContent = "Public candidate evidence created; trusted-base verification is still required.";
}

document.getElementById("approve").addEventListener("click", () => {
  createEvidence().catch(error => {
    document.getElementById("state").textContent = "DENY: " + error.message;
    document.getElementById("evidence").value = "";
  });
});
