const AUTHORIZE_URL = "https://appcenter.intuit.com/connect/oauth2";
const TOKEN_URL = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer";
const REVOKE_URL = "https://developer.api.intuit.com/v2/oauth2/tokens/revoke";

function basicAuth(clientId, clientSecret) {
  return `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`;
}

export function buildAuthorizeUrl({ clientId, redirectUri, scope, state }) {
  const url = new URL(AUTHORIZE_URL);
  if (url.origin !== "https://appcenter.intuit.com" || url.pathname !== "/connect/oauth2") {
    throw new Error("Refusing to start: authorize URL is not the Intuit endpoint");
  }
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", scope);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("state", state);
  return url.toString();
}

export async function exchangeCode({ clientId, clientSecret, redirectUri, code, fetchImpl }) {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
  });
  const response = await fetchImpl(TOKEN_URL, {
    method: "POST",
    headers: {
      Accept: "application/json",
      Authorization: basicAuth(clientId, clientSecret),
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body,
  });
  if (!response.ok) return { ok: false, status: response.status };
  let json;
  try {
    json = await response.json();
  } catch {
    return { ok: false, status: response.status };
  }
  if (!json || typeof json.access_token !== "string" || typeof json.refresh_token !== "string") {
    return { ok: false, status: response.status };
  }
  return { ok: true, status: response.status, tokens: json };
}

export async function revokeToken({ clientId, clientSecret, token, fetchImpl }) {
  const response = await fetchImpl(REVOKE_URL, {
    method: "POST",
    headers: {
      Accept: "application/json",
      Authorization: basicAuth(clientId, clientSecret),
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ token }),
  });
  if (response.status !== 200) return { ok: false, status: response.status };
  return { ok: true, status: 200 };
}
