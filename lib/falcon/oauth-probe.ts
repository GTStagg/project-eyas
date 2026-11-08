import "server-only";

export const FALCON_BASE_URL_RE = /^https:\/\/api(\.[a-z0-9-]+)*\.crowdstrike\.com$/i;

export type ProbeResult = {
  ok: boolean;
  message: string;
  // OAuth-only checks (creds + base-url match) populate these:
  oauth_ok?: boolean;
  oauth_status?: number;
  // Tenant-identification probe (uses Sensor Download:read or Hosts:read).
  // Populated when `deep` is requested AND OAuth succeeded.
  tenant_cid?: string | null;
  tenant_probe_ok?: boolean;
  tenant_probe_detail?: string;
  // Hosts read smoke-test result. Populated when deep + OAuth ok.
  hosts_read_ok?: boolean;
  hosts_read_status?: number;
};

/** Cheap OAuth-only probe — confirms creds + base URL. */
export async function probeFalconCredentials(
  clientId: string,
  clientSecret: string,
  baseUrl: string,
): Promise<ProbeResult> {
  const oauth = await tokenRequest(clientId, clientSecret, baseUrl);
  if (!oauth.ok) {
    return {
      ok: false,
      message: oauth.message,
      oauth_ok: false,
      oauth_status: oauth.status,
    };
  }
  return {
    ok: true,
    message: "Connected to Falcon.",
    oauth_ok: true,
    oauth_status: oauth.status,
  };
}

/**
 * Deep probe: OAuth + tenant CID lookup + Hosts:read smoke. Catches the
 * "wrong tenant" mismatch (clientId for SE pasted into Default record)
 * — the tenant CID surfaces in the response and the operator can see
 * the Default record actually belongs to SE.
 *
 * Tenant CID is fetched via `/sensors/queries/installers/v1?limit=1`
 * which requires `Sensor Download:read` (almost universally granted). On
 * 403 we fall back to `/devices/queries/devices/v1?limit=1` (Hosts:read).
 * Either way we surface what we got.
 */
export async function probeFalconCredentialsDeep(
  clientId: string,
  clientSecret: string,
  baseUrl: string,
): Promise<ProbeResult> {
  const shallow = await probeFalconCredentials(clientId, clientSecret, baseUrl);
  if (!shallow.ok) return shallow;
  // OAuth succeeded — re-mint a token to use for downstream calls. The
  // shallow probe doesn't return the token; we just call again.
  const tok = await tokenRequest(clientId, clientSecret, baseUrl);
  if (!tok.ok || !tok.access_token) {
    return shallow; // shouldn't happen since shallow.ok was true
  }

  const url = baseUrl.replace(/\/$/, "");
  const headers = { Authorization: `Bearer ${tok.access_token}` };

  // Hosts read smoke: returns up to 1 device id.
  let hostsResp: Response | null = null;
  try {
    hostsResp = await fetch(`${url}/devices/queries/devices/v1?limit=1`, {
      headers,
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    /* fall through */
  }
  const hostsOk = !!hostsResp && hostsResp.ok;
  const hostsStatus = hostsResp?.status ?? 0;

  // Tenant CID. The simplest authoritative source is response headers on
  // any authed call: CrowdStrike returns `X-Cs-Region` and (sometimes)
  // `X-Cs-Cid` on response. If we got a hosts response, peek there.
  // Otherwise we leave tenant_cid null and surface the probe error.
  let tenantCid: string | null = null;
  let tenantDetail = "";
  let tenantOk = false;
  if (hostsResp) {
    tenantCid =
      hostsResp.headers.get("x-cs-cid") ||
      hostsResp.headers.get("X-Cs-Cid") ||
      hostsResp.headers.get("x-cs-customer") ||
      null;
    if (tenantCid) {
      tenantOk = true;
      tenantDetail = "Returned by the Falcon API";
    }
  }

  // If headers didn't carry the CID, try the dedicated endpoint.
  if (!tenantCid) {
    try {
      const r = await fetch(`${url}/sensors/queries/installers/ccid/v1`, {
        headers,
        signal: AbortSignal.timeout(10_000),
      });
      if (r.ok) {
        const j = (await r.json()) as { resources?: string[] };
        if (j.resources && j.resources[0]) {
          // CCID format: <CID>-<checksum> or <CID>-NN-<checksum>. Strip
          // the suffix to surface just the CID prefix.
          const ccid = j.resources[0];
          tenantCid = ccid.split("-")[0] || ccid;
          tenantOk = true;
          tenantDetail = "Returned by the Falcon API";
        }
      } else {
        tenantDetail = "Sensor Download permission required to look up the tenant ID.";
      }
    } catch (err) {
      tenantDetail = err instanceof Error ? err.message : String(err);
    }
  }

  let message = "Connected.";
  if (tenantCid) message += ` Tenant: ${tenantCid}.`;
  if (hostsOk) message += " Host read access confirmed.";
  else if (hostsStatus === 403) message += " Host read access not granted.";

  return {
    ok: true,
    message,
    oauth_ok: true,
    oauth_status: shallow.oauth_status,
    tenant_cid: tenantCid,
    tenant_probe_ok: tenantOk,
    tenant_probe_detail: tenantDetail,
    hosts_read_ok: hostsOk,
    hosts_read_status: hostsStatus,
  };
}

async function tokenRequest(
  clientId: string,
  clientSecret: string,
  baseUrl: string,
): Promise<{ ok: boolean; status: number; message: string; access_token?: string }> {
  try {
    const res = await fetch(`${baseUrl.replace(/\/$/, "")}/oauth2/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
      }).toString(),
      signal: AbortSignal.timeout(10_000),
    });
    if (res.ok) {
      const j = (await res.json()) as { access_token?: string };
      return {
        ok: true,
        status: res.status,
        message: "ok",
        access_token: j.access_token,
      };
    }
    const text = await res.text();
    let detail = text.slice(0, 200);
    try {
      const parsed = JSON.parse(text) as { errors?: Array<{ message?: string }> };
      if (parsed.errors?.[0]?.message) detail = parsed.errors[0].message;
    } catch {
      /* keep raw */
    }
    return {
      ok: false,
      status: res.status,
      message: `${res.status} ${res.statusText}: ${detail}`,
    };
  } catch (err) {
    return {
      ok: false,
      status: 0,
      message: err instanceof Error ? err.message : String(err),
    };
  }
}
