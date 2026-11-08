// Validation for an operator-supplied Anthropic base URL (direct API or a
// corporate gateway). The URL receives the Anthropic key or gateway token, and
// the first-run connection test fetches it before anyone has signed in, so it
// must not be usable to reach cloud metadata services or to smuggle
// credentials. Private-network gateways stay allowed: many corporate gateways
// live on internal addresses.

const METADATA_HOSTS = new Set([
  "metadata.google.internal",
  "metadata.goog",
  "metadata",
  "instance-data",
  "instance-data.ec2.internal",
]);

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** Returns an error message, or null when the URL is acceptable. */
export function anthropicBaseUrlError(raw: string): string | null {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return "Anthropic Base URL must be a full URL, e.g. https://gateway.example.com.";
  }
  const host = url.hostname.toLowerCase();
  if (url.username || url.password) return "Anthropic Base URL must not contain credentials.";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && (LOOPBACK.has(host) || host.endsWith(".localhost")))) {
    return "Anthropic Base URL must use https:// (plain http is allowed only for localhost).";
  }
  if (
    METADATA_HOSTS.has(host) ||
    /^169\.254\.\d{1,3}\.\d{1,3}$/.test(host) ||
    /^\[?fe[89ab][0-9a-f]:/.test(host) ||
    host === "[fd00:ec2::254]" ||
    host === "100.100.100.200"
  ) {
    return "Anthropic Base URL can't point at a link-local or cloud metadata address.";
  }
  return null;
}
