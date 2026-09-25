import { domainToUnicode } from "url";
import { WEIGHTS, SUSPICIOUS_TLDS, URL_SHORTENERS, KNOWN_BRANDS } from "../constants.js";

const IP_REGEX = /^\d{1,3}(\.\d{1,3}){3}$/;
const LOGIN_WORDS = ["login", "signin", "verify", "account", "secure", "update", "confirm"];

// Very small Levenshtein distance for lookalike-domain detection.
function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] =
        a[i - 1] === b[j - 1]
          ? dp[i - 1][j - 1]
          : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[a.length][b.length];
}

function findLookalikeBrand(domain) {
  // Check the full second-level label AND each hyphen-split segment, so
  // "paypa1-login.xyz" catches "paypa1" against "paypal" even though the
  // whole label is too different in length to match directly.
  const secondLevel = domain.split(".")[0];
  const segments = [secondLevel, ...secondLevel.split("-")];

  for (const segment of segments) {
    if (segment.length < 4) continue; // too short to compare meaningfully
    for (const brand of KNOWN_BRANDS) {
      if (segment === brand) continue; // exact match to the real brand is fine
      const dist = levenshtein(segment, brand);
      if (dist > 0 && dist <= 2 && segment.length >= brand.length - 2) {
        return brand;
      }
    }
  }
  return null;
}

function checkIdnHomograph(hostname) {
  const hasPunycode = hostname.split(".").some((label) => label.startsWith("xn--"));
  if (!hasPunycode) return null;

  const decoded = domainToUnicode(hostname);
  if (decoded === hostname) return null;

  return decoded;
}

function analyzeOneUrl(rawUrl) {
  let hostname;
  try {
    hostname = new URL(rawUrl).hostname.toLowerCase();
  } catch {
    return null;
  }

  const flags = [];
  let score = 0;

  const isIp = IP_REGEX.test(hostname);
  if (isIp) {
    flags.push({ label: "IP-based URL", weight: WEIGHTS.IP_BASED_URL });
    score += WEIGHTS.IP_BASED_URL;
  }

  const isShortener = URL_SHORTENERS.some((s) => hostname.includes(s));
  if (isShortener) {
    flags.push({ label: "URL shortener", weight: WEIGHTS.URL_SHORTENER });
    score += WEIGHTS.URL_SHORTENER;
  }

  const suspiciousTld = SUSPICIOUS_TLDS.find((tld) => hostname.endsWith(tld));
  if (suspiciousTld) {
    flags.push({ label: `Suspicious TLD (${suspiciousTld})`, weight: WEIGHTS.SUSPICIOUS_DOMAIN });
    score += WEIGHTS.SUSPICIOUS_DOMAIN;
  }

  const lookalike = !isIp ? findLookalikeBrand(hostname) : null;
  if (lookalike) {
    flags.push({ label: `Lookalike of "${lookalike}"`, weight: WEIGHTS.LOOKALIKE_DOMAIN });
    score += WEIGHTS.LOOKALIKE_DOMAIN;
  }

  const idnHomograph = !isIp ? checkIdnHomograph(hostname) : null;
  if (idnHomograph) {
    flags.push({ label: `IDN homograph (displays as "${idnHomograph}")`, weight: WEIGHTS.IDN_HOMOGRAPH });
    score += WEIGHTS.IDN_HOMOGRAPH;
  }

  const isLoginUrl = LOGIN_WORDS.some((w) => rawUrl.toLowerCase().includes(w));
  if (isLoginUrl) {
    flags.push({ label: "Login-related URL", weight: WEIGHTS.LOGIN_URL });
    score += WEIGHTS.LOGIN_URL;
  }

  const subdomainCount = hostname.split(".").length - 2;
  if (subdomainCount >= 3) {
    flags.push({ label: "Excessive subdomains", weight: WEIGHTS.SUSPICIOUS_DOMAIN });
    score += WEIGHTS.SUSPICIOUS_DOMAIN;
  }

  return { url: rawUrl, domain: hostname, isIp, flags, score };
}

export function detectUrls(parsed) {
  const analyzed = parsed.urls.map(analyzeOneUrl).filter(Boolean);
  const evidence = [];

  // Roll each unique flag type into one evidence line (avoid duplicate spam
  // if the same issue shows up across multiple URLs).
  const seen = new Map();
  for (const item of analyzed) {
    for (const flag of item.flags) {
      if (!seen.has(flag.label)) {
        seen.set(flag.label, { indicator: flag.label, score: flag.weight, urls: [] });
      }
      seen.get(flag.label).urls.push(item.domain);
    }
  }

  for (const [, entry] of seen) {
    evidence.push({
      indicator: entry.indicator,
      severity: entry.score >= 20 ? "high" : "medium",
      score: entry.score,
      detail: `Seen in: ${[...new Set(entry.urls)].join(", ")}`,
    });
  }

  return { panel: { urls: analyzed }, evidence };
}
