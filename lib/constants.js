export const URGENCY_KEYWORDS = [
  "urgent",
  "immediately",
  "verify",
  "suspended",
  "account locked",
  "confirm",
  "act now",
  "final notice",
  "security alert",
  "unauthorized",
  "click here",
];

export const CREDENTIAL_KEYWORDS = [
  "password",
  "login",
  "credentials",
  "ssn",
  "social security",
  "bank account",
  "card number",
  "pin",
  "otp",
  "one-time code",
];

export const SUSPICIOUS_TLDS = [
  ".xyz",
  ".top",
  ".zip",
  ".club",
  ".work",
  ".gq",
  ".tk",
  ".ml",
  ".info",
];

export const URL_SHORTENERS = [
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "ow.ly",
  "is.gd",
  "buff.ly",
  "rebrand.ly",
];

export const KNOWN_BRANDS = [
  "paypal",
  "amazon",
  "google",
  "microsoft",
  "apple",
  "netflix",
  "bankofamerica",
  "wellsfargo",
  "chase",
  "facebook",
  "instagram",
  "linkedin",
];

// Score weights — tune these live during the demo if needed, nowhere else.
export const WEIGHTS = {
  REPLY_TO_MISMATCH: 15,
  RETURN_PATH_MISMATCH: 10,
  SUSPICIOUS_DOMAIN: 20,
  LOOKALIKE_DOMAIN: 20,
  IP_BASED_URL: 20,
  URL_SHORTENER: 10,
  LOGIN_URL: 10,
  URGENCY_LANGUAGE: 10,
  CREDENTIAL_LANGUAGE: 10,
  SPF_FAIL: 10,
  DKIM_FAIL: 10,
  DMARC_FAIL: 15,
};

export const THRESHOLDS = {
  LOW_MAX: 29,
  SUSPICIOUS_MAX: 59,
};
