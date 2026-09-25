function extractHeader(raw, name) {
 
  const re = new RegExp(`^${name}:\\s*(.+(?:\\n[ \\t]+.+)*)`, "im");
  const match = raw.match(re);
  if (!match) return null;
  return match[1].replace(/\n[ \t]+/g, " ").trim();
}

function extractEmailAddress(headerValue) {
  if (!headerValue) return null;
  const match = headerValue.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
  return match ? match[0].toLowerCase() : null;
}

function extractDomain(emailOrUrl) {
  if (!emailOrUrl) return null;
  if (emailOrUrl.includes("@")) {
    return emailOrUrl.split("@")[1]?.toLowerCase() || null;
  }
  try {
    const url = emailOrUrl.startsWith("http") ? emailOrUrl : `http://${emailOrUrl}`;
    return new URL(url).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function extractBody(raw) {
  
  const idx = raw.search(/\n\s*\n/);
  return idx === -1 ? raw : raw.slice(idx).trim();
}

function extractUrls(text) {
  const re = /https?:\/\/[^\s"'<>)\]]+/gi;
  const found = text.match(re) || [];
  // De-duplicate while preserving order.
  return [...new Set(found)];
}

export function parseEmail(raw) {
  const fromHeader = extractHeader(raw, "From");
  const replyToHeader = extractHeader(raw, "Reply-To");
  const returnPathHeader = extractHeader(raw, "Return-Path");
  const subject = extractHeader(raw, "Subject") || "(no subject)";
  const authResults = extractHeader(raw, "Authentication-Results");
  const body = extractBody(raw);

  const from = extractEmailAddress(fromHeader);
  const replyTo = extractEmailAddress(replyToHeader);
  const returnPath = extractEmailAddress(returnPathHeader);

  const urls = extractUrls(raw);

  return {
    subject,
    from,
    fromDomain: extractDomain(from),
    replyTo,
    replyToDomain: extractDomain(replyTo),
    returnPath,
    returnPathDomain: extractDomain(returnPath),
    authResultsRaw: authResults,
    body,
    urls,
    raw,
  };
}
