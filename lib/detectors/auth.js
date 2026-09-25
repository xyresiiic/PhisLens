import { WEIGHTS } from "../constants.js";

function extractResult(authRaw, mechanism) {
  if (!authRaw) return "Not Available";
  const re = new RegExp(`${mechanism}=(\\w+)`, "i");
  const match = authRaw.match(re);
  return match ? match[1].toUpperCase() : "Not Available";
}

export function detectAuth(parsed) {
  const spf = extractResult(parsed.authResultsRaw, "spf");
  const dkim = extractResult(parsed.authResultsRaw, "dkim");
  const dmarc = extractResult(parsed.authResultsRaw, "dmarc");

  const evidence = [];

  if (spf === "FAIL") {
    evidence.push({
      indicator: "SPF authentication failed",
      severity: "medium",
      score: WEIGHTS.SPF_FAIL,
      detail: "Sending server is not authorized for this domain",
    });
  }
  if (dkim === "FAIL") {
    evidence.push({
      indicator: "DKIM authentication failed",
      severity: "medium",
      score: WEIGHTS.DKIM_FAIL,
      detail: "Message signature could not be verified",
    });
  }
  if (dmarc === "FAIL") {
    evidence.push({
      indicator: "DMARC authentication failed",
      severity: "high",
      score: WEIGHTS.DMARC_FAIL,
      detail: "Message fails domain alignment policy",
    });
  }

  return { panel: { spf, dkim, dmarc }, evidence };
}
