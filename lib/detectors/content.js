import { WEIGHTS, URGENCY_KEYWORDS, CREDENTIAL_KEYWORDS } from "../constants.js";

function findMatches(text, list) {
  const lower = text.toLowerCase();
  return list.filter((word) => lower.includes(word));
}

export function detectContent(parsed) {
  const evidence = [];
  const urgencyMatches = findMatches(parsed.body, URGENCY_KEYWORDS);
  const credentialMatches = findMatches(parsed.body, CREDENTIAL_KEYWORDS);

  if (urgencyMatches.length > 0) {
    evidence.push({
      indicator: "Urgency language detected",
      severity: "medium",
      score: WEIGHTS.URGENCY_LANGUAGE,
      detail: `Matched: ${urgencyMatches.join(", ")}`,
    });
  }

  if (credentialMatches.length > 0) {
    evidence.push({
      indicator: "Credential-related language detected",
      severity: "medium",
      score: WEIGHTS.CREDENTIAL_LANGUAGE,
      detail: `Matched: ${credentialMatches.join(", ")}`,
    });
  }

  return {
    panel: { urgencyMatches, credentialMatches },
    evidence,
  };
}
