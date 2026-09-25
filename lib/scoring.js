import { parseEmail } from "./parser.js";
import { detectSender } from "./detectors/sender.js";
import { detectUrls } from "./detectors/url.js";
import { detectContent } from "./detectors/content.js";
import { detectAuth } from "./detectors/auth.js";
import { THRESHOLDS } from "./constants.js";

function classify(score) {
  if (score <= THRESHOLDS.LOW_MAX) return "LOW RISK";
  if (score <= THRESHOLDS.SUSPICIOUS_MAX) return "SUSPICIOUS";
  return "PHISHING";
}

function recommendationFor(classification) {
  if (classification === "PHISHING") {
    return "Do not click any links or reply. Report this email to your IT/security team and verify the sender through an independent channel.";
  }
  if (classification === "SUSPICIOUS") {
    return "Treat this email with caution. Verify the sender independently before clicking links or replying.";
  }
  return "No strong indicators of phishing were found. Standard email caution still applies.";
}

export function analyzeEmail(raw) {
  const parsed = parseEmail(raw);

  const sender = detectSender(parsed);
  const url = detectUrls(parsed);
  const content = detectContent(parsed);
  const auth = detectAuth(parsed);

  const evidence = [
    ...sender.evidence,
    ...url.evidence,
    ...content.evidence,
    ...auth.evidence,
  ].sort((a, b) => b.score - a.score);

  const rawScore = evidence.reduce((sum, e) => sum + e.score, 0);
  const score = Math.min(rawScore, 100);
  const classification = classify(score);

  return {
    subject: parsed.subject,
    score,
    classification,
    evidence,
    sender: sender.panel,
    urls: url.panel.urls,
    auth: auth.panel,
    content: content.panel,
    recommendation: recommendationFor(classification),
  };
}
