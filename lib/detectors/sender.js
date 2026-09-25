import { WEIGHTS } from "../constants.js";

export function detectSender(parsed) {
  const evidence = [];
  const { fromDomain, replyToDomain, returnPathDomain, from, replyTo, returnPath } = parsed;

  const replyToMismatch =
    replyToDomain && fromDomain && replyToDomain !== fromDomain;

  const returnPathMismatch =
    returnPathDomain && fromDomain && returnPathDomain !== fromDomain;

  if (replyToMismatch) {
    evidence.push({
      indicator: "Reply-To mismatch",
      severity: "high",
      score: WEIGHTS.REPLY_TO_MISMATCH,
      detail: `From domain "${fromDomain}" differs from Reply-To domain "${replyToDomain}"`,
    });
  }

  if (returnPathMismatch) {
    evidence.push({
      indicator: "Return-Path mismatch",
      severity: "medium",
      score: WEIGHTS.RETURN_PATH_MISMATCH,
      detail: `From domain "${fromDomain}" differs from Return-Path domain "${returnPathDomain}"`,
    });
  }

  return {
    panel: {
      from,
      replyTo,
      returnPath,
      fromDomain,
      replyToDomain,
      returnPathDomain,
      replyToMismatch,
      returnPathMismatch,
    },
    evidence,
  };
}
