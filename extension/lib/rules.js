// declarativeNetRequest (DNR) dynamic rules = the "instant block" for repeat visits.
// After the API says a URL is malicious, we add a rule that redirects exactly that
// URL to the warning page. Chrome applies it before any byte of the page loads.
//
// Rule ids:
//   1    master "allow everything" rule, present only while protection is OFF
//        (an allow rule with a higher priority beats our redirect rules)
//   2..  one redirect rule per blocked URL; a bigger id = newer, so the oldest
//        rule is the one with the smallest id.

import { MAX_BLOCK_RULES } from "../config.js";
import { withLock } from "./lock.js";

export const MASTER_ALLOW_RULE_ID = 1;
const FIRST_BLOCK_ID = 2;

export const MASTER_ALLOW_RULE = {
  id: MASTER_ALLOW_RULE_ID,
  priority: 100,
  action: { type: "allow" },
  condition: { resourceTypes: ["main_frame"] },
};

// DNR urlFilter syntax: "|" anchors the start/end, "*" and "^" are wildcards.
// A URL that contains those characters (or non-ASCII) cannot be matched exactly,
// so it gets no rule; the normal webNavigation check still protects it.
export function urlFilterFor(url) {
  const text = String(url);
  if (!/^[\x21-\x7e]+$/.test(text)) return null;
  if (/[*^|]/.test(text)) return null;
  return "|" + text + "|";
}

export function urlFromRule(rule) {
  const f = rule?.condition?.urlFilter;
  return typeof f === "string" && f.length > 2 && f.startsWith("|") && f.endsWith("|") ? f.slice(1, -1) : null;
}

export function isBlockRule(rule) {
  return rule && rule.id !== MASTER_ALLOW_RULE_ID && rule.action?.type === "redirect";
}

export function makeBlockRule(id, url, redirectPath) {
  return {
    id,
    priority: 1,
    action: { type: "redirect", redirect: { extensionPath: redirectPath } },
    condition: { urlFilter: urlFilterFor(url), resourceTypes: ["main_frame"] },
  };
}

// Pure planning functions -> { removeRuleIds, addRules } for updateDynamicRules().

export function planAddBlockRule(existing, url, redirectPath, cap = MAX_BLOCK_RULES) {
  const filter = urlFilterFor(url);
  if (!filter) return null;
  const blocks = existing.filter(isBlockRule).sort((a, b) => a.id - b.id);
  const removeRuleIds = blocks.filter((r) => r.condition?.urlFilter === filter).map((r) => r.id);
  const remaining = blocks.filter((r) => !removeRuleIds.includes(r.id));
  const overflow = remaining.length - (cap - 1); // keep room for the new one
  if (overflow > 0) removeRuleIds.push(...remaining.slice(0, overflow).map((r) => r.id));
  const maxId = existing.reduce((m, r) => Math.max(m, r.id), FIRST_BLOCK_ID - 1);
  return { removeRuleIds, addRules: [makeBlockRule(maxId + 1, url, redirectPath)] };
}

export function planRemoveForUrl(existing, url) {
  const filter = urlFilterFor(url);
  const ids = existing.filter((r) => isBlockRule(r) && r.condition?.urlFilter === filter).map((r) => r.id);
  return { removeRuleIds: ids, addRules: [] };
}

export function planProtection(existing, enabled) {
  const hasMaster = existing.some((r) => r.id === MASTER_ALLOW_RULE_ID);
  if (enabled) return { removeRuleIds: hasMaster ? [MASTER_ALLOW_RULE_ID] : [], addRules: [] };
  return { removeRuleIds: hasMaster ? [MASTER_ALLOW_RULE_ID] : [], addRules: [MASTER_ALLOW_RULE] };
}

// Thin wrapper around chrome.declarativeNetRequest (or a fake one in the tests).
export function createRuleManager(dnr, { cap = MAX_BLOCK_RULES } = {}) {
  const update = (plan) =>
    plan && (plan.removeRuleIds.length || plan.addRules.length) ? dnr.updateDynamicRules(plan) : Promise.resolve();
  const locked = (job) => withLock("dnr-rules", job);

  return {
    addBlock: (url, redirectPath) =>
      locked(async () => {
        const plan = planAddBlockRule(await dnr.getDynamicRules(), url, redirectPath, cap);
        if (!plan) return false;
        await update(plan);
        return true;
      }),
    removeForUrl: (url) => locked(async () => update(planRemoveForUrl(await dnr.getDynamicRules(), url))),
    findForUrl: async (url) => {
      const filter = urlFilterFor(url);
      if (!filter) return null;
      return (await dnr.getDynamicRules()).find((r) => isBlockRule(r) && r.condition?.urlFilter === filter) || null;
    },
    setProtection: (enabled) => locked(async () => update(planProtection(await dnr.getDynamicRules(), enabled))),
    clearBlocks: () =>
      locked(async () => {
        const ids = (await dnr.getDynamicRules()).filter(isBlockRule).map((r) => r.id);
        await update({ removeRuleIds: ids, addRules: [] });
        return ids.length;
      }),
    countBlocks: async () => (await dnr.getDynamicRules()).filter(isBlockRule).length,
  };
}
