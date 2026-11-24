// declarativeNetRequest rule planning, with a fake chrome.declarativeNetRequest.
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  urlFilterFor,
  urlFromRule,
  planAddBlockRule,
  planRemoveForUrl,
  planProtection,
  createRuleManager,
  MASTER_ALLOW_RULE_ID,
} from "../lib/rules.js";

function fakeDnr() {
  let rules = [];
  return {
    async getDynamicRules() {
      return structuredClone(rules);
    },
    async updateDynamicRules({ removeRuleIds = [], addRules = [] }) {
      rules = rules.filter((r) => !removeRuleIds.includes(r.id));
      for (const r of addRules) {
        if (rules.some((x) => x.id === r.id)) throw new Error("duplicate id " + r.id);
        rules.push(structuredClone(r));
      }
    },
    get rules() {
      return rules;
    },
  };
}

test("urlFilter is an exact, anchored match; unsupported URLs get none", () => {
  assert.equal(urlFilterFor("https://evil.tk/a?b=1"), "|https://evil.tk/a?b=1|");
  assert.equal(urlFilterFor("https://evil.tk/*"), null);
  assert.equal(urlFilterFor("https://evil.tk/a^b"), null);
  assert.equal(urlFilterFor("https://evil.tk/a|b"), null);
  assert.equal(urlFilterFor("https://evil.tk/ä"), null);
  assert.equal(urlFromRule({ condition: { urlFilter: "|https://x.tk/|" } }), "https://x.tk/");
});

test("first block rule gets id 2 and redirects main frames to the warning page", () => {
  const plan = planAddBlockRule([], "https://evil.tk/", "/warning.html?u=x");
  assert.deepEqual(plan.removeRuleIds, []);
  const [rule] = plan.addRules;
  assert.equal(rule.id, 2);
  assert.equal(rule.action.type, "redirect");
  assert.equal(rule.action.redirect.extensionPath, "/warning.html?u=x");
  assert.deepEqual(rule.condition.resourceTypes, ["main_frame"]);
});

test("cap: the oldest rule is removed first", async () => {
  const dnr = fakeDnr();
  const rules = createRuleManager(dnr, { cap: 3 });
  for (let i = 1; i <= 5; i++) await rules.addBlock("https://bad" + i + ".tk/", "/warning.html");
  const urls = dnr.rules.map(urlFromRule);
  assert.deepEqual(urls, ["https://bad3.tk/", "https://bad4.tk/", "https://bad5.tk/"]);
  assert.equal(await rules.countBlocks(), 3);
});

test("adding the same URL again replaces its rule instead of duplicating it", async () => {
  const dnr = fakeDnr();
  const rules = createRuleManager(dnr);
  await rules.addBlock("https://evil.tk/", "/warning.html?p=0.9");
  await rules.addBlock("https://evil.tk/", "/warning.html?p=0.95");
  assert.equal(dnr.rules.length, 1);
  assert.equal(dnr.rules[0].action.redirect.extensionPath, "/warning.html?p=0.95");
});

test("concurrent adds get unique ids (lock)", async () => {
  const dnr = fakeDnr();
  const rules = createRuleManager(dnr);
  await Promise.all(["a", "b", "c", "d"].map((x) => rules.addBlock("https://" + x + ".tk/", "/warning.html")));
  assert.equal(new Set(dnr.rules.map((r) => r.id)).size, 4);
});

test("'Proceed anyway' removes only that URL's rule", async () => {
  const dnr = fakeDnr();
  const rules = createRuleManager(dnr);
  await rules.addBlock("https://a.tk/", "/warning.html");
  await rules.addBlock("https://b.tk/", "/warning.html");
  await rules.removeForUrl("https://a.tk/");
  assert.deepEqual(dnr.rules.map(urlFromRule), ["https://b.tk/"]);
  assert.equal(await rules.findForUrl("https://a.tk/"), null);
  assert.ok(await rules.findForUrl("https://b.tk/"));
  assert.deepEqual(planRemoveForUrl([], "https://x.tk/").removeRuleIds, []);
});

test("protection off adds the master allow rule; on removes it; blocks are kept", async () => {
  const dnr = fakeDnr();
  const rules = createRuleManager(dnr);
  await rules.addBlock("https://a.tk/", "/warning.html");
  await rules.setProtection(false);
  await rules.setProtection(false); // twice is fine
  const master = dnr.rules.filter((r) => r.id === MASTER_ALLOW_RULE_ID);
  assert.equal(master.length, 1);
  assert.equal(master[0].action.type, "allow");
  assert.ok(master[0].priority > 1);
  await rules.setProtection(true);
  assert.equal(dnr.rules.some((r) => r.id === MASTER_ALLOW_RULE_ID), false);
  assert.equal(await rules.countBlocks(), 1);
  assert.deepEqual(planProtection([], true), { removeRuleIds: [], addRules: [] });
});

test("clearBlocks keeps the master rule", async () => {
  const dnr = fakeDnr();
  const rules = createRuleManager(dnr);
  await rules.setProtection(false);
  await rules.addBlock("https://a.tk/", "/warning.html");
  await rules.addBlock("https://b.tk/", "/warning.html");
  assert.equal(await rules.clearBlocks(), 2);
  assert.deepEqual(dnr.rules.map((r) => r.id), [MASTER_ALLOW_RULE_ID]);
});
