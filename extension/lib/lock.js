// Tiny lock: async jobs that share a name run one after another.
// Used for read-modify-write updates of chrome.storage (history list, DNR rules),
// which would otherwise lose updates when two navigations finish at the same time.

const tails = new Map();

export function withLock(name, job) {
  const previous = tails.get(name) || Promise.resolve();
  const run = previous.then(() => job());
  const tail = run.catch(() => {});
  tails.set(name, tail);
  tail.then(() => {
    if (tails.get(name) === tail) tails.delete(name);
  });
  return run;
}
