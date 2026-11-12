// The automatic update check runs once per launch. The profile picker mounts
// at launch and again every time a profile is locked, so the rule cannot live
// in the component: each lock would be another request to GitHub. Module state
// lasts until the page is loaded again. The answer is kept, so the "update
// available" notice is still there after a lock, and a failure is not retried:
// an offline machine has nothing to gain from asking again.
export function onceUntilReload<T>(run: () => Promise<T>): () => Promise<T> {
  let result: Promise<T> | null = null;
  return () => {
    if (!result) {
      try {
        result = run();
      } catch (e) {
        result = Promise.reject(e);
      }
    }
    return result;
  };
}
