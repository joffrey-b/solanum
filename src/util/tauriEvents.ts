// Tauri's listen() (and the window's onResized / onCloseRequested) hand back
// their unlisten function through a promise, one IPC round trip later. An
// effect cleanup that runs before it arrives has nothing to call, so the
// `listen(...).then(fn => { unlisten = fn })` form left the listener
// registered for the life of the window (F-052). These helpers unlisten
// whenever the function arrives. No React or Tauri import: tested in Node.

export type Unlisten = () => void;

/** A cleanup for a registration still on its way: calling it unlistens now,
 *  or as soon as the registration resolves. A failed registration is ignored
 *  (nothing to remove). */
export const unlistenWhenReady = (registration: Promise<Unlisten>): Unlisten => {
  let done = false;
  let unlisten: Unlisten | null = null;
  registration.then(
    (fn) => {
      if (done) fn();
      else unlisten = fn;
    },
    () => { /* never registered */ },
  );
  return () => {
    if (done) return;
    done = true;
    if (unlisten) {
      unlisten();
      unlisten = null;
    }
  };
};

/** Registers `handler` for `name` through `listen` and returns the cleanup.
 *  Events that arrive after the cleanup, before the late unlisten has run,
 *  are not delivered. */
export const subscribe = <E>(
  listen: (name: string, handler: (event: E) => void) => Promise<Unlisten>,
  name: string,
  handler: (event: E) => void,
): Unlisten => {
  let live = true;
  const stop = unlistenWhenReady(listen(name, (event) => { if (live) handler(event); }));
  return () => {
    live = false;
    stop();
  };
};
