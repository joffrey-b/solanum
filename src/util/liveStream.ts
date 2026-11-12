// One run of a backend stream that reports through two app events, a data
// event and a "closed" event (the Docker live log: `docker-logs-<id>`,
// `docker-logs-closed-<id>`). Each start is its own run (F-051): both
// listeners are registered before the stream is started, every step checks
// whether the run was stopped meanwhile and undoes what it created, a stop
// sent before the backend registered the stream is sent again once it has,
// and a stop or a close from the server tears the same things down (both
// listeners, nothing delivered afterwards). No React or Tauri import: tested
// in Node.

import { unlistenWhenReady, type Unlisten } from "./tauriEvents";

export interface LiveStreamOptions<T> {
  dataEvent: string;
  closedEvent: string;
  listen: (name: string, handler: (payload: T) => void) => Promise<Unlisten>;
  /** Runs first (the log's current tail); a stop meanwhile ends the run. */
  before?: () => Promise<void>;
  start: () => Promise<unknown>;
  /** Asks the backend to end the stream; errors are ignored. */
  stop: () => Promise<unknown>;
  onData: (payload: T) => void;
  /** Called once, when the run ends for any reason; `error` if it failed. */
  onEnd: (error?: string) => void;
}

export interface LiveRun {
  /** Ends the run: the backend stream is stopped if it was started. */
  stop(): void;
  readonly ended: boolean;
}

const message = (e: unknown) =>
  typeof e === "string" ? e : (e as any)?.message ? String((e as any).message) : String(e);

export function startLiveStream<T>(o: LiveStreamOptions<T>): LiveRun {
  let ended = false;
  let startSent = false;
  const cleanups: Unlisten[] = [];

  const end = (sendStop: boolean, error?: string) => {
    if (ended) return;
    ended = true;
    cleanups.splice(0).forEach((c) => c());
    if (sendStop && startSent) o.stop().catch(() => {});
    o.onEnd(error);
  };

  (async () => {
    if (o.before) {
      await o.before();
      if (ended) return;
    }
    const dataReg = o.listen(o.dataEvent, (payload) => { if (!ended) o.onData(payload); });
    const closedReg = o.listen(o.closedEvent, () => end(false));
    cleanups.push(unlistenWhenReady(dataReg), unlistenWhenReady(closedReg));
    try {
      await Promise.all([dataReg, closedReg]);
    } catch (e) {
      end(false, message(e));
      return;
    }
    if (ended) return;
    startSent = true;
    try {
      await o.start();
    } catch (e) {
      end(false, message(e));
      return;
    }
    // Stopped while the start was on its way: that stop may have reached the
    // backend before the stream existed, so this one ends it.
    if (ended) o.stop().catch(() => {});
  })().catch((e) => end(true, message(e)));

  return {
    stop: () => end(true),
    get ended() { return ended; },
  };
}
