// Sessions whose typed commands are not recorded in the command history
// ("Don't record command history" in the session tab's menu, F-023). For this
// run of the app only; dropped when its session closes, which includes
// locking the profile (session ids are reused: `session-<server id>`).
const paused = new Set<string>();

export const isRecordingPaused = (sessionId: string): boolean => paused.has(sessionId);

export const setRecordingPaused = (sessionId: string, on: boolean) => {
  if (on) paused.add(sessionId);
  else paused.delete(sessionId);
};

/** Forgets every session that is no longer open. */
export const keepRecordingPausedFor = (openSessionIds: string[]) => {
  const open = new Set(openSessionIds);
  for (const id of [...paused]) if (!open.has(id)) paused.delete(id);
};
