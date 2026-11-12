// localStorage belongs to the whole app, not to a profile, and session and
// server ids are small integers every vault reuses. So what one profile's
// panes remember (folders last open, bookmarks, the side last used) is kept
// under that profile's name (F-070): `solanum-profile:<name>:<what>`. Profile
// names are letters, digits, `-` and `_`, so the `:` delimiters cannot be
// confused. The values stay plaintext (paths and UI choices, never secrets);
// deleting or creating a profile removes its keys, so a new profile with an
// old name starts clean. No React import: tested in Node.

const PREFIX = "solanum-profile:";

// Keys of the time before they were per profile: they belong to no known
// profile, so they are removed once at start-up.
export const LEGACY_PREFIXES = [
  "solanum-server-dirs-",
  "solanum-sftp-side-",
  "solanum-sftp-bookmarks-",
  "solanum-pinned-folder-expanded-",
];

/** The part of `Storage` used here (a fake in the tests). */
export interface KeyStore {
  readonly length: number;
  key(index: number): string | null;
  removeItem(key: string): void;
}

let current: string | null = null;

/** Set when a profile is unlocked, `null` when it is locked. */
export const setStorageProfile = (name: string | null): void => {
  current = name;
};

export const profilePrefix = (name: string): string => `${PREFIX}${name}:`;

/** The key for `what` in the unlocked profile; `null` when none is unlocked
 *  (nothing is remembered then). */
export const profileKey = (what: string): string | null => (current === null ? null : profilePrefix(current) + what);

const storage = (): KeyStore | null => {
  try {
    return window.localStorage;
  } catch {
    return null;
  }
};

const removeWhere = (store: KeyStore | null, doomed: (key: string) => boolean): number => {
  if (!store) return 0;
  try {
    const keys: string[] = [];
    for (let i = 0; i < store.length; i++) {
      const k = store.key(i);
      if (k !== null && doomed(k)) keys.push(k);
    }
    keys.forEach((k) => store.removeItem(k));
    return keys.length;
  } catch {
    return 0;
  }
};

/** Removes every key of profile `name`. */
export const clearProfileStorage = (name: string, store: KeyStore | null = storage()): number => {
  const prefix = profilePrefix(name);
  return removeWhere(store, (k) => k.startsWith(prefix));
};

/** Removes the keys written before they were per profile. */
export const dropLegacyKeys = (store: KeyStore | null = storage()): number =>
  removeWhere(store, (k) => LEGACY_PREFIXES.some((p) => k.startsWith(p)));
