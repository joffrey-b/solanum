import test from "node:test";
import assert from "node:assert/strict";
import { clearProfileStorage, dropLegacyKeys, profileKey, setStorageProfile } from "./profileStorage.mjs";

const store = (keys) => {
  const m = new Map(keys.map((k) => [k, "v"]));
  return {
    get length() { return m.size; },
    key: (i) => [...m.keys()][i] ?? null,
    removeItem: (k) => { m.delete(k); },
    keys: () => [...m.keys()].sort(),
  };
};

test("keys are per profile, and none while locked (F-070)", () => {
  setStorageProfile(null);
  assert.equal(profileKey("server-dirs-3"), null);
  setStorageProfile("work");
  assert.equal(profileKey("server-dirs-3"), "solanum-profile:work:server-dirs-3");
  setStorageProfile("home");
  assert.notEqual(profileKey("server-dirs-3"), "solanum-profile:work:server-dirs-3");
  setStorageProfile(null);
});

test("clearing a profile removes only its keys, not those of a name it begins", () => {
  const s = store([
    "solanum-profile:a:server-dirs-1",
    "solanum-profile:a:sftp-bookmarks-local",
    "solanum-profile:a-b:server-dirs-1",
    "solanum-profile:ab:server-dirs-1",
    "solanum-primary-color",
  ]);
  assert.equal(clearProfileStorage("a", s), 2);
  assert.deepEqual(s.keys(), ["solanum-primary-color", "solanum-profile:a-b:server-dirs-1", "solanum-profile:ab:server-dirs-1"]);
});

test("the old shared keys go once; preferences stay", () => {
  const s = store([
    "solanum-server-dirs-session-3",
    "solanum-server-dirs-session-quick-1730000000000",
    "solanum-sftp-side-session-3",
    "solanum-sftp-bookmarks-3",
    "solanum-sftp-bookmarks-local",
    "solanum-pinned-folder-expanded-work-7",
    "solanum-sftp-layout",
    "solanum-pinned-panel-open",
    "solanum-pinned-panel-width",
    "solanum-profile:work:server-dirs-3",
  ]);
  assert.equal(dropLegacyKeys(s), 6);
  assert.deepEqual(s.keys(), ["solanum-pinned-panel-open", "solanum-pinned-panel-width", "solanum-profile:work:server-dirs-3", "solanum-sftp-layout"]);
});

test("a storage that throws is tolerated", () => {
  const broken = { get length() { throw new Error("denied"); }, key: () => null, removeItem: () => {} };
  assert.equal(clearProfileStorage("a", broken), 0);
  assert.equal(dropLegacyKeys(null), 0);
});
