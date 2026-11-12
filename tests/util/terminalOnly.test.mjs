import test from "node:test";
import assert from "node:assert/strict";
import { needsAnotherChannel, terminalOnlyNotice, terminalOnlyReason, unavailableHint } from "./terminalOnly.mjs";

test("only the backend's reasons count as a limit", () => {
  for (const reason of ["setting", "server_ident", "refused_channel"]) {
    assert.equal(terminalOnlyReason(reason), reason);
  }
  for (const other of [null, undefined, "", "yes", true, {}]) {
    assert.equal(terminalOnlyReason(other), null);
  }
});

test("SFTP, live info and Docker need another channel, the rest do not", () => {
  for (const tool of ["sftp", "info", "docker"]) assert.equal(needsAnotherChannel(tool), true);
  for (const tool of ["cmds", "tunnels", null]) assert.equal(needsAnotherChannel(tool), false);
});

test("a detected host gets the notice and the offer, a server already set does not", () => {
  assert.deepEqual(terminalOnlyNotice(null, 3), { show: false, offerSetting: false });
  assert.deepEqual(terminalOnlyNotice("setting", 3), { show: false, offerSetting: false });
  assert.deepEqual(terminalOnlyNotice("server_ident", 3), { show: true, offerSetting: true });
  assert.deepEqual(terminalOnlyNotice("refused_channel", 3), { show: true, offerSetting: true });
});

test("a quick-connect session has no saved server to offer the setting on", () => {
  assert.deepEqual(terminalOnlyNotice("server_ident", 0), { show: true, offerSetting: false });
});

test("the tooltip says whether the user or the host decided", () => {
  assert.match(unavailableHint("SFTP", "setting"), /^SFTP is off/);
  assert.match(unavailableHint("Docker", "refused_channel"), /^Docker is unavailable/);
});
