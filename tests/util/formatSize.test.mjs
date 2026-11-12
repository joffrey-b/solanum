import test from "node:test";
import assert from "node:assert/strict";
import { formatSize } from "./formatSize.mjs";

test("sizes keep their format up to TB", () => {
  assert.equal(formatSize(0), "0 B");
  assert.equal(formatSize(512), "512 B");
  assert.equal(formatSize(1536), "1.5 KB");
  assert.equal(formatSize(5 * 1024 ** 4), "5 TB");
});

// R-010: from 1 PiB on the unit came out as "undefined".
test("very large sizes get a unit (R-010)", () => {
  assert.equal(formatSize(1024 ** 5), "1 PB");
  assert.equal(formatSize(3 * 1024 ** 6), "3 EB");
  assert.equal(formatSize(2 ** 80), "1048576 EB");
  assert.equal(formatSize(Number.MAX_VALUE).endsWith(" EB"), true);
});
