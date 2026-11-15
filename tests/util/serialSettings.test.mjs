import test from "node:test";
import assert from "node:assert/strict";
import {
  defaultSerial, serialSummary, serialProblem, isSerialServer, serialFromServer, serialCardLabel, sameSerial,
  COMMON_BAUDS, MIN_BAUD, MAX_BAUD,
} from "./serialSettings.mjs";

test("PuTTY's defaults, and the summary Rust writes too", () => {
  const d = defaultSerial("COM3");
  assert.deepEqual(d, { port: "COM3", baud: 9600, dataBits: 8, parity: "none", stopBits: 1, flow: "none" });
  assert.equal(serialSummary(d), "9600 8N1");
  assert.equal(serialSummary({ ...d, baud: 115200, dataBits: 7, parity: "even", stopBits: 2, flow: "rtscts" }), "115200 7E2 RTS/CTS");
  assert.equal(serialSummary({ ...d, parity: "odd", flow: "xonxoff" }), "9600 8O1 XON/XOFF");
  assert.ok(COMMON_BAUDS.includes(9600) && COMMON_BAUDS.includes(115200));
});

test("the form says what is wrong before saving", () => {
  const ok = defaultSerial("/dev/ttyUSB0");
  assert.equal(serialProblem(ok), null);
  assert.match(serialProblem(defaultSerial("")), /port/);
  assert.match(serialProblem(defaultSerial("  ")), /port/);
  for (const baud of [0, MIN_BAUD - 1, MAX_BAUD + 1, 9600.5, NaN]) {
    assert.match(serialProblem({ ...ok, baud }) ?? "", /speed/, String(baud));
  }
  assert.equal(serialProblem({ ...ok, baud: MIN_BAUD }), null);
  assert.equal(serialProblem({ ...ok, baud: MAX_BAUD }), null);
  assert.match(serialProblem({ ...ok, dataBits: 9 }) ?? "", /Data bits/);
  assert.match(serialProblem({ ...ok, stopBits: 3 }) ?? "", /Stop bits/);
  assert.match(serialProblem({ ...ok, parity: "mark" }) ?? "", /parity/);
  assert.match(serialProblem({ ...ok, flow: "dsrdtr" }) ?? "", /flow/);
});

test("a server row: SSH gives null, serial gives its settings, odd values fall back", () => {
  assert.equal(isSerialServer({ connection_type: "ssh" }), false);
  assert.equal(isSerialServer({}), false, "a row from before schema 7 is SSH");
  assert.equal(isSerialServer(null), false);
  assert.equal(serialFromServer({ connection_type: "ssh", serial: null }), null);
  const row = { connection_type: "serial", serial: { port: "COM3", baud: 115200, dataBits: 7, parity: "even", stopBits: 2, flow: "rtscts" } };
  assert.equal(isSerialServer(row), true);
  assert.deepEqual(serialFromServer(row), row.serial);
  const odd = { connection_type: "serial", serial: { port: "COM3", baud: "fast", parity: "mark", flow: "dsrdtr" } };
  assert.deepEqual(serialFromServer(odd), { ...defaultSerial("COM3") });
  assert.equal(serialFromServer({ connection_type: "serial", serial: null }), null);
});

test("the card shows the port and speed, and the line settings only when they are not 8N1", () => {
  assert.equal(serialCardLabel({ connection_type: "serial", serial: defaultSerial("COM3") }), "COM3 · 9600");
  assert.equal(
    serialCardLabel({ connection_type: "serial", serial: { ...defaultSerial("/dev/ttyUSB0"), baud: 115200, dataBits: 7, parity: "even" } }),
    "/dev/ttyUSB0 · 115200 7E1",
  );
  assert.equal(serialCardLabel({ connection_type: "serial", serial: { ...defaultSerial("COM3"), flow: "rtscts" } }), "COM3 · 9600 8N1 RTS/CTS");
  assert.equal(serialCardLabel({ connection_type: "ssh" }), null);
});

test("the same settings are recognised, any difference is not", () => {
  const a = defaultSerial("COM3");
  assert.equal(sameSerial(a, { ...a }), true);
  for (const change of [{ port: "COM4" }, { baud: 115200 }, { dataBits: 7 }, { parity: "even" }, { stopBits: 2 }, { flow: "rtscts" }]) {
    assert.equal(sameSerial(a, { ...a, ...change }), false, JSON.stringify(change));
  }
});
