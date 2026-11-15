// Serial servers (schema 7): the port and line settings as the window holds
// them, in the shape `save_server` takes and `get_servers` returns
// (serial::SerialSettings in Rust, camelCase). Rust checks every value again
// when saving and when opening; this is for the form to say what is wrong
// before it sends anything, and for the labels.

export type Parity = "none" | "odd" | "even";
export type Flow = "none" | "xonxoff" | "rtscts";

export interface SerialSettings {
  port: string;
  baud: number;
  dataBits: number;
  parity: Parity;
  stopBits: number;
  flow: Flow;
}

export const DEFAULT_BAUD = 9600;
export const MIN_BAUD = 50;
export const MAX_BAUD = 4_000_000;

/** The speeds the picker offers; any other number in range can be typed. */
export const COMMON_BAUDS = [300, 1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600];

export const PARITIES: { value: Parity; label: string }[] = [
  { value: "none", label: "None" },
  { value: "odd", label: "Odd" },
  { value: "even", label: "Even" },
];

export const FLOWS: { value: Flow; label: string }[] = [
  { value: "none", label: "None" },
  { value: "xonxoff", label: "XON/XOFF" },
  { value: "rtscts", label: "RTS/CTS" },
];

/** PuTTY's defaults: 9600 8N1, no flow control. */
export function defaultSerial(port = ""): SerialSettings {
  return { port, baud: DEFAULT_BAUD, dataBits: 8, parity: "none", stopBits: 1, flow: "none" };
}

/** "9600 8N1", "115200 7E2 RTS/CTS" (as `SerialSettings::summary` in Rust). */
export function serialSummary(s: SerialSettings): string {
  const parity = s.parity === "odd" ? "O" : s.parity === "even" ? "E" : "N";
  const flow = s.flow === "xonxoff" ? " XON/XOFF" : s.flow === "rtscts" ? " RTS/CTS" : "";
  return `${s.baud} ${s.dataBits}${parity}${s.stopBits}${flow}`;
}

/** What is wrong with these settings, or null. The port name itself is
 * checked by Rust, which knows what this system calls its ports. */
export function serialProblem(s: SerialSettings): string | null {
  if (!s.port.trim()) return "Choose a serial port.";
  if (!Number.isInteger(s.baud) || s.baud < MIN_BAUD || s.baud > MAX_BAUD) {
    return `The speed must be a whole number between ${MIN_BAUD} and ${MAX_BAUD}.`;
  }
  if (![5, 6, 7, 8].includes(s.dataBits)) return "Data bits must be 5, 6, 7 or 8.";
  if (![1, 2].includes(s.stopBits)) return "Stop bits must be 1 or 2.";
  if (!PARITIES.some((p) => p.value === s.parity)) return "Choose a parity.";
  if (!FLOWS.some((f) => f.value === s.flow)) return "Choose a flow control.";
  return null;
}

/** Whether a row of `get_servers` is a serial server. */
export function isSerialServer(server: { connection_type?: string } | null | undefined): boolean {
  return server?.connection_type === "serial";
}

/** A serial server's settings from its `get_servers` row, or null for SSH.
 * Values the form cannot show (a hand-edited vault) fall back to defaults,
 * which Rust would refuse to open anyway. */
export function serialFromServer(server: { connection_type?: string; serial?: Partial<SerialSettings> | null } | null | undefined): SerialSettings | null {
  if (!isSerialServer(server) || !server?.serial) return null;
  const d = defaultSerial();
  const s = server.serial;
  return {
    port: typeof s.port === "string" ? s.port : d.port,
    baud: typeof s.baud === "number" ? s.baud : d.baud,
    dataBits: typeof s.dataBits === "number" ? s.dataBits : d.dataBits,
    parity: PARITIES.some((p) => p.value === s.parity) ? (s.parity as Parity) : d.parity,
    stopBits: typeof s.stopBits === "number" ? s.stopBits : d.stopBits,
    flow: FLOWS.some((f) => f.value === s.flow) ? (s.flow as Flow) : d.flow,
  };
}

/** What a server card shows under the name: "COM3 · 9600" for a serial
 * server (with the line settings only when they are not 8N1), else null. */
export function serialCardLabel(server: { connection_type?: string; serial?: Partial<SerialSettings> | null }): string | null {
  const s = serialFromServer(server);
  if (!s) return null;
  const summary = serialSummary(s);
  const line = summary.endsWith(" 8N1") ? String(s.baud) : summary;
  return `${s.port} · ${line}`;
}

/** Same settings (a Quick connect to a port already saved reuses it). */
export function sameSerial(a: SerialSettings, b: SerialSettings): boolean {
  return a.port === b.port && a.baud === b.baud && a.dataBits === b.dataBits && a.parity === b.parity
    && a.stopBits === b.stopBits && a.flow === b.flow;
}
