// Whether a tunnel rule listens beyond loopback, so that other machines could
// connect to it: on this machine's network for local (L) and dynamic (D)
// tunnels, on the server's network for remote (R) ones. A bare port is
// loopback for every kind (127.0.0.1 here, `localhost` on the server). The
// Rust twin is `tunnel::listens_beyond_loopback` (src-tauri/src/tunnel.rs),
// which decides the `exposed` flag of a running tunnel; keep them in step.

/** The host of "host:port" or "[v6]:port", brackets removed; null for a bare port. */
const bindHost = (local: string): string | null => {
  const s = local.trim();
  if (!s.includes(":")) return null;
  if (s.startsWith("[")) {
    const close = s.indexOf("]");
    return close > 0 ? s.slice(1, close) : s;
  }
  return s.slice(0, s.lastIndexOf(":"));
};

// 127.0.0.0/8 as Rust's parser reads it: four decimal octets up to 255, no
// leading zeros (Rust refuses "127.0.0.01", so it is not loopback there).
const OCTET = "(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
const LOOPBACK_V4 = new RegExp(`^127\\.${OCTET}\\.${OCTET}\\.${OCTET}$`);

const isLoopback = (host: string): boolean => {
  const h = host.toLowerCase();
  return h === "localhost" || h === "::1" || LOOPBACK_V4.test(h);
};

export const listensBeyondLoopback = (local: string): boolean => {
  const host = bindHost(local);
  return host !== null && !isLoopback(host);
};

/** What such a rule exposes, per kind (the Rust side logs the same text). */
export const exposureWarning = (kind: string): string =>
  kind === "R"
    ? "The server is asked to listen beyond its loopback: if its GatewayPorts setting allows it, machines on the server's network can connect to this port."
    : kind === "D"
      ? "Listens beyond loopback: machines that can reach this computer can use this proxy, and with it your SSH session, without a password."
      : "Listens beyond loopback: machines that can reach this computer can connect to this port.";
