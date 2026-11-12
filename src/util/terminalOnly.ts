// A session that runs a plain terminal and nothing beside it: the rules the
// session view follows. The backend decides and enforces this per connection
// (`ssh_connect::ChannelGate`); this only decides what the window shows.

/** Why a connection is terminal only (`ssh_connect::TerminalOnly` in Rust). */
export type TerminalOnlyReason = "setting" | "server_ident" | "refused_channel";

/** Reads the value the backend sent; anything else means no limit. */
export function terminalOnlyReason(value: unknown): TerminalOnlyReason | null {
  return value === "setting" || value === "server_ident" || value === "refused_channel" ? value : null;
}

/** The tools that need a channel beside the terminal. */
export function needsAnotherChannel(tool: string | null): boolean {
  return tool === "sftp" || tool === "info" || tool === "docker";
}

/** The tooltip of a tool that cannot run on this connection. */
export function unavailableHint(label: string, reason: TerminalOnlyReason): string {
  return reason === "setting"
    ? `${label} is off: this server is set to terminal only`
    : `${label} is unavailable: this host allows only a terminal`;
}

/**
 * Whether the window says so, and whether it offers to save the setting. A
 * host found out by detection gets the notice; a server already set to
 * terminal only is what the user asked for. Quick-connect sessions (server id
 * 0) have no saved server to put the setting on.
 */
export function terminalOnlyNotice(reason: TerminalOnlyReason | null, serverId: number): { show: boolean; offerSetting: boolean } {
  const detected = reason === "server_ident" || reason === "refused_channel";
  return { show: detected, offerSetting: detected && serverId > 0 };
}
