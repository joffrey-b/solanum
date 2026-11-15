//! Serial consoles (desktop): a COM port or a `/dev` tty as a terminal tab,
//! with PuTTY's settings (speed, data bits, parity, stop bits, flow control)
//! and Send break.
//!
//! What may be opened (`port_problem`): on Windows `COM<n>`, on Linux the
//! usual serial device names under `/dev` (and the links in `/dev/serial/`
//! that lead to one), on macOS `/dev/cu.*` and `/dev/tty.*`, and anything the
//! system itself lists as a serial port. The rule is checked whatever the
//! window sends, and on Linux and macOS the resolved path must also be a
//! character device: opening some other device file can have effects of its
//! own (a watchdog starts counting when it is opened).
//!
//! One thread per open port does all its I/O (`run_port`): it writes what is
//! queued, then reads with a short timeout. Windows serialises reads and
//! writes on one port handle, so a writer thread beside a blocked reader would
//! wait behind it; one loop behaves the same everywhere, and a key waits at
//! most `IO_TIMEOUT`. Keys wait in the terminal's capped `InputQueue` like any
//! other terminal's.
//!
//! Desktop only: Android reaches USB serial adapters only through its USB
//! host API from Kotlin (owner decision 2026-11-13: not for now). The settings
//! and the name rule build everywhere, because a profile made on a computer
//! can be opened on a phone.

use crate::open_guard::Platform;

pub(crate) const DEFAULT_BAUD: u32 = 9600;
pub(crate) const MIN_BAUD: u32 = 50;
pub(crate) const MAX_BAUD: u32 = 4_000_000;

/// What `serial_send_break` holds the line low for. Cisco's ROMMON and most
/// consoles take anything from 250 ms up.
#[cfg_attr(target_os = "android", allow(dead_code))]
pub(crate) const BREAK_LENGTH: std::time::Duration = std::time::Duration::from_millis(300);

/// Text the window shows, and Android's answer to every serial command.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub(crate) const NOT_ON_ANDROID: &str = "[SERIAL] UNSUPPORTED: serial ports are not available on Android.";

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Parity {
    None,
    Odd,
    Even,
}

impl Parity {
    /// As stored in `servers.serial_parity`.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Parity::None => "none",
            Parity::Odd => "odd",
            Parity::Even => "even",
        }
    }

    #[cfg_attr(target_os = "android", allow(dead_code))]
    pub(crate) fn parse(s: &str) -> Option<Parity> {
        match s {
            "none" => Some(Parity::None),
            "odd" => Some(Parity::Odd),
            "even" => Some(Parity::Even),
            _ => None,
        }
    }

    #[cfg(test)]
    fn letter(self) -> char {
        match self {
            Parity::None => 'N',
            Parity::Odd => 'O',
            Parity::Even => 'E',
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum Flow {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "xonxoff")]
    XonXoff,
    #[serde(rename = "rtscts")]
    RtsCts,
}

impl Flow {
    /// As stored in `servers.serial_flow`.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Flow::None => "none",
            Flow::XonXoff => "xonxoff",
            Flow::RtsCts => "rtscts",
        }
    }

    #[cfg_attr(target_os = "android", allow(dead_code))]
    pub(crate) fn parse(s: &str) -> Option<Flow> {
        match s {
            "none" => Some(Flow::None),
            "xonxoff" => Some(Flow::XonXoff),
            "rtscts" => Some(Flow::RtsCts),
            _ => None,
        }
    }
}

/// How to open a serial port. The window sends it with a node to save; a
/// port is only ever opened with what the vault holds for a saved node.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SerialSettings {
    pub(crate) port: String,
    pub(crate) baud: u32,
    pub(crate) data_bits: u8,
    pub(crate) parity: Parity,
    pub(crate) stop_bits: u8,
    pub(crate) flow: Flow,
}

impl SerialSettings {
    /// PuTTY's defaults: 9600 8N1, no flow control.
    #[cfg(test)]
    pub(crate) fn defaults(port: &str) -> SerialSettings {
        SerialSettings { port: port.into(), baud: DEFAULT_BAUD, data_bits: 8, parity: Parity::None, stop_bits: 1, flow: Flow::None }
    }

    /// "9600 8N1", "115200 7E2 XON/XOFF" (the window has its own, `serialSettings.ts`).
    #[cfg(test)]
    pub(crate) fn summary(&self) -> String {
        let flow = match self.flow {
            Flow::None => "",
            Flow::XonXoff => " XON/XOFF",
            Flow::RtsCts => " RTS/CTS",
        };
        format!("{} {}{}{}{}", self.baud, self.data_bits, self.parity.letter(), self.stop_bits, flow)
    }

    /// The line settings, whatever the port.
    pub(crate) fn line_problem(&self) -> Option<String> {
        if !(MIN_BAUD..=MAX_BAUD).contains(&self.baud) {
            return Some(format!("The speed must be between {MIN_BAUD} and {MAX_BAUD} bits per second."));
        }
        if !(5..=8).contains(&self.data_bits) {
            return Some("Data bits must be 5, 6, 7 or 8.".into());
        }
        if !matches!(self.stop_bits, 1 | 2) {
            return Some("Stop bits must be 1 or 2.".into());
        }
        None
    }

    /// Whether these settings may be saved: sane line settings, and a port
    /// name that is a serial port on some system (a profile moves between
    /// computers: a Windows node keeps `COM3` when it is edited on Linux), or
    /// one this system lists. Opening checks the name again for this system.
    pub(crate) fn save_problem(&self, listed: &[String]) -> Option<String> {
        if let Some(p) = self.line_problem() {
            return Some(p);
        }
        let on_some_system = [Platform::Windows, Platform::Linux, Platform::MacOs]
            .into_iter()
            .any(|platform| port_problem(&self.port, platform, listed).is_none());
        if on_some_system {
            None
        } else {
            port_problem(&self.port, Platform::current(), listed)
        }
    }
}

/// Linux device names that are serial ports: the 16550-style UARTs, USB
/// adapters (FTDI, CP210x, PL2303, CH34x as `ttyUSB`; CDC-ACM as `ttyACM`;
/// Exar), the UARTs of ARM boards (Raspberry Pi, i.MX, Tegra, Samsung,
/// Qualcomm, OMAP), USB gadget serial and Bluetooth RFCOMM. Each is followed by
/// digits. Anything else the system lists as a serial port is accepted too.
const LINUX_PREFIXES: &[&str] = &[
    "ttyS", "ttyUSB", "ttyACM", "ttyAMA", "ttyXRUSB", "ttyCH343USB", "ttymxc", "ttyTHS", "ttySAC", "ttyHS", "ttyMSM",
    "ttyO", "ttyGS", "ttyLP", "rfcomm",
];

/// `prefix` followed by one or more ASCII digits and nothing else.
fn numbered(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix).is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// A file name in a device folder: no separator, not `.` or `..`.
fn plain_leaf(leaf: &str) -> bool {
    !leaf.is_empty() && leaf != "." && leaf != ".." && !leaf.contains('/') && !leaf.contains('\\')
}

fn linux_name_ok(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("/dev/") else { return false };
    if let Some(leaf) = rest.strip_prefix("serial/by-id/").or_else(|| rest.strip_prefix("serial/by-path/")) {
        return plain_leaf(leaf);
    }
    plain_leaf(rest) && LINUX_PREFIXES.iter().any(|p| numbered(rest, p))
}

fn macos_name_ok(name: &str) -> bool {
    name.strip_prefix("/dev/cu.").or_else(|| name.strip_prefix("/dev/tty.")).is_some_and(plain_leaf)
}

/// `COM1` to `COM256`, with or without the `\\.\` device prefix, any case.
fn windows_name_ok(name: &str) -> bool {
    let bare = if name.len() >= 4 && name[..4].eq_ignore_ascii_case(r"\\.\") { &name[4..] } else { name };
    if bare.len() < 4 || !bare[..3].eq_ignore_ascii_case("COM") {
        return false;
    }
    let digits = &bare[3..];
    !digits.starts_with('0')
        && digits.bytes().all(|b| b.is_ascii_digit())
        && digits.parse::<u32>().is_ok_and(|n| (1..=256).contains(&n))
}

/// Why `name` may not be opened as a serial port on `platform`, or `None`.
/// `listed`: the ports the system reports right now (`list_ports`), which are
/// accepted whatever their name (a virtual port pair such as com0com's
/// `CNCA0`, an unusual Linux driver).
pub(crate) fn port_problem(name: &str, platform: Platform, listed: &[String]) -> Option<String> {
    if name.trim().is_empty() {
        return Some("Choose a serial port.".into());
    }
    if name.len() > 255 || name.chars().any(|c| c.is_control()) || name != name.trim() {
        return Some("That is not a serial port name.".into());
    }
    if listed.iter().any(|l| l == name) {
        return None;
    }
    let ok = match platform {
        Platform::Windows => windows_name_ok(name),
        Platform::Linux => linux_name_ok(name),
        Platform::MacOs => macos_name_ok(name),
    };
    if ok {
        return None;
    }
    Some(match platform {
        Platform::Windows => format!("\"{}\" is not a serial port: use a name such as COM3.", crate::open_guard::visible_text(name)),
        Platform::Linux => format!(
            "\"{}\" is not a serial port: use a device such as /dev/ttyUSB0, /dev/ttyACM0 or /dev/ttyS0.",
            crate::open_guard::visible_text(name)
        ),
        Platform::MacOs => format!(
            "\"{}\" is not a serial port: use a device such as /dev/cu.usbserial-1410.",
            crate::open_guard::visible_text(name)
        ),
    })
}

/// What the SSH-only paths (connecting, jump hosts, monitors) say about a
/// serial server.
pub(crate) const NOT_SSH: &str = "[SERIAL] NOT_SSH: this server is a serial port: it has no SSH connection, so no tunnels, monitor or jump host.";

/// Whether a saved server is a serial port (`false` for a missing row, which
/// the caller reports in its own way).
pub(crate) fn is_serial_server(conn: &rusqlite::Connection, id: i64) -> bool {
    conn.query_row("SELECT connection_type = 'serial' FROM servers WHERE id = ?1", [id], |r| r.get::<_, bool>(0))
        .unwrap_or(false)
}

/// A saved serial server's settings, from the vault (a port is never opened
/// with settings the window sends). Values a hand-edited vault could hold out
/// of range are refused here as well as when saving.
#[cfg_attr(target_os = "android", allow(dead_code))]
pub(crate) fn settings_of_server(conn: &rusqlite::Connection, id: i64) -> Result<SerialSettings, String> {
    type Row = (String, String, i64, i64, String, i64, String);
    let row: Row = conn
        .query_row(
            "SELECT connection_type, serial_port, serial_baud, serial_data_bits, serial_parity, serial_stop_bits, serial_flow FROM servers WHERE id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?)),
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => "[SERIAL] NOT_FOUND: this server no longer exists.".to_string(),
            other => format!("[DATABASE] SERIAL_READ_FAILED: {other}"),
        })?;
    let (kind, port, baud, data_bits, parity, stop_bits, flow) = row;
    if kind != "serial" {
        return Err("[SERIAL] NOT_SERIAL: this server is not a serial port.".into());
    }
    let invalid = || "[SERIAL] SETTINGS_REFUSED: this server's serial settings are not valid; edit them.".to_string();
    let settings = SerialSettings {
        port,
        baud: u32::try_from(baud).map_err(|_| invalid())?,
        data_bits: u8::try_from(data_bits).map_err(|_| invalid())?,
        parity: Parity::parse(&parity).ok_or_else(invalid)?,
        stop_bits: u8::try_from(stop_bits).map_err(|_| invalid())?,
        flow: Flow::parse(&flow).ok_or_else(invalid)?,
    };
    if settings.line_problem().is_some() {
        return Err(invalid());
    }
    Ok(settings)
}

/// One port in the picker.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct PortEntry {
    pub(crate) name: String,
    /// The adapter's product and maker for a USB port (as its firmware names
    /// itself, made safe to show), else the kind of port, else empty.
    pub(crate) description: String,
}

#[cfg(not(target_os = "android"))]
pub(crate) use desktop::*;

#[cfg(not(target_os = "android"))]
mod desktop {
    use super::*;
    use crate::ssh_manager::PtySize;
    use crate::terminal_io::{Input, InputQueue, Queued, TerminalIo};
    use std::collections::VecDeque;
    use std::io::{self, Read, Write};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc as std_mpsc, Arc, Mutex};
    use std::time::Duration;

    /// How long a read waits for data before the loop writes queued keys
    /// and looks at its stop flag again.
    pub(crate) const IO_TIMEOUT: Duration = Duration::from_millis(20);

    /// What `end` waits for the port's thread, at most.
    const STOP_WAIT: Duration = Duration::from_secs(2);

    /// The ports this system reports, USB adapters first. On Linux the list
    /// is read from `/sys/class/tty` (serialport without libudev), which
    /// serialport `expect()`s to exist: it is checked first, so a system
    /// without it (a container) gets an empty list, not a panic.
    pub(crate) fn list_ports() -> Vec<PortEntry> {
        if cfg!(target_os = "linux") && !std::path::Path::new("/sys/class/tty").is_dir() {
            return Vec::new();
        }
        let Ok(ports) = serialport::available_ports() else { return Vec::new() };
        let ports = ports.into_iter().filter(|p| !placeholder_uart(&p.port_name));
        let visible = crate::open_guard::visible_text;
        let mut entries: Vec<(bool, PortEntry)> = ports
            .into_iter()
            .map(|p| {
                let (usb, description) = match &p.port_type {
                    serialport::SerialPortType::UsbPort(u) => {
                        let text = |s: &Option<String>| s.as_deref().map(str::trim).filter(|s| !s.is_empty()).map(visible);
                        let name = match (text(&u.manufacturer), text(&u.product)) {
                            // "FTDI FT232R USB UART", not "FTDI FTDI FT232R..." when the product names its maker.
                            (Some(maker), Some(product)) if product.contains(&maker) => product,
                            (Some(maker), Some(product)) => format!("{maker} {product}"),
                            (one, other) => one.or(other).unwrap_or_else(|| "USB serial".into()),
                        };
                        (true, format!("{name} (USB {:04x}:{:04x})", u.vid, u.pid))
                    }
                    serialport::SerialPortType::PciPort => (false, "PCI serial port".to_string()),
                    serialport::SerialPortType::BluetoothPort => (false, "Bluetooth".to_string()),
                    serialport::SerialPortType::Unknown => (false, String::new()),
                };
                (usb, PortEntry { name: visible(&p.port_name), description })
            })
            .collect();
        entries.sort_by(|(a_usb, a), (b_usb, b)| b_usb.cmp(a_usb).then_with(|| natural(&a.name).cmp(&natural(&b.name))));
        entries.dedup_by(|a, b| a.1.name == b.1.name);
        entries.into_iter().map(|(_, e)| e).collect()
    }

    /// Linux registers UART slots whether or not a chip is behind them (32
    /// `ttyS` on a common kernel): such a slot's `type` reads 0 ("unknown").
    /// They are left out of the list; a name typed by hand is still opened.
    fn placeholder_uart(name: &str) -> bool {
        if !cfg!(target_os = "linux") {
            return false;
        }
        let Some(leaf) = name.strip_prefix("/dev/").filter(|l| plain_leaf(l)) else { return false };
        std::fs::read_to_string(format!("/sys/class/tty/{leaf}/type")).is_ok_and(|t| t.trim() == "0")
    }

    /// Sorts `COM10` after `COM9` and `ttyUSB10` after `ttyUSB2`.
    fn natural(name: &str) -> (String, u64) {
        let digits = name.len() - name.bytes().rev().take_while(u8::is_ascii_digit).count();
        (name[..digits].to_ascii_lowercase(), name[digits..].parse().unwrap_or(0))
    }

    /// The names `list_ports` reports, to accept whatever the system lists.
    pub(crate) fn listed_names() -> Vec<String> {
        list_ports().into_iter().map(|p| p.name).collect()
    }

    /// Linux and macOS: the device file `name` leads to must itself be a
    /// serial port by name (or listed) and a character device. Follows the
    /// links in `/dev/serial/by-id/`.
    #[cfg(unix)]
    fn checked_device(name: &str, platform: Platform, listed: &[String]) -> Result<(), String> {
        use std::os::unix::fs::FileTypeExt;
        let shown = crate::open_guard::visible_text(name);
        let resolved = std::fs::canonicalize(name).map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => format!("[SERIAL] NOT_FOUND: {shown} does not exist. Is the adapter plugged in?"),
            _ => format!("[SERIAL] OPEN_FAILED: {shown}: {e}"),
        })?;
        let resolved_str = resolved.to_string_lossy();
        if resolved_str != name {
            if let Some(problem) = port_problem(&resolved_str, platform, listed) {
                return Err(format!("[SERIAL] NOT_A_PORT: {shown} leads to {}: {problem}", crate::open_guard::visible_text(&resolved_str)));
            }
        }
        let meta = std::fs::metadata(&resolved).map_err(|e| format!("[SERIAL] OPEN_FAILED: {shown}: {e}"))?;
        if !meta.file_type().is_char_device() {
            return Err(format!("[SERIAL] NOT_A_PORT: {shown} is not a device."));
        }
        Ok(())
    }

    /// The group that owns a device, to name it when opening is refused.
    #[cfg(unix)]
    fn owning_group(name: &str) -> Option<String> {
        use std::os::unix::fs::MetadataExt;
        let gid = std::fs::metadata(name).ok()?.gid();
        let groups = std::fs::read_to_string("/etc/group").ok()?;
        groups.lines().find_map(|line| {
            let mut fields = line.split(':');
            let group = fields.next()?;
            let _password = fields.next()?;
            (fields.next()?.parse::<u32>().ok()? == gid).then(|| group.to_string())
        })
    }

    /// What a failed open means, in words the user can act on.
    fn open_error(name: &str, e: serialport::Error, listed: &[String]) -> String {
        let shown = crate::open_guard::visible_text(name);
        let detail = crate::open_guard::visible_text(&e.description);
        match e.kind() {
            // Unix: EBUSY or the lock of another opener. Windows: also a port
            // that does not exist, or access denied (which is what a port in
            // use by another program gives); the list tells them apart.
            serialport::ErrorKind::NoDevice if cfg!(unix) || listed.iter().any(|l| l == name) => {
                format!("[SERIAL] BUSY: {shown} is in use by another program (or another Solanum tab).")
            }
            serialport::ErrorKind::NoDevice | serialport::ErrorKind::Io(io::ErrorKind::NotFound) => {
                format!("[SERIAL] NOT_FOUND: {shown} was not found. Is the adapter plugged in?")
            }
            serialport::ErrorKind::Io(io::ErrorKind::PermissionDenied) => {
                #[cfg(unix)]
                if let Some(group) = owning_group(name).filter(|g| g != "root") {
                    return format!(
                        "[SERIAL] PERMISSION_DENIED: you may not open {shown}: it belongs to the group \"{group}\". \
                         Add yourself with `sudo usermod -aG {group} $USER`, then log out and back in."
                    );
                }
                format!("[SERIAL] PERMISSION_DENIED: you may not open {shown} ({detail}).")
            }
            serialport::ErrorKind::InvalidInput => {
                format!("[SERIAL] SETTINGS_REFUSED: {shown} does not accept these settings ({detail}).")
            }
            _ => format!("[SERIAL] OPEN_FAILED: {shown}: {detail}"),
        }
    }

    /// Opens a port as a terminal. Blocking (call it off the async runtime).
    pub(crate) fn open(settings: &SerialSettings) -> Result<SerialTerminal, String> {
        let platform = Platform::current();
        let listed = listed_names();
        if let Some(problem) = port_problem(&settings.port, platform, &listed) {
            return Err(format!("[SERIAL] NOT_A_PORT: {problem}"));
        }
        if let Some(problem) = settings.line_problem() {
            return Err(format!("[SERIAL] SETTINGS_REFUSED: {problem}"));
        }
        #[cfg(unix)]
        checked_device(&settings.port, platform, &listed)?;

        let port = serialport::new(&settings.port, settings.baud)
            .data_bits(match settings.data_bits {
                5 => serialport::DataBits::Five,
                6 => serialport::DataBits::Six,
                7 => serialport::DataBits::Seven,
                _ => serialport::DataBits::Eight,
            })
            .parity(match settings.parity {
                Parity::None => serialport::Parity::None,
                Parity::Odd => serialport::Parity::Odd,
                Parity::Even => serialport::Parity::Even,
            })
            .stop_bits(if settings.stop_bits == 2 { serialport::StopBits::Two } else { serialport::StopBits::One })
            .flow_control(match settings.flow {
                Flow::None => serialport::FlowControl::None,
                Flow::XonXoff => serialport::FlowControl::Software,
                Flow::RtsCts => serialport::FlowControl::Hardware,
            })
            .timeout(IO_TIMEOUT)
            .open()
            .map_err(|e| open_error(&settings.port, e, &listed))?;
        Ok(SerialTerminal::start(port, settings.flow))
    }

    /// What the window asks of a port, in order. A chunk's `Queued` place in
    /// the input queue is given back when the chunk is dropped (written, or
    /// the port ended).
    enum ToPort {
        Data(Vec<u8>, #[allow(dead_code)] Queued),
        Break(tokio::sync::oneshot::Sender<Result<(), String>>),
    }

    /// An open port as a terminal (`terminal_io::pump` runs it).
    pub(crate) struct SerialTerminal {
        output: tokio::sync::mpsc::Receiver<Vec<u8>>,
        to_port: Option<std_mpsc::Sender<ToPort>>,
        queue: InputQueue,
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
        why: Arc<Mutex<Option<String>>>,
    }

    impl SerialTerminal {
        /// Runs `port` on a thread of its own. DTR goes up, as PuTTY does, and
        /// RTS too unless the hardware flow control drives it.
        pub(crate) fn start(mut port: Box<dyn serialport::SerialPort>, flow: Flow) -> SerialTerminal {
            let _ = port.write_data_terminal_ready(true);
            if flow != Flow::RtsCts {
                let _ = port.write_request_to_send(true);
            }
            let (out_tx, out_rx) = tokio::sync::mpsc::channel(64);
            let (to_port, from_window) = std_mpsc::channel();
            let stop = Arc::new(AtomicBool::new(false));
            let why = Arc::new(Mutex::new(None));
            let thread = {
                let (stop, why) = (Arc::clone(&stop), Arc::clone(&why));
                std::thread::Builder::new()
                    .name("solanum-serial".into())
                    .spawn(move || run_port(port, from_window, out_tx, stop, why))
                    .ok()
            };
            SerialTerminal { output: out_rx, to_port: Some(to_port), queue: InputQueue::default(), stop, thread, why }
        }

        /// Why the port ended by itself (it went away, an I/O error), once
        /// its output has ended. Read before the terminal is handed to `pump`.
        pub(crate) fn why_ended(&self) -> Arc<Mutex<Option<String>>> {
            Arc::clone(&self.why)
        }
    }

    impl Drop for SerialTerminal {
        /// The thread stops at its next turn and closes the port.
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
        }
    }

    /// A timeout or an interrupted call: try again on the next turn.
    fn transient(e: &io::Error) -> bool {
        matches!(e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted)
    }

    /// Holds the line low for `BREAK_LENGTH`, unless the terminal is closed meanwhile.
    fn send_break(port: &dyn serialport::SerialPort, stop: &AtomicBool) -> Result<(), String> {
        port.set_break().map_err(|e| format!("[SERIAL] BREAK_FAILED: this port did not send a break ({}).", crate::open_guard::visible_text(&e.description)))?;
        let until = std::time::Instant::now() + BREAK_LENGTH;
        while std::time::Instant::now() < until && !stop.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(10));
        }
        port.clear_break().map_err(|e| format!("[SERIAL] BREAK_FAILED: {}", crate::open_guard::visible_text(&e.description)))
    }

    /// The port's thread: queued keys and breaks go out in order, one write
    /// call per turn (so reading goes on while a device holds the line with
    /// XOFF or CTS), and what comes in goes to the terminal. Ends when the
    /// terminal stops it or goes away, or when the port fails (`why`); the
    /// port closes when it returns.
    fn run_port(
        mut port: Box<dyn serialport::SerialPort>,
        from_window: std_mpsc::Receiver<ToPort>,
        output: tokio::sync::mpsc::Sender<Vec<u8>>,
        stop: Arc<AtomicBool>,
        why: Arc<Mutex<Option<String>>>,
    ) {
        let fail = |what: &str, e: &dyn std::fmt::Display| {
            *why.lock().unwrap_or_else(|p| p.into_inner()) =
                Some(format!("{what}: {}", crate::open_guard::visible_text(&e.to_string())));
        };
        let mut pending: VecDeque<ToPort> = VecDeque::new();
        let mut written = 0usize;
        let mut window_gone = false;
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            if stop.load(Ordering::SeqCst) {
                return;
            }
            loop {
                match from_window.try_recv() {
                    Ok(m) => pending.push_back(m),
                    Err(std_mpsc::TryRecvError::Empty) => break,
                    Err(std_mpsc::TryRecvError::Disconnected) => {
                        window_gone = true;
                        break;
                    }
                }
            }
            if window_gone && pending.is_empty() {
                return;
            }
            let mut progressed = false;
            match pending.front() {
                Some(ToPort::Data(data, _)) => match port.write(&data[written..]) {
                    Ok(n) => {
                        progressed = n > 0;
                        written += n;
                        if written >= data.len() {
                            pending.pop_front();
                            written = 0;
                        }
                    }
                    Err(e) if transient(&e) => {}
                    Err(e) => return fail("Writing to the port failed", &e),
                },
                Some(ToPort::Break(_)) => {
                    if let Some(ToPort::Break(reply)) = pending.pop_front() {
                        let _ = reply.send(send_break(&*port, &stop));
                        progressed = true;
                    }
                }
                None => {}
            }
            // More to write: read only what is already there, then write again.
            if progressed && !pending.is_empty() && port.bytes_to_read().unwrap_or(1) == 0 {
                continue;
            }
            match port.read(&mut buf) {
                // Linux and macOS: readable with nothing to read is a hang-up.
                Ok(0) => return fail("The port hung up", &"no more data"),
                Ok(n) => {
                    if output.blocking_send(buf[..n].to_vec()).is_err() {
                        return;
                    }
                }
                Err(e) if transient(&e) => {}
                Err(e) => return fail("The port went away", &e),
            }
        }
    }

    impl TerminalIo for SerialTerminal {
        async fn next_output(&mut self) -> Option<Vec<u8>> {
            self.output.recv().await
        }

        async fn send_input(&mut self, data: Vec<u8>) -> Input {
            let place = match self.queue.admit(data.len()) {
                Ok(place) => place,
                Err(refused) => return refused,
            };
            match &self.to_port {
                Some(to_port) if to_port.send(ToPort::Data(data, place)).is_ok() => Input::Accepted,
                _ => Input::Gone,
            }
        }

        /// A serial line has no window size.
        async fn resize_pty(&mut self, _size: PtySize) {}

        /// Stops the thread and waits until the port is closed, so it can be
        /// opened again at once (Reconnect).
        async fn end(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            self.to_port = None;
            if let Some(thread) = self.thread.take() {
                let joined = tokio::task::spawn_blocking(move || thread.join());
                let _ = tokio::time::timeout(STOP_WAIT, joined).await;
            }
        }

        /// The other end of a serial line cannot end it: output that stops
        /// means the port went away.
        fn ended_by_peer(&self) -> bool {
            false
        }

        async fn send_break(&mut self, reply: tokio::sync::oneshot::Sender<Result<(), String>>) {
            match &self.to_port {
                Some(to_port) => {
                    if let Err(std_mpsc::SendError(ToPort::Break(reply))) = to_port.send(ToPort::Break(reply)) {
                        let _ = reply.send(Err("[SERIAL] CLOSED: the port is closed.".into()));
                    }
                }
                None => {
                    let _ = reply.send(Err("[SERIAL] CLOSED: the port is closed.".into()));
                }
            }
        }
    }

    /// The line shown when a port ended by itself. CAN first, as for the
    /// terminal loop's own notices.
    pub(crate) fn ended_notice(port: &str, why: &str) -> String {
        format!(
            "\x18\x1b[0m\r\n\x1b[33m[Solanum: {} closed. {}. Press R or Reconnect to open it again.]\x1b[0m\r\n",
            crate::open_guard::visible_text(port),
            why
        )
    }
}

/// The names of the ports this system lists, for `save_server` (none on Android).
pub(crate) async fn listed_ports() -> Vec<String> {
    #[cfg(target_os = "android")]
    {
        Vec::new()
    }
    #[cfg(not(target_os = "android"))]
    {
        tokio::task::spawn_blocking(listed_names).await.unwrap_or_default()
    }
}

/// Registers an open port as terminal `terminal_id` and runs it until it
/// ends: output to `emit`, then `on_end` with how it ended and, for a port
/// that went away, why. Refused (and the port closed) if a profile lock began
/// since `epoch` was taken. No `AppHandle` here: the command hands it in as
/// the two callbacks, so the unit tests can run this.
#[cfg(not(target_os = "android"))]
pub(crate) async fn run_terminal(
    state: &crate::ssh_manager::SshState,
    epoch: &crate::ssh_manager::ProfileEpoch,
    terminal_id: String,
    mut io: SerialTerminal,
    log: Option<tokio::fs::File>,
    emit: impl FnMut(&[u8]) + Send + 'static,
    on_end: impl FnOnce(crate::terminal_io::Ended, Option<String>) + Send + 'static,
) -> Result<(), String> {
    use crate::ssh_manager::{PtySize, TerminalCommand};
    use crate::terminal_io::TerminalIo;
    let why = io.why_ended();
    let (tx, rx) = tokio::sync::mpsc::channel::<TerminalCommand>(32);
    let (resize_tx, resize_rx) = tokio::sync::watch::channel(PtySize { cols: 80, rows: 24 });
    {
        // Checked under the map's lock: a teardown that began meanwhile has
        // cleared it, or will clear it after this insert.
        let mut txs = state.terminal_txs.lock().await;
        if !epoch.current() {
            drop(txs);
            io.end().await;
            return Err(crate::ssh_manager::PROFILE_CLOSING_MSG.into());
        }
        txs.insert(terminal_id.clone(), tx);
    }
    state.resize_txs.lock().await.insert(terminal_id.clone(), resize_tx);
    let (txs, resizes) = (std::sync::Arc::clone(&state.terminal_txs), std::sync::Arc::clone(&state.resize_txs));
    tokio::spawn(async move {
        let ended = crate::terminal_io::pump(io, rx, resize_rx, log, emit).await;
        let reason = why.lock().unwrap_or_else(|p| p.into_inner()).take();
        crate::ssh_manager::forget_ended_terminal(&txs, &resizes, &terminal_id).await;
        on_end(ended, reason);
    });
    Ok(())
}

/// Send break on terminal `terminal_id`, after the keys queued before it;
/// answers once the line is back up.
pub(crate) async fn send_break_to(state: &crate::ssh_manager::SshState, terminal_id: &str) -> Result<(), String> {
    use crate::ssh_manager::TerminalCommand;
    let closed = || "[SERIAL] CLOSED: the port is closed.".to_string();
    let tx = state.terminal_txs.lock().await.get(terminal_id).cloned().ok_or_else(closed)?;
    let (reply, answer) = tokio::sync::oneshot::channel();
    tx.send(TerminalCommand::Break(reply)).await.map_err(|_| closed())?;
    match tokio::time::timeout(std::time::Duration::from_secs(10), answer).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(closed()),
        Err(_) => Err("[SERIAL] BREAK_FAILED: the break did not go out within 10 seconds: the device has not taken the keys sent before it.".into()),
    }
}

/// The ports for the picker, USB adapters first (none on Android).
#[tauri::command]
pub async fn list_serial_ports() -> Result<Vec<PortEntry>, String> {
    #[cfg(target_os = "android")]
    {
        Ok(Vec::new())
    }
    #[cfg(not(target_os = "android"))]
    {
        tokio::task::spawn_blocking(list_ports).await.map_err(|e| format!("[SERIAL] LIST_FAILED: {e}"))
    }
}

/// Opens saved server `server_id`'s serial port as terminal `terminal_id`.
/// The port and its settings come from the vault, never from the window.
/// Returns why the session log could not be started, if it could not.
#[tauri::command]
pub async fn open_serial_terminal(
    app: tauri::AppHandle,
    state: tauri::State<'_, crate::ssh_manager::SshState>,
    db: tauri::State<'_, crate::DbState>,
    terminal_id: String,
    server_id: i64,
    log_file_path: Option<String>,
) -> Result<Option<String>, String> {
    #[cfg(target_os = "android")]
    {
        let _ = (&app, &state, &db, &terminal_id, server_id, &log_file_path);
        Err(NOT_ON_ANDROID.into())
    }
    #[cfg(not(target_os = "android"))]
    {
        use tauri::Emitter;
        let epoch = state.epoch();
        if epoch.closing() {
            return Err(crate::ssh_manager::PROFILE_CLOSING_MSG.into());
        }
        let settings = {
            let guard = db.conn.lock().map_err(|_| "[STATE] LOCK_FAILED")?;
            let conn = guard.as_ref().ok_or("[STATE] DATABASE_NOT_INITIALIZED")?;
            settings_of_server(conn, server_id)?
        };
        let port = settings.port.clone();
        let io = tokio::task::spawn_blocking(move || open(&settings))
            .await
            .map_err(|e| format!("[SERIAL] OPEN_FAILED: {e}"))??;
        let (log, log_problem) = crate::ssh_manager::start_session_log(&log_file_path).await;
        let (out_app, out_id) = (app.clone(), terminal_id.clone());
        let end_id = terminal_id.clone();
        run_terminal(
            &state,
            &epoch,
            terminal_id,
            io,
            log,
            move |bytes: &[u8]| crate::ssh_manager::emit_terminal_batch(&out_app, &out_id, bytes),
            move |ended, why| {
                let lost = ended == crate::terminal_io::Ended::Lost;
                if lost {
                    let why = why.unwrap_or_else(|| "It stopped answering".into());
                    crate::ssh_manager::emit_terminal_batch(&app, &end_id, ended_notice(&port, &why).as_bytes());
                }
                let _ = app.emit(&format!("terminal-closed-{end_id}"), serde_json::json!({ "lost": lost }));
            },
        )
        .await?;
        Ok(log_problem)
    }
}

/// Send break on an open serial terminal (`BREAK_LENGTH`).
#[tauri::command]
pub async fn serial_send_break(state: tauri::State<'_, crate::ssh_manager::SshState>, terminal_id: String) -> Result<(), String> {
    send_break_to(&state, &terminal_id).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn none() -> Vec<String> {
        Vec::new()
    }

    #[test]
    fn windows_takes_com_ports_only() {
        for ok in ["COM1", "COM3", "com12", "COM256", r"\\.\COM10", r"\\.\com4"] {
            assert_eq!(port_problem(ok, Platform::Windows, &none()), None, "{ok}");
        }
        for bad in [
            "COM0", "COM257", "COM03", "COM", "COM1a", "LPT1", "CON", "NUL", r"\\.\PhysicalDrive0", r"\\.\C:", "C:\\x",
            "/dev/ttyUSB0", "COM 1", " COM1", "COM1\n", r"\\?\COM1",
        ] {
            assert!(port_problem(bad, Platform::Windows, &none()).is_some(), "{bad:?}");
        }
    }

    #[test]
    fn linux_takes_serial_devices_and_their_by_id_links() {
        for ok in [
            "/dev/ttyS0", "/dev/ttyUSB0", "/dev/ttyUSB12", "/dev/ttyACM1", "/dev/ttyAMA0", "/dev/ttyXRUSB0", "/dev/rfcomm0",
            "/dev/ttyTHS1", "/dev/ttymxc2", "/dev/serial/by-id/usb-FTDI_FT232R_USB_UART_A50285BI-if00-port0",
            "/dev/serial/by-path/pci-0000:00:14.0-usb-0:2:1.0-port0",
        ] {
            assert_eq!(port_problem(ok, Platform::Linux, &none()), None, "{ok}");
        }
        for bad in [
            "/dev/tty", "/dev/tty1", "/dev/tty63", "/dev/console", "/dev/ptmx", "/dev/pts/3", "/dev/sda", "/dev/watchdog",
            "/dev/mem", "/dev/ttyUSB", "/dev/ttyUSB0x", "/dev/../dev/ttyUSB0", "/dev/serial/by-id/", "/dev/serial/by-id/..",
            "/dev/serial/by-id/a/b", "/etc/passwd", "ttyUSB0", "/home/u/ttyUSB0", "COM3", "",
        ] {
            assert!(port_problem(bad, Platform::Linux, &none()).is_some(), "{bad:?}");
        }
    }

    #[test]
    fn macos_takes_cu_and_tty_devices() {
        for ok in ["/dev/cu.usbserial-1410", "/dev/tty.usbserial-1410", "/dev/cu.SLAB_USBtoUART", "/dev/cu.Bluetooth-Incoming-Port"] {
            assert_eq!(port_problem(ok, Platform::MacOs, &none()), None, "{ok}");
        }
        for bad in ["/dev/tty", "/dev/cu.", "/dev/ttys003", "/dev/disk0", "/dev/cu.a/b", "/dev/cu..", "COM3", "/dev/ttyUSB0"] {
            assert!(port_problem(bad, Platform::MacOs, &none()).is_some(), "{bad:?}");
        }
    }

    #[test]
    fn a_port_the_system_lists_is_taken_whatever_its_name() {
        let listed = vec!["CNCA0".to_string(), "/dev/ttyWCH0".to_string()];
        assert_eq!(port_problem("CNCA0", Platform::Windows, &listed), None);
        assert_eq!(port_problem("/dev/ttyWCH0", Platform::Linux, &listed), None);
        assert!(port_problem("CNCB0", Platform::Windows, &listed).is_some(), "only what is listed");
        assert!(port_problem("CNCA0\0", Platform::Windows, &listed).is_some(), "control characters never");
        assert!(port_problem("", Platform::Windows, &[String::new()]).is_some(), "an empty name never");
    }

    #[test]
    fn line_settings_have_bounds() {
        let ok = SerialSettings::defaults("COM3");
        assert_eq!(ok.line_problem(), None);
        assert_eq!(ok.summary(), "9600 8N1");
        let s = |f: &dyn Fn(&mut SerialSettings)| {
            let mut s = SerialSettings::defaults("COM3");
            f(&mut s);
            s
        };
        assert_eq!(s(&|s| { s.baud = 115_200; s.data_bits = 7; s.parity = Parity::Even; s.stop_bits = 2; s.flow = Flow::RtsCts }).summary(), "115200 7E2 RTS/CTS");
        assert_eq!(s(&|s| s.flow = Flow::XonXoff).summary(), "9600 8N1 XON/XOFF");
        for bad in [
            s(&|s| s.baud = 49), s(&|s| s.baud = 4_000_001), s(&|s| s.baud = 0), s(&|s| s.data_bits = 4), s(&|s| s.data_bits = 9),
            s(&|s| s.stop_bits = 0), s(&|s| s.stop_bits = 3),
        ] {
            assert!(bad.line_problem().is_some(), "{bad:?}");
        }
        assert_eq!(s(&|s| s.baud = MIN_BAUD).line_problem(), None);
        assert_eq!(s(&|s| s.baud = MAX_BAUD).line_problem(), None);
    }

    /// A profile moves between computers: a node keeps a port name of
    /// another system when it is saved here, and only opening it fails.
    #[test]
    fn a_port_of_another_system_can_be_saved() {
        for port in ["COM3", "/dev/ttyUSB0", "/dev/cu.usbserial-1410"] {
            assert_eq!(SerialSettings::defaults(port).save_problem(&[]), None, "{port}");
        }
        for port in ["", "/etc/passwd", "/dev/sda", r"\\.\PhysicalDrive0", "LPT1"] {
            assert!(SerialSettings::defaults(port).save_problem(&[]).is_some(), "{port:?}");
        }
        let mut slow = SerialSettings::defaults("COM3");
        slow.baud = 10;
        assert!(slow.save_problem(&[]).is_some());
    }

    #[test]
    fn stored_names_round_trip() {
        for p in [Parity::None, Parity::Odd, Parity::Even] {
            assert_eq!(Parity::parse(p.as_str()), Some(p));
        }
        for f in [Flow::None, Flow::XonXoff, Flow::RtsCts] {
            assert_eq!(Flow::parse(f.as_str()), Some(f));
        }
        assert_eq!(Parity::parse("mark"), None);
        assert_eq!(Flow::parse("dsrdtr"), None);
        let json = serde_json::json!({"port": "COM3", "baud": 9600, "dataBits": 8, "parity": "even", "stopBits": 1, "flow": "rtscts"});
        let s: SerialSettings = serde_json::from_value(json).unwrap();
        assert_eq!((s.parity, s.flow), (Parity::Even, Flow::RtsCts));
        assert!(serde_json::from_value::<SerialSettings>(serde_json::json!({"port": "COM3", "baud": 9600, "dataBits": 8, "parity": "mark", "stopBits": 1, "flow": "none"})).is_err());
    }

    /// Prints what the picker would show on this machine (plug an adapter in
    /// to see its entry): `cargo test --lib -- --ignored --nocapture this_machines_ports`.
    #[cfg(not(target_os = "android"))]
    #[test]
    #[ignore = "prints this machine's serial ports"]
    fn this_machines_ports() {
        for p in list_ports() {
            println!("{:<40} {}", p.name, p.description);
        }
    }

    /// A real serial terminal on a pseudo-terminal pair: the test holds the
    /// "device" end.
    #[cfg(unix)]
    mod on_a_pty_pair {
        use super::super::*;
        use crate::ssh_manager::{PtySize, TerminalCommand};
        use crate::terminal_io::{pump, Ended, TerminalIo};
        use std::io::{Read, Write};
        use std::time::{Duration, Instant};

        /// Reads from the device end until `want` has arrived or 5 s passed.
        fn device_reads(device: &mut serialport::TTYPort, want: &[u8]) -> Vec<u8> {
            let mut got = Vec::new();
            let mut buf = [0u8; 4096];
            let until = Instant::now() + Duration::from_secs(5);
            while Instant::now() < until && !got.windows(want.len()).any(|w| w == want) {
                match device.read(&mut buf) {
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                    Err(_) => std::thread::sleep(Duration::from_millis(5)),
                }
            }
            got
        }

        fn pair() -> (serialport::TTYPort, SerialTerminal) {
            use serialport::SerialPort;
            let (mut device, mut ours) = serialport::TTYPort::pair().expect("a pseudo-terminal pair");
            device.set_timeout(Duration::from_millis(50)).unwrap();
            ours.set_timeout(IO_TIMEOUT).unwrap();
            (device, SerialTerminal::start(Box::new(ours), Flow::None))
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn output_and_keys_go_through_the_terminal_loop() {
            let (mut device, io) = pair();
            let (input, input_rx) = tokio::sync::mpsc::channel(32);
            let (_sizes, sizes_rx) = tokio::sync::watch::channel(PtySize { cols: 80, rows: 24 });
            let shown = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
            let task = {
                let shown = std::sync::Arc::clone(&shown);
                tokio::spawn(pump(io, input_rx, sizes_rx, None, move |b: &[u8]| shown.lock().unwrap().extend_from_slice(b)))
            };
            device.write_all(b"Switch>").unwrap();
            let until = Instant::now() + Duration::from_secs(5);
            while Instant::now() < until && !shown.lock().unwrap().ends_with(b"Switch>") {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            assert!(shown.lock().unwrap().ends_with(b"Switch>"), "the device's output reaches the window");

            input.send(TerminalCommand::Data(b"enable\r".to_vec())).await.unwrap();
            let got = tokio::task::spawn_blocking(move || {
                let got = device_reads(&mut device, b"enable\r");
                (device, got)
            });
            let (device, got) = got.await.unwrap();
            assert!(got.ends_with(b"enable\r"), "keys reach the device: {got:?}");

            // A break, in order with the keys, and the line still works after it.
            let (reply, answer) = tokio::sync::oneshot::channel();
            input.send(TerminalCommand::Break(reply)).await.unwrap();
            let answer = tokio::time::timeout(Duration::from_secs(5), answer).await.expect("an answer").expect("a reply");
            // A pseudo-terminal may refuse a break; either way it answers and the line goes on.
            let _ = answer;
            input.send(TerminalCommand::Data(b"show ver\r".to_vec())).await.unwrap();
            let mut device = device;
            let (device, got) = tokio::task::spawn_blocking(move || {
                let got = device_reads(&mut device, b"show ver\r");
                (device, got)
            })
            .await
            .unwrap();
            assert!(got.ends_with(b"show ver\r"), "keys after the break: {got:?}");

            // The tab closes while the device is still there.
            drop(input);
            let ended = tokio::time::timeout(Duration::from_secs(5), task).await.expect("the loop ends").unwrap();
            assert_eq!(ended, Ended::Closed);
            drop(device);
        }

        /// Closing the tab stops the port's thread and closes the port: the
        /// device end then reads an error (no reader left on the other end).
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn ending_the_terminal_closes_the_port() {
            let (mut device, mut io) = pair();
            let started = Instant::now();
            io.end().await;
            assert!(started.elapsed() < Duration::from_secs(2), "end waited {:?}", started.elapsed());
            let mut buf = [0u8; 16];
            let until = Instant::now() + Duration::from_secs(2);
            let mut closed = false;
            while Instant::now() < until {
                match device.read(&mut buf) {
                    Err(e) if e.kind() != std::io::ErrorKind::TimedOut => {
                        closed = true;
                        break;
                    }
                    _ => std::thread::sleep(Duration::from_millis(10)),
                }
            }
            assert!(closed, "the port is still open after end()");
            assert!(io.next_output().await.is_none(), "no output after end()");
        }

        /// The device end going away ends the terminal as lost, with a reason.
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn a_port_that_goes_away_ends_the_terminal_with_a_reason() {
            let (device, io) = pair();
            let why = io.why_ended();
            let (_input, input_rx) = tokio::sync::mpsc::channel(32);
            let (_sizes, sizes_rx) = tokio::sync::watch::channel(PtySize { cols: 80, rows: 24 });
            let task = tokio::spawn(pump(io, input_rx, sizes_rx, None, |_: &[u8]| {}));
            drop(device);
            let ended = tokio::time::timeout(Duration::from_secs(5), task).await.expect("the loop ends").unwrap();
            assert_eq!(ended, Ended::Lost);
            let why = why.lock().unwrap().clone();
            assert!(why.is_some(), "a reason is kept");
            let notice = ended_notice("/dev/ttyUSB0", &why.unwrap());
            assert!(notice.contains("/dev/ttyUSB0 closed") && notice.contains("Reconnect"), "{notice}");
        }

        /// Keys a device does not take are capped like any terminal's (R-002).
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn keys_are_capped_while_the_device_does_not_read() {
            use crate::terminal_io::{Input, INPUT_QUEUE_CAP};
            let (_device, mut io) = pair();
            let mut refused = false;
            for _ in 0..(INPUT_QUEUE_CAP / 1024 + 64) {
                if let Input::Refused { .. } = io.send_input(vec![b'x'; 1024]).await {
                    refused = true;
                    break;
                }
            }
            // A pseudo-terminal buffers some kilobytes, then the writes wait: past the
            // cap the keys are refused rather than queued without end.
            assert!(refused, "keys were queued past the cap");
            io.end().await;
        }

        #[test]
        fn a_pseudo_terminal_is_not_a_serial_port_by_name() {
            let (_device, ours) = serialport::TTYPort::pair().unwrap();
            let name = serialport::SerialPort::name(&ours).unwrap_or_default();
            assert!(port_problem(&name, Platform::current(), &[]).is_some(), "{name} opened by name");
        }
    }
}
