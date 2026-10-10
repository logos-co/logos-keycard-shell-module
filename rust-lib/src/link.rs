//! A link to a Shell: APDUs in HID frames, over USB, or over TCP to the emulator in tests.
//! `KEYCARD_SHELL_EMULATOR=host:port` picks the emulator; nothing else does.

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use crate::apdu::{Result, ShellError, Transport};
use crate::commands;
use crate::hid::{self, Reassembly, CHANNEL, FRAME};

pub const VENDOR_ID: u16 = 0x1209;
pub const PRODUCT_ID: u16 = 0x21f7;

/// How long an answer may take: the person reads the request on the Shell first.
const PATIENCE: Duration = Duration::from_secs(600);

pub trait Frames: Send {
    fn write(&mut self, frame: &[u8; FRAME]) -> Result<()>;
    /// The next frame, or `None` when none came within `wait`.
    fn read(&mut self, wait: Duration) -> Result<Option<[u8; FRAME]>>;
}

/// APDUs over frames: one command, then frames until its whole answer has come.
pub struct Link<F: Frames> {
    frames: F,
}

impl<F: Frames> Link<F> {
    pub fn new(frames: F) -> Self {
        Link { frames }
    }
}

impl<F: Frames> Transport for Link<F> {
    fn exchange(&mut self, apdu: &[u8]) -> Result<Vec<u8>> {
        for f in hid::frames(CHANNEL, apdu) {
            self.frames.write(&f)?;
        }
        let mut answer = Reassembly::new(CHANNEL);
        let start = Instant::now();
        while start.elapsed() < PATIENCE {
            if let Some(frame) = self.frames.read(Duration::from_millis(250))? {
                if let Some(done) = answer.push(&frame)? {
                    return Ok(done);
                }
            }
        }
        Err(ShellError::Link("no answer within ten minutes".into()))
    }
}

/// Frames over TCP, to the emulator.
pub struct TcpFrames {
    stream: TcpStream,
    pending: Vec<u8>,
}

impl TcpFrames {
    pub fn connect(addr: &str) -> Result<Self> {
        let stream =
            TcpStream::connect(addr).map_err(|e| ShellError::Link(format!("{addr}: {e}")))?;
        let _ = stream.set_nodelay(true);
        Ok(TcpFrames {
            stream,
            pending: Vec::new(),
        })
    }
}

impl Frames for TcpFrames {
    fn write(&mut self, frame: &[u8; FRAME]) -> Result<()> {
        self.stream
            .write_all(frame)
            .map_err(|e| ShellError::Link(e.to_string()))
    }

    fn read(&mut self, wait: Duration) -> Result<Option<[u8; FRAME]>> {
        let _ = self.stream.set_read_timeout(Some(wait));
        while self.pending.len() < FRAME {
            let mut buf = [0u8; FRAME];
            match self.stream.read(&mut buf) {
                Ok(0) => return Err(ShellError::Link("the emulator closed the link".into())),
                Ok(n) => self.pending.extend_from_slice(&buf[..n]),
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    return Ok(None)
                }
                Err(e) => return Err(ShellError::Link(e.to_string())),
            }
        }
        let frame: [u8; FRAME] = self.pending[..FRAME].try_into().expect("a frame");
        self.pending.drain(..FRAME);
        Ok(Some(frame))
    }
}

/// The Shells this module can reach.
pub trait Devices: Send + Sync {
    /// The USB serials of the Shells connected now.
    fn connected(&self) -> Vec<String>;
    /// A link to the Shell with this serial.
    fn open(&self, serial: &str) -> Result<Box<dyn Transport>>;
}

/// The emulator, at `host:port`, as one connected Shell.
pub struct Emulated {
    addr: String,
}

impl Emulated {
    pub fn new(addr: impl Into<String>) -> Self {
        Emulated { addr: addr.into() }
    }
}

impl Devices for Emulated {
    fn connected(&self) -> Vec<String> {
        let Ok(frames) = TcpFrames::connect(&self.addr) else {
            return Vec::new();
        };
        let mut link = Link::new(frames);
        commands::device_info(&mut link)
            .map(|i| vec![i.serial()])
            .unwrap_or_default()
    }

    fn open(&self, _serial: &str) -> Result<Box<dyn Transport>> {
        Ok(Box::new(Link::new(TcpFrames::connect(&self.addr)?)))
    }
}

/// The Shells on USB, through hidapi.
#[cfg(feature = "hid")]
pub struct Usb {
    api: std::sync::Mutex<Option<hidapi::HidApi>>,
}

#[cfg(feature = "hid")]
impl Usb {
    pub fn new() -> Self {
        Usb {
            api: std::sync::Mutex::new(None),
        }
    }

    fn with_api<T>(&self, f: impl FnOnce(&mut hidapi::HidApi) -> Result<T>) -> Result<T> {
        let mut guard = self.api.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_none() {
            *guard =
                Some(hidapi::HidApi::new().map_err(|e| ShellError::Link(format!("USB: {e}")))?);
        }
        f(guard.as_mut().expect("just made"))
    }
}

#[cfg(feature = "hid")]
impl Default for Usb {
    fn default() -> Self {
        Usb::new()
    }
}

#[cfg(feature = "hid")]
struct HidFrames(hidapi::HidDevice);

/// A Shell that left USB mid-session: unplugged, or off after its idle time.
#[cfg(feature = "hid")]
fn gone(e: hidapi::HidError) -> ShellError {
    ShellError::Link(format!(
        "the Keycard Shell disconnected; it turns itself off after a few minutes without a press: turn it on, unlock it and try again ({e})"
    ))
}

#[cfg(feature = "hid")]
impl Frames for HidFrames {
    fn write(&mut self, frame: &[u8; FRAME]) -> Result<()> {
        // Report ID 0 first: the Shell's reports have none.
        let mut report = [0u8; FRAME + 1];
        report[1..].copy_from_slice(frame);
        self.0.write(&report).map(|_| ()).map_err(gone)
    }

    fn read(&mut self, wait: Duration) -> Result<Option<[u8; FRAME]>> {
        let mut buf = [0u8; FRAME];
        let n = self
            .0
            .read_timeout(&mut buf, wait.as_millis() as i32)
            .map_err(gone)?;
        Ok((n > 0).then_some(buf))
    }
}

#[cfg(feature = "hid")]
impl Devices for Usb {
    fn connected(&self) -> Vec<String> {
        self.with_api(|api| {
            let _ = api.refresh_devices();
            Ok(api
                .device_list()
                .filter(|d| d.vendor_id() == VENDOR_ID && d.product_id() == PRODUCT_ID)
                .filter_map(|d| d.serial_number().map(str::to_lowercase))
                .collect())
        })
        .unwrap_or_default()
    }

    fn open(&self, serial: &str) -> Result<Box<dyn Transport>> {
        self.with_api(|api| {
            let device = api
                .open_serial(VENDOR_ID, PRODUCT_ID, serial)
                .map_err(|e| ShellError::Link(format!("open {serial}: {e}")))?;
            Ok(Box::new(Link::new(HidFrames(device))) as Box<dyn Transport>)
        })
    }
}

/// The Shells to use: the emulator when `KEYCARD_SHELL_EMULATOR` names one, else USB.
pub fn from_env() -> Box<dyn Devices> {
    match std::env::var("KEYCARD_SHELL_EMULATOR") {
        Ok(addr) if !addr.trim().is_empty() => Box::new(Emulated::new(addr.trim())),
        #[cfg(feature = "hid")]
        _ => Box::new(Usb::new()),
        #[cfg(not(feature = "hid"))]
        _ => Box::new(Emulated::new("")),
    }
}
