use chrono::Local;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame, Terminal,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    io::{self, stdout},
    path::PathBuf,
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::process::Command;

#[cfg(target_os = "linux")]
use std::net::ToSocketAddrs;

#[cfg(not(target_os = "linux"))]
use std::io::{BufRead, BufReader, Write};

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

const DEFAULT_BLOCKED_DOMAINS: &[&str] = &[
    "github.com",
    "twitter.com",
    "x.com",
    "youtube.com",
    "instagram.com",
    "linkedin.com",
    "bsky.app",
    "hachyderm.io",
    "zulip.com",
    "facebook.com",
];

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    #[serde(default = "default_blocked_domains")]
    blocked_domains: Vec<String>,
}

fn default_blocked_domains() -> Vec<String> {
    DEFAULT_BLOCKED_DOMAINS.iter().map(|s| s.to_string()).collect()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            blocked_domains: default_blocked_domains(),
        }
    }
}

impl Config {
    fn config_path() -> PathBuf {
        let config_dir = get_config_dir().join("study-time");
        fs::create_dir_all(&config_dir).ok();
        config_dir.join("config.toml")
    }

    fn load() -> Self {
        let path = Self::config_path();
        if path.exists() {
            let content = fs::read_to_string(&path).unwrap_or_default();
            toml::from_str(&content).unwrap_or_default()
        } else {
            let config = Self::default();
            config.save();
            config
        }
    }

    fn save(&self) {
        let path = Self::config_path();
        if let Ok(content) = toml::to_string_pretty(self) {
            fs::write(&path, content).ok();
            // Fix ownership when running with sudo (Unix only)
            #[cfg(unix)]
            if let Ok(sudo_user) = std::env::var("SUDO_USER") {
                let _ = Command::new("chown")
                    .args([&sudo_user, path.to_str().unwrap_or_default()])
                    .output();
            }
        }
    }
}

/// Get the appropriate config directory, handling sudo on Unix
fn get_config_dir() -> PathBuf {
    #[cfg(unix)]
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        // When running with sudo, use the original user's home directory
        if let Ok(output) = Command::new("getent").args(["passwd", &sudo_user]).output() {
            if let Ok(line) = String::from_utf8(output.stdout) {
                // getent passwd format: username:x:uid:gid:gecos:home:shell
                if let Some(home) = line.split(':').nth(5) {
                    return PathBuf::from(home).join(".config");
                }
            }
        }
        // Fallback to /home/user
        return PathBuf::from(format!("/home/{}", sudo_user)).join(".config");
    }
    dirs::config_dir().unwrap_or_else(|| PathBuf::from("."))
}

// ─────────────────────────────────────────────────────────────────────────────
// Progress Persistence
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, Default)]
struct Progress {
    #[serde(default)]
    stats: Stats,
    #[serde(default)]
    daily: HashMap<String, u64>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct Stats {
    total_seconds: u64,
    last_date: Option<String>,
}

impl Progress {
    fn config_path() -> PathBuf {
        let config_dir = get_config_dir().join("study-time");
        fs::create_dir_all(&config_dir).ok();
        config_dir.join("progress.toml")
    }

    fn load() -> Self {
        let path = Self::config_path();
        if path.exists() {
            let content = fs::read_to_string(&path).unwrap_or_default();
            toml::from_str(&content).unwrap_or_default()
        } else {
            Self::default()
        }
    }

    fn save(&self) {
        let path = Self::config_path();
        if let Ok(content) = toml::to_string_pretty(self) {
            fs::write(path, content).ok();
        }
    }

    fn add_time(&mut self, seconds: u64) {
        let today = Local::now().format("%Y-%m-%d").to_string();

        // Reset daily counter if it's a new day
        if self.stats.last_date.as_ref() != Some(&today) {
            self.stats.last_date = Some(today.clone());
        }

        // Update totals
        self.stats.total_seconds += seconds;
        *self.daily.entry(today).or_insert(0) += seconds;
    }

    fn today_seconds(&self) -> u64 {
        let today = Local::now().format("%Y-%m-%d").to_string();
        *self.daily.get(&today).unwrap_or(&0)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Website Blocking (Cross-platform)
// ─────────────────────────────────────────────────────────────────────────────

trait Blocker {
    fn block(&mut self);
    fn unblock(&mut self);
    fn flush_all(&mut self);
}

// ─────────────────────────────────────────────────────────────────────────────
// Linux: iptables-based blocking
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
struct PlatformBlocker {
    blocked_ips: Vec<String>,
    blocked_domains: Vec<String>,
}

#[cfg(target_os = "linux")]
impl PlatformBlocker {
    fn new(blocked_domains: Vec<String>) -> Self {
        let mut blocker = Self {
            blocked_ips: Vec::new(),
            blocked_domains,
        };
        blocker.cleanup_stale_rules();
        blocker
    }

    fn cleanup_stale_rules(&mut self) {
        for domain in &self.blocked_domains {
            let ips = resolve_domain_ips(domain);
            for ip in ips {
                loop {
                    let output = Command::new("iptables")
                        .args(["-D", "OUTPUT", "-d", &ip, "-j", "DROP"])
                        .output();
                    if output.is_err() || !output.unwrap().status.success() {
                        break;
                    }
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl Blocker for PlatformBlocker {
    fn block(&mut self) {
        for domain in &self.blocked_domains {
            let ips = resolve_domain_ips(domain);
            for ip in ips {
                if !self.blocked_ips.contains(&ip) {
                    let _ = Command::new("iptables")
                        .args(["-A", "OUTPUT", "-d", &ip, "-j", "DROP"])
                        .output();
                    self.blocked_ips.push(ip);
                }
            }
        }
    }

    fn unblock(&mut self) {
        for ip in self.blocked_ips.drain(..) {
            let _ = Command::new("iptables")
                .args(["-D", "OUTPUT", "-d", &ip, "-j", "DROP"])
                .output();
        }
    }

    fn flush_all(&mut self) {
        self.blocked_ips.clear();
        for domain in &self.blocked_domains {
            let ips = resolve_domain_ips(domain);
            for ip in ips {
                loop {
                    let output = Command::new("iptables")
                        .args(["-D", "OUTPUT", "-d", &ip, "-j", "DROP"])
                        .output();
                    if output.is_err() || !output.unwrap().status.success() {
                        break;
                    }
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for PlatformBlocker {
    fn drop(&mut self) {
        self.flush_all();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Windows & macOS: hosts file-based blocking
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(not(target_os = "linux"))]
struct PlatformBlocker {
    blocked_domains: Vec<String>,
    is_blocking: bool,
}

#[cfg(not(target_os = "linux"))]
impl PlatformBlocker {
    fn new(blocked_domains: Vec<String>) -> Self {
        let mut blocker = Self {
            blocked_domains,
            is_blocking: false,
        };
        // Clean up any stale entries from previous crashed sessions
        blocker.flush_all();
        blocker
    }

    fn hosts_path() -> PathBuf {
        #[cfg(windows)]
        {
            PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts")
        }
        #[cfg(not(windows))]
        {
            PathBuf::from("/etc/hosts")
        }
    }

    fn marker_start() -> &'static str {
        "# >>> STUDY-TIME BLOCK START <<<"
    }

    fn marker_end() -> &'static str {
        "# >>> STUDY-TIME BLOCK END <<<"
    }
}

#[cfg(not(target_os = "linux"))]
impl Blocker for PlatformBlocker {
    fn block(&mut self) {
        if self.is_blocking {
            return;
        }

        let hosts_path = Self::hosts_path();
        let content = fs::read_to_string(&hosts_path).unwrap_or_default();

        // Build block entries
        let mut block_entries = String::new();
        block_entries.push_str(Self::marker_start());
        block_entries.push('\n');
        for domain in &self.blocked_domains {
            block_entries.push_str(&format!("127.0.0.1 {}\n", domain));
            block_entries.push_str(&format!("127.0.0.1 www.{}\n", domain));
            block_entries.push_str(&format!("::1 {}\n", domain));
            block_entries.push_str(&format!("::1 www.{}\n", domain));
        }
        block_entries.push_str(Self::marker_end());
        block_entries.push('\n');

        // Append to hosts file
        let new_content = format!("{}\n{}", content.trim_end(), block_entries);
        if let Ok(mut file) = fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&hosts_path)
        {
            let _ = file.write_all(new_content.as_bytes());
            self.is_blocking = true;

            // Flush DNS cache
            #[cfg(windows)]
            {
                let _ = std::process::Command::new("ipconfig")
                    .args(["/flushdns"])
                    .output();
            }
            #[cfg(target_os = "macos")]
            {
                let _ = std::process::Command::new("dscacheutil")
                    .args(["-flushcache"])
                    .output();
                let _ = std::process::Command::new("killall")
                    .args(["-HUP", "mDNSResponder"])
                    .output();
            }
        }
    }

    fn unblock(&mut self) {
        self.flush_all();
        self.is_blocking = false;
    }

    fn flush_all(&mut self) {
        let hosts_path = Self::hosts_path();
        let content = match fs::read_to_string(&hosts_path) {
            Ok(c) => c,
            Err(_) => return,
        };

        // Remove our block section
        let mut new_lines = Vec::new();
        let mut in_block = false;

        let file = std::io::Cursor::new(content);
        for line in BufReader::new(file).lines().map_while(Result::ok) {
            if line.contains(Self::marker_start()) {
                in_block = true;
                continue;
            }
            if line.contains(Self::marker_end()) {
                in_block = false;
                continue;
            }
            if !in_block {
                new_lines.push(line);
            }
        }

        let new_content = new_lines.join("\n");
        if let Ok(mut file) = fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&hosts_path)
        {
            let _ = file.write_all(new_content.as_bytes());
        }

        self.is_blocking = false;
    }
}

#[cfg(not(target_os = "linux"))]
impl Drop for PlatformBlocker {
    fn drop(&mut self) {
        self.flush_all();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn resolve_domain_ips(domain: &str) -> Vec<String> {
    let mut ips = Vec::new();

    if let Ok(addrs) = format!("{}:443", domain).to_socket_addrs() {
        for addr in addrs {
            ips.push(addr.ip().to_string());
        }
    }

    if let Ok(addrs) = format!("www.{}:443", domain).to_socket_addrs() {
        for addr in addrs {
            let ip = addr.ip().to_string();
            if !ips.contains(&ip) {
                ips.push(ip);
            }
        }
    }

    ips
}

// ─────────────────────────────────────────────────────────────────────────────
// App State
// ─────────────────────────────────────────────────────────────────────────────

struct App {
    studying: bool,
    session_start: Option<Instant>,
    session_seconds: u64,
    progress: Progress,
    blocker: PlatformBlocker,
}

impl App {
    fn new() -> Self {
        let config = Config::load();
        Self {
            studying: false,
            session_start: None,
            session_seconds: 0,
            progress: Progress::load(),
            blocker: PlatformBlocker::new(config.blocked_domains),
        }
    }

    fn toggle_study_mode(&mut self) {
        if self.studying {
            // Stop studying
            if let Some(start) = self.session_start.take() {
                let elapsed = start.elapsed().as_secs() + self.session_seconds;
                self.progress.add_time(elapsed);
                self.progress.save();
                self.session_seconds = 0;
            }
            self.blocker.unblock();
            self.studying = false;
        } else {
            // Start studying
            self.session_start = Some(Instant::now());
            self.session_seconds = 0;
            self.blocker.block();
            self.studying = true;
        }
    }

    fn current_session_duration(&self) -> Duration {
        if let Some(start) = self.session_start {
            Duration::from_secs(start.elapsed().as_secs() + self.session_seconds)
        } else {
            Duration::from_secs(self.session_seconds)
        }
    }

    fn today_duration(&self) -> Duration {
        let base = self.progress.today_seconds();
        let current = if self.studying {
            self.current_session_duration().as_secs()
        } else {
            0
        };
        Duration::from_secs(base + current)
    }

    fn save_and_exit(&mut self) {
        if self.studying {
            if let Some(start) = self.session_start.take() {
                let elapsed = start.elapsed().as_secs() + self.session_seconds;
                self.progress.add_time(elapsed);
            }
        }
        self.progress.save();
        self.blocker.flush_all();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UI Rendering
// ─────────────────────────────────────────────────────────────────────────────

fn format_duration(duration: Duration) -> String {
    let total_secs = duration.as_secs();
    let hours = total_secs / 3600;
    let mins = (total_secs % 3600) / 60;
    let secs = total_secs % 60;
    format!("{:02}:{:02}:{:02}", hours, mins, secs)
}

fn ui(frame: &mut Frame, app: &App) {
    let area = frame.area();

    // Center the main box
    let main_area = centered_rect(50, 60, area);

    // Main container
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if app.studying {
            Color::Green
        } else {
            Color::Cyan
        }))
        .title(" 📚 STUDY TIME 📚 ")
        .title_alignment(Alignment::Center);

    frame.render_widget(block.clone(), main_area);

    let inner = block.inner(main_area);

    // Layout: status, emoticon, timers, controls
    let chunks = Layout::vertical([
        Constraint::Length(2), // Status
        Constraint::Length(3), // Emoticon
        Constraint::Length(2), // Session time
        Constraint::Length(2), // Today time
        Constraint::Min(1),    // Spacer
        Constraint::Length(2), // Controls
    ])
    .split(inner);

    // Status
    let (status_text, status_color) = if app.studying {
        ("🔒 STUDY MODE ACTIVE", Color::Green)
    } else {
        ("😴 Relaxing...", Color::Yellow)
    };
    let status = Paragraph::new(status_text)
        .style(
            Style::default()
                .fg(status_color)
                .add_modifier(Modifier::BOLD),
        )
        .alignment(Alignment::Center);
    frame.render_widget(status, chunks[0]);

    // Emoticon
    let emoticon = if app.studying { "📖" } else { "🎮" };
    let emoticon_para = Paragraph::new(emoticon)
        .style(Style::default().add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center);
    frame.render_widget(emoticon_para, chunks[1]);

    // Session time
    let session_time = format!(
        "Session: {}",
        format_duration(app.current_session_duration())
    );
    let session = Paragraph::new(session_time)
        .style(Style::default().fg(Color::White))
        .alignment(Alignment::Center);
    frame.render_widget(session, chunks[2]);

    // Today time
    let today_time = format!("Today:   {}", format_duration(app.today_duration()));
    let today = Paragraph::new(today_time)
        .style(Style::default().fg(Color::Magenta))
        .alignment(Alignment::Center);
    frame.render_widget(today, chunks[3]);

    // Controls
    let controls = Paragraph::new(Line::from(vec![
        Span::styled(
            "[Space]",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Toggle  "),
        Span::styled(
            "[Q]",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
        Span::raw(" Quit"),
    ]))
    .alignment(Alignment::Center);
    frame.render_widget(controls, chunks[5]);
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let popup_layout = Layout::vertical([
        Constraint::Percentage((100 - percent_y) / 2),
        Constraint::Percentage(percent_y),
        Constraint::Percentage((100 - percent_y) / 2),
    ])
    .split(area);

    Layout::horizontal([
        Constraint::Percentage((100 - percent_x) / 2),
        Constraint::Percentage(percent_x),
        Constraint::Percentage((100 - percent_x) / 2),
    ])
    .split(popup_layout[1])[1]
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

fn main() -> io::Result<()> {
    // Check for admin/root privileges
    if !check_admin() {
        eprintln!("⚠️  This app requires elevated privileges to block websites.");
        #[cfg(windows)]
        eprintln!("   Please run as Administrator.");
        #[cfg(unix)]
        eprintln!("   Please run with: sudo ./study-time");
        std::process::exit(1);
    }

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app
    let mut app = App::new();

    // Main loop
    let tick_rate = Duration::from_millis(250);
    let mut last_tick = Instant::now();

    loop {
        terminal.draw(|f| ui(f, &app))?;

        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => {
                            break;
                        }
                        KeyCode::Char(' ') => {
                            app.toggle_study_mode();
                        }
                        _ => {}
                    }
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = Instant::now();
        }
    }

    // Cleanup
    app.save_and_exit();
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    println!("👋 Study session saved! Keep up the great work!");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Platform-specific admin check
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(unix)]
fn check_admin() -> bool {
    unsafe { libc::geteuid() == 0 }
}

#[cfg(windows)]
fn check_admin() -> bool {
    is_elevated::is_elevated()
}
