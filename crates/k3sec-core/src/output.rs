//! Rendering of [`SecEvent`]s to the terminal.
//!
//! Two formats:
//! * [`OutputFormat::Pretty`], human-readable, colored, one line per event.
//! * [`OutputFormat::Json`]  , NDJSON, one event per line, stable schema.
//!
//! A single [`Printer`] owns stdout so that concurrent producers (the events
//! watch and each pod-log task) never interleave a half-written line. All
//! writes go through one `emit` call holding the stdout lock for its duration.

use std::io::{IsTerminal, Write};

use owo_colors::OwoColorize;

use crate::event::{SecEvent, Severity};

/// Output format selected on the CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, Default)]
#[clap(rename_all = "lowercase")]
pub enum OutputFormat {
    /// Colored, human-readable single-line output.
    #[default]
    Pretty,
    /// JSON: one event per line (NDJSON) for streams, one document for reports.
    Json,
}

/// Serializes events to stdout in the chosen [`OutputFormat`].
pub struct Printer {
    format: OutputFormat,
    color: bool,
}

impl Printer {
    /// Build a printer. Color is enabled only for pretty output on a real TTY
    /// and when `NO_COLOR` is unset (see <https://no-color.org>).
    pub fn new(format: OutputFormat) -> Self {
        let color = matches!(format, OutputFormat::Pretty)
            && std::io::stdout().is_terminal()
            && std::env::var_os("NO_COLOR").is_none();
        Self { format, color }
    }

    /// Render `event` to stdout followed by a newline.
    ///
    /// A broken pipe (e.g. `k3sec watch | head`) is swallowed so the process
    /// exits cleanly instead of panicking on a closed downstream reader.
    pub fn emit(&self, event: &SecEvent) {
        let line = match self.format {
            OutputFormat::Pretty => self.render_pretty(event),
            OutputFormat::Json => match event.to_ndjson() {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "failed to serialize event to JSON");
                    return;
                }
            },
        };

        let stdout = std::io::stdout();
        let mut lock = stdout.lock();
        if let Err(e) = writeln!(lock, "{line}") {
            if e.kind() != std::io::ErrorKind::BrokenPipe {
                tracing::warn!(error = %e, "failed to write to stdout");
            }
        }
    }

    fn render_pretty(&self, ev: &SecEvent) -> String {
        let time = ev.timestamp.format("%H:%M:%S").to_string();
        // Pad the label *before* colorizing so ANSI codes don't skew alignment.
        let badge = format!("{:<6}", ev.severity.label());
        let location = ev.location();

        if !self.color {
            return format!("{time}  {badge}  {location}  {}", ev.message);
        }

        let time = time.dimmed().to_string();
        let badge = colorize_severity(&badge, ev.severity);
        let location = location.bold().to_string();
        // Make high-severity lines (e.g. YARA detections) pop: red message too.
        let message = if ev.severity >= Severity::Error {
            ev.message.red().bold().to_string()
        } else {
            ev.message.clone()
        };
        format!("{time}  {badge}  {location}  {message}")
    }
}

/// Apply the severity color scheme:
/// Normal → dim gray, Warning → yellow, Error/Critical → red, Info → default.
fn colorize_severity(text: &str, severity: Severity) -> String {
    match severity {
        Severity::Info => text.to_string(),
        Severity::Normal => text.dimmed().to_string(),
        Severity::Warning => text.yellow().to_string(),
        Severity::Error => text.red().to_string(),
        Severity::Critical => text.red().bold().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Source;
    use chrono::{TimeZone, Utc};

    fn sample() -> SecEvent {
        SecEvent::builder(
            Source::K8sEvent,
            Utc.with_ymd_and_hms(2026, 8, 11, 18, 30, 5).unwrap(),
        )
        .kind("Failed")
        .severity(Severity::Warning)
        .namespace("default")
        .object("pod/academy")
        .message("Error: ImagePullBackOff")
        .build()
    }

    #[test]
    fn pretty_without_color_is_plain_and_ordered() {
        let printer = Printer {
            format: OutputFormat::Pretty,
            color: false,
        };
        let line = printer.render_pretty(&sample());
        assert_eq!(
            line,
            "18:30:05  WARN    default/pod/academy  Error: ImagePullBackOff"
        );
        // No ANSI escapes when color is off.
        assert!(!line.contains('\u{1b}'));
    }

    #[test]
    fn pretty_with_color_wraps_in_ansi() {
        let printer = Printer {
            format: OutputFormat::Pretty,
            color: true,
        };
        let line = printer.render_pretty(&sample());
        assert!(
            line.contains('\u{1b}'),
            "expected ANSI escapes when color on"
        );
        // The message text itself is still present verbatim.
        assert!(line.contains("Error: ImagePullBackOff"));
    }

    #[test]
    fn json_format_is_single_ndjson_line() {
        let printer = Printer::new(OutputFormat::Json);
        assert!(!printer.color);
        let ev = sample();
        let rendered = ev.to_ndjson().unwrap();
        assert!(!rendered.contains('\n'));
        let v: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(v["source"], "k8s-event");
        assert_eq!(v["object"], "pod/academy");
    }
}
