//! Ratatui v0.30+ 3-pane interactive Taggant Custody & Autopsy Console (`taggant tui`).

pub mod ui;

use std::io;
use std::time::Duration;

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};

use crate::ops::scan::UnifiedAutopsyResult;
use crate::vault::{AlertChainReport, CanaryRecord, TripwireAlert};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivePane {
    Canaries,
    Autopsy,
    TripwireAlerts,
}

pub struct TaggantTuiApp {
    pub vault_path: String,
    pub pub_key_b64: String,
    pub canaries: Vec<CanaryRecord>,
    pub autopsy_hits: Vec<UnifiedAutopsyResult>,
    pub alerts: Vec<TripwireAlert>,
    pub chain_report: AlertChainReport,
    pub active_pane: ActivePane,
    pub selected_canary: usize,
    pub selected_autopsy: usize,
    pub selected_alert: usize,
}

impl TaggantTuiApp {
    pub fn new(
        vault_path: String,
        pub_key_b64: String,
        canaries: Vec<CanaryRecord>,
        autopsy_hits: Vec<UnifiedAutopsyResult>,
        alerts: Vec<TripwireAlert>,
        chain_report: AlertChainReport,
    ) -> Self {
        Self {
            vault_path,
            pub_key_b64,
            canaries,
            autopsy_hits,
            alerts,
            chain_report,
            active_pane: ActivePane::Canaries,
            selected_canary: 0,
            selected_autopsy: 0,
            selected_alert: 0,
        }
    }

    pub fn next_pane(&mut self) {
        self.active_pane = match self.active_pane {
            ActivePane::Canaries => ActivePane::Autopsy,
            ActivePane::Autopsy => ActivePane::TripwireAlerts,
            ActivePane::TripwireAlerts => ActivePane::Canaries,
        };
    }

    pub fn prev_pane(&mut self) {
        self.active_pane = match self.active_pane {
            ActivePane::Canaries => ActivePane::TripwireAlerts,
            ActivePane::Autopsy => ActivePane::Canaries,
            ActivePane::TripwireAlerts => ActivePane::Autopsy,
        };
    }

    pub fn move_down(&mut self) {
        match self.active_pane {
            ActivePane::Canaries if !self.canaries.is_empty() => {
                self.selected_canary = (self.selected_canary + 1) % self.canaries.len();
            }
            ActivePane::Autopsy if !self.autopsy_hits.is_empty() => {
                self.selected_autopsy = (self.selected_autopsy + 1) % self.autopsy_hits.len();
            }
            ActivePane::TripwireAlerts if !self.alerts.is_empty() => {
                self.selected_alert = (self.selected_alert + 1) % self.alerts.len();
            }
            _ => {}
        }
    }

    pub fn move_up(&mut self) {
        match self.active_pane {
            ActivePane::Canaries if !self.canaries.is_empty() => {
                self.selected_canary = self
                    .selected_canary
                    .checked_sub(1)
                    .unwrap_or(self.canaries.len() - 1);
            }
            ActivePane::Autopsy if !self.autopsy_hits.is_empty() => {
                self.selected_autopsy = self
                    .selected_autopsy
                    .checked_sub(1)
                    .unwrap_or(self.autopsy_hits.len() - 1);
            }
            ActivePane::TripwireAlerts if !self.alerts.is_empty() => {
                self.selected_alert = self
                    .selected_alert
                    .checked_sub(1)
                    .unwrap_or(self.alerts.len() - 1);
            }
            _ => {}
        }
    }
}

fn install_terminal_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        prev(info);
    }));
}

pub fn run_interactive_tui(mut app: TaggantTuiApp) -> Result<()> {
    install_terminal_panic_hook();
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = (|| -> Result<()> {
        loop {
            terminal.draw(|frame| ui::render(frame, &app))?;
            if event::poll(Duration::from_millis(100))?
                && let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Tab => app.next_pane(),
                    KeyCode::BackTab => app.prev_pane(),
                    KeyCode::Down | KeyCode::Char('j') => app.move_down(),
                    KeyCode::Up | KeyCode::Char('k') => app.move_up(),
                    _ => {}
                }
            }
        }
        Ok(())
    })();

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    res
}
