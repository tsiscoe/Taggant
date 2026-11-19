//! Ratatui v0.30+ 3-pane layout and ANSI/OSC escape-sanitized renderer (`CWE-150`) for **Taggant**.

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap},
};

use crate::tui::{ActivePane, TaggantTuiApp};

/// Strip C0/C1 control characters and ANSI/OSC escape sequences (`\x1b`) before rendering
/// untrusted paths, HTTP headers, or token previews into the terminal buffer (`CWE-150`).
pub fn sanitize_terminal_str(input: &str) -> String {
    input
        .chars()
        .filter(|&c| c == '\n' || c == '\t' || (!c.is_control() && c != '\u{001b}'))
        .collect()
}

pub fn render(frame: &mut Frame, app: &TaggantTuiApp) {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(4),
            Constraint::Percentage(46),
            Constraint::Percentage(40),
            Constraint::Length(2),
        ])
        .split(frame.area());

    let chain_badge = if app.chain_report.valid {
        Span::styled(
            " MERKLE CHAIN: VERIFIED ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            " MERKLE CHAIN: TAMPERED ",
            Style::default()
                .fg(Color::White)
                .bg(Color::Red)
                .add_modifier(Modifier::BOLD),
        )
    };

    let masthead = Paragraph::new(Line::from(vec![
        Span::styled(
            " TAGGANT v0.1.0 ",
            Style::default()
                .fg(Color::White)
                .bg(Color::Red)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" // "),
        Span::styled(
            "ASYMMETRIC ELLIGATOR2 HONEYTOKEN SEEDER & OFFLINE AUTOPSY  ",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        chain_badge,
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(masthead, vertical[0]);

    let head_short = if app.chain_report.head_hash.len() >= 16 {
        &app.chain_report.head_hash[..16]
    } else {
        &app.chain_report.head_hash
    };
    let telemetry_text = format!(
        "Vault: {}   |   Planted Canaries: {}   |   Autopsy Hits: {}   |   Tripwire Alerts: {} (head: {}...)\nSeeding Public Key: {}",
        sanitize_terminal_str(&app.vault_path),
        app.canaries.len(),
        app.autopsy_hits.len(),
        app.alerts.len(),
        head_short,
        sanitize_terminal_str(&app.pub_key_b64)
    );
    let telemetry = Paragraph::new(telemetry_text).block(
        Block::default()
            .title(" [00] CUSTODY & MERKLE TELEMETRY ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(telemetry, vertical[1]);

    // Top row split: Pane 1 (Planted Canaries) + Pane 2 (Offline Autopsy Inspector)
    let mid_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(vertical[2]);

    let canary_border = if app.active_pane == ActivePane::Canaries {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let canary_rows: Vec<Row> = app
        .canaries
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let style = if i == app.selected_canary && app.active_pane == ActivePane::Canaries {
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(sanitize_terminal_str(&c.profile)),
                Cell::from(sanitize_terminal_str(&c.host)),
                Cell::from(sanitize_terminal_str(&c.target_path)),
                Cell::from(sanitize_terminal_str(&c.token_preview)),
            ])
            .style(style)
        })
        .collect();

    let canary_table = Table::new(
        canary_rows,
        [
            Constraint::Length(14),
            Constraint::Length(18),
            Constraint::Percentage(40),
            Constraint::Percentage(30),
        ],
    )
    .header(
        Row::new(["PROFILE", "HOST", "TARGET PATH", "TOKEN PREVIEW"]).style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
    )
    .block(
        Block::default()
            .title(" [01] PLANTED CANARY INVENTORY ")
            .borders(Borders::ALL)
            .border_style(canary_border),
    );
    frame.render_widget(canary_table, mid_cols[0]);

    let autopsy_border = if app.active_pane == ActivePane::Autopsy {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let autopsy_body = if let Some(hit) = app.autopsy_hits.get(app.selected_autopsy) {
        format!(
            "Mode: {}\nProfile: {}\nToken: {}\nMinted UTC: {}\nHost Tag: {} ({})\nPath Tag: {} ({})\nBranch Tag: {} ({})",
            sanitize_terminal_str(&hit.tier),
            sanitize_terminal_str(&hit.profile),
            sanitize_terminal_str(&hit.token_preview),
            sanitize_terminal_str(hit.minted_utc.as_deref().unwrap_or("unknown")),
            sanitize_terminal_str(&hit.host_tag_hex),
            sanitize_terminal_str(hit.resolved_host.as_deref().unwrap_or("unindexed")),
            sanitize_terminal_str(&hit.path_tag_hex),
            sanitize_terminal_str(hit.resolved_path.as_deref().unwrap_or("unindexed")),
            sanitize_terminal_str(&hit.branch_tag_hex),
            sanitize_terminal_str(hit.resolved_branch.as_deref().unwrap_or("unindexed")),
        )
    } else if let Some(canary) = app.canaries.get(app.selected_canary) {
        format!(
            "Selected Canary Telemetry (Preview)\nProfile: {} ({})\nHost: {} [tag: {}]\nTarget: {} [tag: {}]\nBranch: {} [tag: {}]\nMinted Epoch: {}m",
            sanitize_terminal_str(&canary.profile),
            sanitize_terminal_str(&canary.env_var),
            sanitize_terminal_str(&canary.host),
            sanitize_terminal_str(&canary.host_tag_hex),
            sanitize_terminal_str(&canary.target_path),
            sanitize_terminal_str(&canary.path_tag_hex),
            sanitize_terminal_str(&canary.branch),
            sanitize_terminal_str(&canary.branch_tag_hex),
            canary.epoch_minutes
        )
    } else {
        "No autopsy hits or planted canaries in vault.\nRun `taggant seed` or pass `--autopsy-file`."
            .to_string()
    };
    let autopsy_pane = Paragraph::new(autopsy_body)
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .title(" [02] OFFLINE ELLIGATOR2 AUTOPSY INSPECTOR ")
                .borders(Borders::ALL)
                .border_style(autopsy_border),
        );
    frame.render_widget(autopsy_pane, mid_cols[1]);

    // Bottom pane: Pane 3 (BLAKE3 Chained Loopback Tripwire Alerts)
    let alert_border = if app.active_pane == ActivePane::TripwireAlerts {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let alert_rows: Vec<Row> = app
        .alerts
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let style = if i == app.selected_alert && app.active_pane == ActivePane::TripwireAlerts
            {
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let hash_short = if a.entry_hash.len() >= 12 {
                &a.entry_hash[..12]
            } else {
                &a.entry_hash
            };
            Row::new(vec![
                Cell::from(format!("#{}", a.seq)),
                Cell::from(sanitize_terminal_str(&a.source_ip)),
                Cell::from(sanitize_terminal_str(&format!(
                    "{} {}",
                    a.method, a.request_path
                ))),
                Cell::from(sanitize_terminal_str(&a.profile)),
                Cell::from(sanitize_terminal_str(&a.target_path_label)),
                Cell::from(sanitize_terminal_str(hash_short)),
            ])
            .style(style)
        })
        .collect();

    let alert_table = Table::new(
        alert_rows,
        [
            Constraint::Length(6),
            Constraint::Length(14),
            Constraint::Percentage(32),
            Constraint::Length(15),
            Constraint::Percentage(24),
            Constraint::Length(14),
        ],
    )
    .header(
        Row::new([
            "SEQ",
            "SRC IP",
            "HTTP PROBE",
            "PROFILE",
            "ORIGIN PATH",
            "BLAKE3",
        ])
        .style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
    )
    .block(
        Block::default()
            .title(" [03] BLAKE3 MERKLE LOOPBACK TRIPWIRE ALERTS ")
            .borders(Borders::ALL)
            .border_style(alert_border),
    );
    frame.render_widget(alert_table, vertical[3]);

    let footer = Paragraph::new(
        "Keys: [Tab/Shift-Tab] Switch Pane  |  [j/k / Arrows] Navigate  |  [q / Esc] Quit",
    )
    .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(footer, vertical[4]);
}
