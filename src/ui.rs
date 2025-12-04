use crate::app::{App, AppState};
use crate::scanner::FindingType;
use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph},
    Frame, Terminal,
};
use std::io;
use std::time::Duration;

pub fn run(app: &mut App) -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_app(&mut terminal, app);

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

fn run_app<B: ratatui::backend::Backend>(terminal: &mut Terminal<B>, app: &mut App) -> Result<()> {
    loop {
        terminal.draw(|f| draw_ui(f, app))?;

        // Check if scan is complete
        if app.state == AppState::Scanning {
            app.check_scan_complete();
        }

        // Poll for events with timeout for smooth progress updates
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    handle_key(app, key.code)?;
                }
            }
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}

fn handle_key(app: &mut App, key: KeyCode) -> Result<()> {
    match app.state {
        AppState::SelectFolder => match key {
            KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
            KeyCode::Up | KeyCode::Char('k') => app.navigate_up(),
            KeyCode::Down | KeyCode::Char('j') => app.navigate_down(),
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => app.enter_selected()?,
            KeyCode::Left | KeyCode::Char('h') | KeyCode::Backspace => app.go_parent()?,
            KeyCode::Char('n') => app.toggle_node_modules(),
            KeyCode::Char('s') | KeyCode::Char(' ') => app.start_scan(),
            _ => {}
        },
        AppState::Scanning => match key {
            KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
            _ => {}
        },
        AppState::Results => match key {
            KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
            KeyCode::Up | KeyCode::Char('k') => app.results_up(),
            KeyCode::Down | KeyCode::Char('j') => app.results_down(),
            KeyCode::Char('b') | KeyCode::Backspace => app.back_to_folder_select(),
            KeyCode::Char('s') => app.start_scan(),
            _ => {}
        },
    }
    Ok(())
}

fn draw_ui(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(10),   // Main content
            Constraint::Length(3), // Footer/help
        ])
        .split(f.area());

    draw_header(f, chunks[0]);

    match app.state {
        AppState::SelectFolder => draw_folder_selector(f, app, chunks[1]),
        AppState::Scanning => draw_scanning(f, app, chunks[1]),
        AppState::Results => draw_results(f, app, chunks[1]),
    }

    draw_footer(f, app, chunks[2]);
}

fn draw_header(f: &mut Frame, area: Rect) {
    let title = Paragraph::new(vec![Line::from(vec![
        Span::styled(
            " 🐛 Shai-Hulud 2.0 Killer ",
            Style::default()
                .fg(Color::Red)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "- NPM Supply Chain Attack Detector",
            Style::default().fg(Color::White),
        ),
    ])])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Red)),
    );
    f.render_widget(title, area);
}

fn draw_folder_selector(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Current path
            Constraint::Length(3), // Scan target
            Constraint::Length(3), // Options
            Constraint::Min(5),    // File list
        ])
        .split(area);

    // Current path
    let path_display = format!(" 📁 {}", app.current_path.display());
    let path_widget = Paragraph::new(path_display)
        .style(Style::default().fg(Color::Cyan))
        .block(
            Block::default()
                .title(" Current Directory ")
                .borders(Borders::ALL),
        );
    f.render_widget(path_widget, chunks[0]);

    // Scan target (shows which folder will be scanned)
    let scan_target = app.get_selected_path();
    let target_display = format!(" 🎯 {}", scan_target.display());
    let target_widget = Paragraph::new(target_display)
        .style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
        .block(
            Block::default()
                .title(" Will Scan (Space/s) ")
                .borders(Borders::ALL),
        );
    f.render_widget(target_widget, chunks[1]);

    // Options
    let node_modules_status = if app.include_node_modules {
        "✓ ON"
    } else {
        "✗ OFF"
    };
    let options = Paragraph::new(format!(
        " Include node_modules: {} (press 'n' to toggle)",
        node_modules_status
    ))
    .style(Style::default().fg(Color::Yellow))
    .block(Block::default().title(" Options ").borders(Borders::ALL));
    f.render_widget(options, chunks[2]);

    // File list
    let items: Vec<ListItem> = app
        .entries
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let icon = if entry.is_dir { "📁 " } else { "📄 " };
            let style = if i == app.selected_index {
                Style::default()
                    .bg(Color::DarkGray)
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else if entry.is_dir {
                Style::default().fg(Color::Blue)
            } else {
                Style::default().fg(Color::White)
            };
            ListItem::new(format!("{}{}", icon, entry.name)).style(style)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .title(" Select Folder to Scan ")
                .borders(Borders::ALL),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    f.render_widget(list, chunks[3]);
}

fn draw_scanning(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // Progress info
            Constraint::Length(3), // Progress bar
            Constraint::Min(3),    // Current file
        ])
        .margin(2)
        .split(area);

    let progress = app.scan_progress.lock().unwrap().clone();

    // Scanning animation
    let dots = ".".repeat((progress.current % 4) + 1);
    let title = format!(" 🔍 Scanning{} ", dots);

    let scan_path = app.scan_path.as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| app.current_path.display().to_string());

    let info = Paragraph::new(vec![
        Line::from(format!("Scanning: {}", scan_path)),
        Line::from(""),
        Line::from(format!(
            "Files processed: {} / {}",
            progress.current, progress.total
        )),
    ])
    .style(Style::default().fg(Color::Yellow))
    .block(Block::default().title(title).borders(Borders::ALL));
    f.render_widget(info, chunks[0]);

    // Progress bar
    let percentage = if progress.total > 0 {
        (progress.current as f64 / progress.total as f64 * 100.0) as u16
    } else {
        0
    };

    let gauge = Gauge::default()
        .block(Block::default().title(" Progress ").borders(Borders::ALL))
        .gauge_style(
            Style::default()
                .fg(Color::Green)
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .percent(percentage)
        .label(format!("{}%", percentage));
    f.render_widget(gauge, chunks[1]);

    // Current file
    let current_file = if progress.current_file.len() > 80 {
        format!("...{}", &progress.current_file[progress.current_file.len() - 77..])
    } else {
        progress.current_file.clone()
    };

    let file_widget = Paragraph::new(current_file)
        .style(Style::default().fg(Color::DarkGray))
        .block(
            Block::default()
                .title(" Current File ")
                .borders(Borders::ALL),
        );
    f.render_widget(file_widget, chunks[2]);
}

fn draw_results(f: &mut Frame, app: &App, area: Rect) {
    let Some(results) = &app.scan_results else {
        return;
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // Summary
            Constraint::Min(10),   // Findings list
        ])
        .split(area);

    // Summary
    let summary_text = vec![
        Line::from(vec![
            Span::raw("Scanned: "),
            Span::styled(
                format!("{} files", results.scanned_files),
                Style::default().fg(Color::Cyan),
            ),
            Span::raw(" in "),
            Span::styled(&results.scan_path, Style::default().fg(Color::Blue)),
        ]),
        Line::from(vec![
            Span::raw("Found: "),
            Span::styled(
                format!("{} CRITICAL", results.summary.critical),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" | "),
            Span::styled(
                format!("{} HIGH", results.summary.high),
                Style::default().fg(Color::LightRed),
            ),
            Span::raw(" | "),
            Span::styled(
                format!("{} MEDIUM", results.summary.medium),
                Style::default().fg(Color::Yellow),
            ),
            Span::raw(" | "),
            Span::styled(
                format!("{} LOW", results.summary.low),
                Style::default().fg(Color::Blue),
            ),
        ]),
    ];

    let status_icon = if results.summary.critical > 0 || results.summary.high > 0 {
        "🚨"
    } else if results.summary.total > 0 {
        "⚠️"
    } else {
        "✅"
    };

    let summary = Paragraph::new(summary_text).block(
        Block::default()
            .title(format!(" {} Scan Results ", status_icon))
            .borders(Borders::ALL)
            .border_style(if results.summary.critical > 0 {
                Style::default().fg(Color::Red)
            } else if results.summary.total > 0 {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default().fg(Color::Green)
            }),
    );
    f.render_widget(summary, chunks[0]);

    // Findings list
    if results.findings.is_empty() {
        let no_findings = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "  ✅ No Shai-Hulud 2.0 indicators found!",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from("  Your codebase appears to be clean."),
        ])
        .block(Block::default().title(" Findings ").borders(Borders::ALL));
        f.render_widget(no_findings, chunks[1]);
    } else {
        // Apply scroll offset to show only visible findings
        let visible_findings: Vec<_> = results
            .findings
            .iter()
            .enumerate()
            .skip(app.results_scroll)
            .collect();

        let items: Vec<ListItem> = visible_findings
            .iter()
            .map(|(i, finding)| {
                let severity_style = Style::default().fg(finding.severity.color());
                let is_selected = *i == app.selected_finding;

                let icon = match finding.finding_type {
                    FindingType::MaliciousFile => "📛",
                    FindingType::MaliciousHash => "🔐",
                    FindingType::SuspiciousPattern => "🔍",
                    FindingType::DangerousHook => "⚡",
                    FindingType::CompromisedPackage => "📦",
                };

                let line_info = finding
                    .line
                    .map(|l| format!(":{}", l))
                    .unwrap_or_default();

                let mut lines = vec![
                    Line::from(vec![
                        Span::styled(
                            format!("[{}] ", finding.severity.as_str()),
                            severity_style.add_modifier(Modifier::BOLD),
                        ),
                        Span::raw(format!("{} ", icon)),
                        Span::styled(
                            format!("{}{}", finding.path, line_info),
                            Style::default().fg(Color::Cyan),
                        ),
                    ]),
                    Line::from(vec![
                        Span::raw("    "),
                        Span::styled(&finding.description, Style::default().fg(Color::White)),
                    ]),
                ];

                if let Some(ctx) = &finding.context {
                    lines.push(Line::from(vec![
                        Span::raw("    "),
                        Span::styled(
                            format!("→ {}", ctx),
                            Style::default().fg(Color::DarkGray),
                        ),
                    ]));
                }

                let style = if is_selected {
                    Style::default().bg(Color::DarkGray)
                } else {
                    Style::default()
                };

                ListItem::new(lines).style(style)
            })
            .collect();

        let scroll_info = if results.findings.len() > 8 {
            format!(" [{}-{}/{}] ", 
                app.results_scroll + 1,
                (app.results_scroll + 8).min(results.findings.len()),
                results.findings.len()
            )
        } else {
            String::new()
        };

        let list = List::new(items).block(
            Block::default()
                .title(format!(" Findings ({}){}", results.findings.len(), scroll_info))
                .borders(Borders::ALL),
        );
        f.render_widget(list, chunks[1]);
    }
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let help_text = match app.state {
        AppState::SelectFolder => {
            "↑/↓: Navigate | Enter: Open folder | Space/s: Scan | n: Toggle node_modules | q: Quit"
        }
        AppState::Scanning => "Scanning in progress... | q: Quit",
        AppState::Results => "↑/↓: Navigate findings | b: Back | s: Rescan | q: Quit",
    };

    let footer = Paragraph::new(help_text)
        .style(Style::default().fg(Color::DarkGray))
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(footer, area);
}
