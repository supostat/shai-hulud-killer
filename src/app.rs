use crate::scanner::{ScanConfig, ScanResults};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, PartialEq)]
pub enum AppState {
    SelectFolder,
    Scanning,
    Results,
}

pub struct App {
    pub state: AppState,
    pub should_quit: bool,

    // Folder selection
    pub current_path: PathBuf,
    pub entries: Vec<DirEntry>,
    pub selected_index: usize,
    pub scroll_offset: usize,

    // Scan config
    pub include_node_modules: bool,

    // Scanning state
    pub scan_progress: Arc<Mutex<ScanProgress>>,
    pub scan_results: Option<ScanResults>,
    pub scan_path: Option<PathBuf>,

    // Results navigation
    pub results_scroll: usize,
    pub selected_finding: usize,
}

#[derive(Clone)]
pub struct DirEntry {
    pub name: String,
    pub path: PathBuf,
    pub is_dir: bool,
}

#[derive(Default, Clone)]
pub struct ScanProgress {
    pub current: usize,
    pub total: usize,
    pub current_file: String,
    pub finished: bool,
}

impl App {
    pub fn new(initial_path: Option<PathBuf>, include_node_modules: bool) -> anyhow::Result<Self> {
        let current_path = initial_path.unwrap_or_else(|| {
            std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"))
        });

        let mut app = Self {
            state: AppState::SelectFolder,
            should_quit: false,
            current_path: current_path.clone(),
            entries: Vec::new(),
            selected_index: 0,
            scroll_offset: 0,
            include_node_modules,
            scan_progress: Arc::new(Mutex::new(ScanProgress::default())),
            scan_results: None,
            scan_path: None,
            results_scroll: 0,
            selected_finding: 0,
        };

        app.refresh_entries()?;
        Ok(app)
    }

    pub fn refresh_entries(&mut self) -> anyhow::Result<()> {
        self.entries.clear();

        // Add parent directory entry
        if let Some(parent) = self.current_path.parent() {
            self.entries.push(DirEntry {
                name: "..".to_string(),
                path: parent.to_path_buf(),
                is_dir: true,
            });
        }

        // Read directory contents
        if let Ok(read_dir) = std::fs::read_dir(&self.current_path) {
            let mut dirs: Vec<DirEntry> = Vec::new();
            let mut files: Vec<DirEntry> = Vec::new();

            for entry in read_dir.filter_map(|e| e.ok()) {
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_string();
                let is_dir = path.is_dir();

                // Skip hidden files/dirs except ..
                if name.starts_with('.') && name != ".." {
                    continue;
                }

                let dir_entry = DirEntry { name, path, is_dir };

                if is_dir {
                    dirs.push(dir_entry);
                } else {
                    files.push(dir_entry);
                }
            }

            // Sort alphabetically
            dirs.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
            files.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

            self.entries.extend(dirs);
            self.entries.extend(files);
        }

        self.selected_index = 0;
        self.scroll_offset = 0;
        Ok(())
    }

    pub fn navigate_up(&mut self) {
        if self.selected_index > 0 {
            self.selected_index -= 1;
            self.adjust_scroll();
        }
    }

    pub fn navigate_down(&mut self) {
        if self.selected_index < self.entries.len().saturating_sub(1) {
            self.selected_index += 1;
            self.adjust_scroll();
        }
    }

    fn adjust_scroll(&mut self) {
        let visible_height = 20; // Approximate visible items
        if self.selected_index < self.scroll_offset {
            self.scroll_offset = self.selected_index;
        } else if self.selected_index >= self.scroll_offset + visible_height {
            self.scroll_offset = self.selected_index - visible_height + 1;
        }
    }

    pub fn enter_selected(&mut self) -> anyhow::Result<()> {
        if let Some(entry) = self.entries.get(self.selected_index).cloned() {
            if entry.is_dir {
                self.current_path = entry.path;
                self.refresh_entries()?;
            }
        }
        Ok(())
    }

    pub fn go_parent(&mut self) -> anyhow::Result<()> {
        if let Some(parent) = self.current_path.parent() {
            self.current_path = parent.to_path_buf();
            self.refresh_entries()?;
        }
        Ok(())
    }

    pub fn get_selected_path(&self) -> PathBuf {
        // Get the path of the currently selected/highlighted entry
        if let Some(entry) = self.entries.get(self.selected_index) {
            if entry.is_dir {
                entry.path.clone()
            } else {
                // If a file is selected, scan its parent directory
                self.current_path.clone()
            }
        } else {
            self.current_path.clone()
        }
    }

    pub fn start_scan(&mut self) {
        self.state = AppState::Scanning;
        self.scan_results = None;

        // Reset progress
        if let Ok(mut progress) = self.scan_progress.lock() {
            *progress = ScanProgress::default();
        }

        // Use the selected/highlighted folder, not the current view folder
        let path = self.get_selected_path();
        self.scan_path = Some(path.clone());
        let config = ScanConfig {
            include_node_modules: self.include_node_modules,
        };
        let progress = self.scan_progress.clone();

        // Spawn scanning thread
        std::thread::spawn(move || {
            let callback_progress = progress.clone();
            let callback = Box::new(move |current: usize, total: usize, file: &str| {
                if let Ok(mut p) = callback_progress.lock() {
                    p.current = current;
                    p.total = total;
                    p.current_file = file.to_string();
                }
            });

            let results = crate::scanner::scan_directory_with_progress(&path, &config, callback);

            if let Ok(mut p) = progress.lock() {
                p.finished = true;
            }

            results
        });
    }

    pub fn check_scan_complete(&mut self) -> Option<ScanResults> {
        let finished = self
            .scan_progress
            .lock()
            .map(|p| p.finished)
            .unwrap_or(false);

        if finished && self.scan_results.is_none() {
            // Perform scan again to get results (since thread result isn't easily accessible)
            let config = ScanConfig {
                include_node_modules: self.include_node_modules,
            };
            let scan_path = self.scan_path.clone().unwrap_or_else(|| self.current_path.clone());
            if let Ok(results) =
                crate::scanner::scan_directory_sync(&scan_path, &config)
            {
                self.scan_results = Some(results.clone());
                self.state = AppState::Results;
                return Some(results);
            }
        }
        None
    }

    pub fn toggle_node_modules(&mut self) {
        self.include_node_modules = !self.include_node_modules;
    }

    pub fn results_up(&mut self) {
        if self.selected_finding > 0 {
            self.selected_finding -= 1;
            self.adjust_results_scroll();
        }
    }

    pub fn results_down(&mut self) {
        if let Some(results) = &self.scan_results {
            if self.selected_finding < results.findings.len().saturating_sub(1) {
                self.selected_finding += 1;
                self.adjust_results_scroll();
            }
        }
    }

    fn adjust_results_scroll(&mut self) {
        let visible_height = 8; // Approximate visible findings (each takes ~3 lines)
        if self.selected_finding < self.results_scroll {
            self.results_scroll = self.selected_finding;
        } else if self.selected_finding >= self.results_scroll + visible_height {
            self.results_scroll = self.selected_finding - visible_height + 1;
        }
    }

    pub fn back_to_folder_select(&mut self) {
        self.state = AppState::SelectFolder;
        self.scan_results = None;
        self.scan_path = None;
        self.selected_finding = 0;
        self.results_scroll = 0;
    }
}
