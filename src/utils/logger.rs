use colored::*;
use log::{Level, LevelFilter, Metadata, Record};

pub struct VenomLogger;

impl log::Log for VenomLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Debug
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let level = match record.level() {
                Level::Error => "ERROR".red().bold(),
                Level::Warn => "WARN".yellow().bold(),
                Level::Info => "INFO".green().bold(),
                Level::Debug => "DEBUG".blue().bold(),
                Level::Trace => "TRACE".white(),
            };
            eprintln!("[{}] {}", level, record.args());
        }
    }

    fn flush(&self) {}
}

pub fn init_logger(verbose: bool) {
    let level = if verbose { LevelFilter::Debug } else { LevelFilter::Info };
    let _ = log::set_boxed_logger(Box::new(VenomLogger))
        .map(|()| log::set_max_level(level));
}