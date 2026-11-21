use crate::telemetry::Telemetry;
use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppLogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl AppLogLevel {
    pub const ALL: [Self; 4] = [Self::Debug, Self::Info, Self::Warn, Self::Error];

    pub fn allows(self, entry: &LogEntry) -> bool {
        entry.effective_level().severity() >= self.severity()
    }

    fn severity(self) -> u8 {
        match self {
            Self::Debug => 0,
            Self::Info => 1,
            Self::Warn => 2,
            Self::Error => 3,
        }
    }
}

impl std::fmt::Display for AppLogLevel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Debug => "Debug",
            Self::Info => "Info",
            Self::Warn => "Warn",
            Self::Error => "Error",
        })
    }
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: SystemTime,
    pub level: Level,
    pub target: String,
    pub message: String,
}

impl LogEntry {
    pub fn effective_level(&self) -> AppLogLevel {
        if self.target.starts_with("tauri") {
            return AppLogLevel::Debug;
        }

        match self.level {
            Level::ERROR => AppLogLevel::Error,
            Level::WARN => AppLogLevel::Warn,
            Level::INFO => AppLogLevel::Info,
            Level::DEBUG | Level::TRACE => AppLogLevel::Debug,
        }
    }
}

#[derive(Debug, Clone)]
pub struct InMemoryLogStore {
    inner: Arc<Mutex<VecDeque<LogEntry>>>,
    capacity: usize,
}

impl InMemoryLogStore {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::with_capacity(capacity))),
            capacity,
        }
    }

    pub fn entries(&self) -> Vec<LogEntry> {
        self.inner
            .lock()
            .map(|entries| entries.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn clear(&self) {
        if let Ok(mut entries) = self.inner.lock() {
            entries.clear();
        }
    }

    fn push(&self, mut entry: LogEntry) {
        if self.capacity == 0 {
            return;
        }
        entry.message = crate::telemetry::redaction::truncate(&entry.message, 64 * 1024);
        if let Ok(mut entries) = self.inner.lock() {
            while entries.len() >= self.capacity {
                entries.pop_front();
            }
            entries.push_back(entry);
        }
    }
}

impl Default for InMemoryLogStore {
    fn default() -> Self {
        Self::new(2_000)
    }
}

#[derive(Debug, Clone)]
pub struct InMemoryLogLayer {
    store: InMemoryLogStore,
    telemetry: Telemetry,
}

impl InMemoryLogLayer {
    pub fn new(store: InMemoryLogStore) -> Self {
        Self {
            store,
            telemetry: Telemetry::default(),
        }
    }

    pub fn with_telemetry(store: InMemoryLogStore, telemetry: Telemetry) -> Self {
        Self { store, telemetry }
    }
}

impl<S> Layer<S> for InMemoryLogLayer
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
{
    fn on_event(&self, event: &Event<'_>, context: Context<'_, S>) {
        let metadata = event.metadata();
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        let mut message = visitor.finish();
        if let Some(scope) = context.event_scope(event) {
            let names = scope
                .from_root()
                .map(|span| span.name())
                .collect::<Vec<_>>();
            if !names.is_empty() {
                message = format!("[{context}] {message}", context = names.join(" > "));
            }
        }
        self.telemetry.log(metadata.level(), metadata.target());
        self.store.push(LogEntry {
            timestamp: SystemTime::now(),
            level: *metadata.level(),
            target: metadata.target().to_owned(),
            message,
        });
    }
}

#[derive(Default)]
struct MessageVisitor {
    message: Option<String>,
    fields: Vec<String>,
}

impl MessageVisitor {
    fn finish(self) -> String {
        match (self.message, self.fields.is_empty()) {
            (Some(message), true) => message,
            (Some(message), false) => format!("{} {}", message, self.fields.join(" ")),
            (None, true) => String::new(),
            (None, false) => self.fields.join(" "),
        }
    }
}

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{value:?}"));
        } else {
            self.fields.push(format!("{}={value:?}", field.name()));
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_owned());
        } else {
            self.fields.push(format!("{}={value}", field.name()));
        }
    }

    fn record_error(
        &mut self,
        field: &tracing::field::Field,
        value: &(dyn std::error::Error + 'static),
    ) {
        self.fields.push(format!("{}={value}", field.name()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::layer::SubscriberExt;

    #[test]
    fn keeps_operation_context_and_bounds_entries() {
        let store = InMemoryLogStore::new(2);
        let subscriber = tracing_subscriber::registry().with(InMemoryLogLayer::new(store.clone()));
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("hotspot_start");
            let _entered = span.enter();
            tracing::info!("first");
            tracing::warn!("second");
            tracing::error!("third");
        });
        let entries = store.entries();
        assert_eq!(entries.len(), 2);
        assert!(entries[0].message.contains("[hotspot_start] second"));
        assert_eq!(entries[1].level, Level::ERROR);
        store.clear();
        assert!(store.entries().is_empty());
    }

    #[test]
    fn zero_capacity_discards_logs() {
        let store = InMemoryLogStore::new(0);
        store.push(LogEntry {
            timestamp: SystemTime::now(),
            level: Level::INFO,
            target: "test".to_owned(),
            message: "test".to_owned(),
        });
        assert!(store.entries().is_empty());
    }
}
