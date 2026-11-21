use opentelemetry::logs::{LogRecord, Logger, LoggerProvider, Severity};
use opentelemetry::metrics::{Counter, Gauge, Histogram, MeterProvider};
use opentelemetry::{InstrumentationScope, KeyValue};
use opentelemetry_otlp::{WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::logs::{LogBatch, LogExporter, SdkLogRecord, SdkLogger, SdkLoggerProvider};
use opentelemetry_sdk::metrics::data::ResourceMetrics;
use opentelemetry_sdk::metrics::exporter::PushMetricExporter;
use opentelemetry_sdk::metrics::reader::MetricReader;
use opentelemetry_sdk::metrics::{
    InstrumentKind, ManualReader, Pipeline, SdkMeterProvider, Temporality,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime};
use uuid::Uuid;

use super::transport::{Endpoint, OtlpHttpClient, REQUEST_TIMEOUT};

const MAX_QUEUED_LOGS: usize = 256;

#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub struct DeliveryState {
    pub last_success_unix: Option<u64>,
    pub consecutive_failures: u32,
    pub next_attempt_seconds: u64,
}

#[derive(Debug, Clone, Copy)]
pub enum Operation {
    HotspotStart,
    HotspotStop,
    SubscriptionImport,
    SubscriptionRefresh,
    GeoDataUpdate,
    SharingStart,
    TunnelProbe,
    ConflictScan,
    CoreStart,
    SettingsSave,
    Onboarding,
    ReportUpload,
}

impl Operation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HotspotStart => "hotspot_start",
            Self::HotspotStop => "hotspot_stop",
            Self::SubscriptionImport => "subscription_import",
            Self::SubscriptionRefresh => "subscription_refresh",
            Self::GeoDataUpdate => "geodata_update",
            Self::SharingStart => "sharing_start",
            Self::TunnelProbe => "tunnel_probe",
            Self::ConflictScan => "conflict_scan",
            Self::CoreStart => "core_start",
            Self::SettingsSave => "settings_save",
            Self::Onboarding => "onboarding",
            Self::ReportUpload => "report_upload",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ErrorKind {
    Subscription,
    Configuration,
    Core,
    Network,
    Conflict,
    GeoData,
    Settings,
    Timeout,
    Permission,
    Selection,
    Cancelled,
}

impl ErrorKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Subscription => "subscription",
            Self::Configuration => "configuration",
            Self::Core => "core",
            Self::Network => "network",
            Self::Conflict => "conflict",
            Self::GeoData => "geodata",
            Self::Settings => "settings",
            Self::Timeout => "timeout",
            Self::Permission => "permission",
            Self::Selection => "selection",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug)]
struct SharedReader(Arc<ManualReader>);

impl MetricReader for SharedReader {
    fn register_pipeline(&self, pipeline: Weak<Pipeline>) {
        self.0.register_pipeline(pipeline);
    }

    fn collect(&self, metrics: &mut ResourceMetrics) -> OTelSdkResult {
        self.0.collect(metrics)
    }

    fn force_flush(&self) -> OTelSdkResult {
        self.0.force_flush()
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.0.shutdown_with_timeout(timeout)
    }

    fn temporality(&self, kind: InstrumentKind) -> Temporality {
        self.0.temporality(kind)
    }
}

pub(super) struct Session {
    pub enabled: AtomicBool,
    pub started_at: Instant,
    provider: SdkMeterProvider,
    reader: SharedReader,
    metric_exporter: Option<opentelemetry_otlp::MetricExporter>,
    logger_provider: SdkLoggerProvider,
    logger: SdkLogger,
    log_exporter: Option<opentelemetry_otlp::LogExporter>,
    queued_logs: Mutex<Vec<(SdkLogRecord, InstrumentationScope)>>,
    launches: Counter<u64>,
    operations: Counter<u64>,
    errors: Counter<u64>,
    log_entries: Counter<u64>,
    dropped_logs: Counter<u64>,
    operation_duration: Histogram<f64>,
    session_duration: Histogram<f64>,
    active: Gauge<u64>,
    clients: Gauge<u64>,
    uptime: Gauge<f64>,
    availability: Gauge<u64>,
    hotspot_started: Mutex<Option<Instant>>,
    delivery: Mutex<DeliveryState>,
}

impl Session {
    pub fn new(
        endpoint: Option<&Endpoint>,
        client: reqwest::Client,
        token: Option<&str>,
        instance_id: Uuid,
    ) -> Result<Self, String> {
        let resource = Resource::builder_empty()
            .with_service_name("vrghotspot")
            .with_attributes([
                KeyValue::new("service.version", env!("CARGO_PKG_VERSION")),
                KeyValue::new("service.instance.id", instance_id.to_string()),
                KeyValue::new("os.type", std::env::consts::OS),
                KeyValue::new("host.arch", std::env::consts::ARCH),
            ])
            .build();
        let (metric_exporter, log_exporter) = if let Some(endpoint) = endpoint {
            let metrics_url = endpoint.url("v1/metrics");
            let logs_url = endpoint.url("v1/logs");
            let metric_exporter = opentelemetry_otlp::MetricExporter::builder()
                .with_http()
                .with_endpoint(metrics_url.to_string())
                .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
                .with_timeout(REQUEST_TIMEOUT)
                .with_temporality(Temporality::Cumulative)
                .with_http_client(OtlpHttpClient {
                    client: client.clone(),
                    endpoint: metrics_url,
                    token: token.map(str::to_owned),
                })
                .build()
                .map_err(|_| "could not initialize OpenTelemetry metrics")?;
            let mut log_exporter = opentelemetry_otlp::LogExporter::builder()
                .with_http()
                .with_endpoint(logs_url.to_string())
                .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
                .with_timeout(REQUEST_TIMEOUT)
                .with_http_client(OtlpHttpClient {
                    client,
                    endpoint: logs_url,
                    token: token.map(str::to_owned),
                })
                .build()
                .map_err(|_| "could not initialize OpenTelemetry logs")?;
            log_exporter.set_resource(&resource);
            (Some(metric_exporter), Some(log_exporter))
        } else {
            (None, None)
        };
        let reader = SharedReader(Arc::new(ManualReader::default()));
        let provider = SdkMeterProvider::builder()
            .with_resource(resource.clone())
            .with_reader(reader.clone())
            .build();
        let meter = provider.meter("vrghotspot");
        let logger_provider = SdkLoggerProvider::builder().with_resource(resource).build();
        let logger = logger_provider.logger("vrghotspot.operations");
        Ok(Self {
            enabled: AtomicBool::new(true),
            started_at: Instant::now(),
            reader,
            launches: meter
                .u64_counter("vrghotspot.application.launches")
                .with_description("Application launches with telemetry enabled")
                .build(),
            operations: meter
                .u64_counter("vrghotspot.operations")
                .with_description("Completed application operations by outcome")
                .build(),
            errors: meter
                .u64_counter("vrghotspot.errors")
                .with_description("Failed application operations by bounded error category")
                .build(),
            log_entries: meter
                .u64_counter("vrghotspot.log.entries")
                .with_description("Local log entries by severity and component, without messages")
                .build(),
            dropped_logs: meter
                .u64_counter("vrghotspot.log.dropped")
                .with_description("Operational log records dropped at the bounded queue")
                .build(),
            operation_duration: meter
                .f64_histogram("vrghotspot.operation.duration")
                .with_unit("s")
                .with_description("Application operation duration")
                .with_boundaries(vec![0.05, 0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0])
                .build(),
            session_duration: meter
                .f64_histogram("vrghotspot.hotspot.session.duration")
                .with_unit("s")
                .with_description("Hotspot session duration while telemetry was enabled")
                .with_boundaries(vec![1.0, 10.0, 60.0, 300.0, 900.0, 3600.0, 14400.0])
                .build(),
            active: meter
                .u64_gauge("vrghotspot.hotspot.active")
                .with_description("Whether the local hotspot runtime is running")
                .build(),
            clients: meter
                .u64_gauge("vrghotspot.hotspot.clients")
                .with_description("Most recently observed connected hotspot clients")
                .build(),
            uptime: meter
                .f64_gauge("vrghotspot.application.uptime")
                .with_unit("s")
                .with_description("Time since telemetry was enabled in this process")
                .build(),
            availability: meter
                .u64_gauge("vrghotspot.connectivity.available")
                .with_description(
                    "Whether the last attempted connectivity surface worked: 1 available, 0 failed, per surface",
                )
                .build(),
            provider,
            metric_exporter,
            logger_provider,
            logger,
            log_exporter,
            queued_logs: Mutex::new(Vec::new()),
            hotspot_started: Mutex::new(None),
            delivery: Mutex::new(DeliveryState::default()),
        })
    }

    pub fn launch(&self) {
        self.launches.add(1, &[]);
    }

    pub fn record_operation(
        &self,
        operation: Operation,
        elapsed: Duration,
        error: Option<ErrorKind>,
    ) {
        if !self.enabled.load(Ordering::Acquire) {
            return;
        }
        let outcome = match error {
            Some(ErrorKind::Cancelled) => "cancelled",
            Some(_) => "error",
            None => "success",
        };
        let attributes = [
            KeyValue::new("operation", operation.as_str()),
            KeyValue::new("outcome", outcome),
        ];
        self.operations.add(1, &attributes);
        self.operation_duration
            .record(elapsed.as_secs_f64(), &attributes);
        if let Some(error) = error {
            self.errors.add(
                1,
                &[
                    KeyValue::new("operation", operation.as_str()),
                    KeyValue::new("error.type", error.as_str()),
                ],
            );
        }
        let mut record = self.logger.create_log_record();
        let now = SystemTime::now();
        record.set_timestamp(now);
        record.set_observed_timestamp(now);
        record.set_severity_number(if error.is_some() {
            Severity::Warn
        } else {
            Severity::Info
        });
        record.set_severity_text(if error.is_some() { "WARN" } else { "INFO" });
        record.set_body("application operation completed".into());
        record.add_attribute("operation", operation.as_str());
        record.add_attribute("outcome", outcome);
        record.add_attribute("duration_seconds", elapsed.as_secs_f64());
        if let Some(error) = error {
            record.add_attribute("error.type", error.as_str());
        }
        if let Ok(mut logs) = self.queued_logs.lock() {
            if logs.len() < MAX_QUEUED_LOGS {
                logs.push((
                    record,
                    InstrumentationScope::builder("vrghotspot.operations").build(),
                ));
            } else {
                self.dropped_logs.add(1, &[]);
            }
        }
    }

    pub fn log(&self, level: &tracing::Level, target: &str) {
        if !self.enabled.load(Ordering::Acquire) {
            return;
        }
        let component = if target == "core_bridge" {
            "mihomo"
        } else if target.starts_with("vrghotspot::os") {
            "network"
        } else if target.starts_with("vrghotspot") {
            "application"
        } else {
            return;
        };
        self.log_entries.add(
            1,
            &[
                KeyValue::new("level", level.as_str()),
                KeyValue::new("component", component),
            ],
        );
    }

    pub fn hotspot_state(&self, running: bool) {
        if !self.enabled.load(Ordering::Acquire) {
            return;
        }
        self.active.record(u64::from(running), &[]);
        if let Ok(mut started) = self.hotspot_started.lock() {
            if running {
                started.get_or_insert_with(Instant::now);
            } else if let Some(started) = started.take() {
                self.session_duration
                    .record(started.elapsed().as_secs_f64(), &[]);
                self.clients.record(0, &[]);
            }
        }
    }

    pub fn clients(&self, count: u32) {
        if self.enabled.load(Ordering::Acquire) {
            self.clients.record(u64::from(count), &[]);
        }
    }

    /// Outcome of one connectivity check. Surfaces are a closed, low-cardinality
    /// set: a checked-in VPN core ("vpn"), the Wi-Fi access point ("hotspot"),
    /// and verified internet through the tunnel ("internet").
    pub fn availability(&self, surface: &'static str, available: bool) {
        if self.enabled.load(Ordering::Acquire) {
            self.availability
                .record(u64::from(available), &[KeyValue::new("surface", surface)]);
        }
    }

    pub fn delivery(&self) -> DeliveryState {
        self.delivery.lock().map(|state| *state).unwrap_or_default()
    }

    pub fn record_delivery(&self, succeeded: bool, next_attempt_in: Duration) {
        if let Ok(mut state) = self.delivery.lock() {
            if succeeded {
                state.last_success_unix = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .ok()
                    .map(|elapsed| elapsed.as_secs());
                state.consecutive_failures = 0;
            } else {
                state.consecutive_failures = state.consecutive_failures.saturating_add(1);
            }
            state.next_attempt_seconds = next_attempt_in.as_secs();
        }
    }

    #[cfg(test)]
    pub fn queued_log_count(&self) -> usize {
        self.queued_logs.lock().map(|logs| logs.len()).unwrap_or(0)
    }

    pub async fn export(&self) -> Result<(), String> {
        if !self.enabled.load(Ordering::Acquire) {
            return Ok(());
        }
        self.uptime
            .record(self.started_at.elapsed().as_secs_f64(), &[]);
        let metrics = async {
            if let Some(exporter) = &self.metric_exporter {
                let mut metrics = ResourceMetrics::default();
                self.reader
                    .collect(&mut metrics)
                    .map_err(|_| "metric collection failed")?;
                exporter
                    .export(&metrics)
                    .await
                    .map_err(|_| "metric export failed")?;
            }
            Ok::<(), String>(())
        };
        let logs = async {
            if let Some(exporter) = &self.log_exporter {
                let records = self
                    .queued_logs
                    .lock()
                    .map(|logs| logs.clone())
                    .unwrap_or_default();
                if !records.is_empty() {
                    let borrowed = records
                        .iter()
                        .map(|(record, scope)| (record, scope))
                        .collect::<Vec<_>>();
                    exporter
                        .export(LogBatch::new(&borrowed))
                        .await
                        .map_err(|_| "operational log export failed")?;
                    if let Ok(mut queue) = self.queued_logs.lock() {
                        let delivered = records.len().min(queue.len());
                        queue.drain(..delivered);
                    }
                }
            } else if let Ok(mut queue) = self.queued_logs.lock() {
                queue.clear();
            }
            Ok::<(), String>(())
        };
        let (metrics, logs) = tokio::join!(metrics, logs);
        metrics.and(logs)
    }

    pub fn shutdown(&self) {
        self.enabled.store(false, Ordering::Release);
        if let Ok(mut queue) = self.queued_logs.lock() {
            queue.clear();
        }
        let _ = self.provider.shutdown();
        let _ = self.logger_provider.shutdown();
    }
}

pub struct OperationGuard {
    pub(super) session: Option<Arc<Session>>,
    pub(super) operation: Operation,
    pub(super) started_at: Instant,
}

impl OperationGuard {
    pub fn finish(mut self, error: Option<ErrorKind>) {
        if let Some(session) = self.session.take() {
            session.record_operation(self.operation, self.started_at.elapsed(), error);
        }
    }
}

impl Drop for OperationGuard {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            session.record_operation(
                self.operation,
                self.started_at.elapsed(),
                Some(ErrorKind::Cancelled),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};

    fn session() -> Session {
        Session::new(
            None,
            super::super::transport::client().unwrap(),
            None,
            Uuid::new_v4(),
        )
        .unwrap()
    }

    #[test]
    fn operation_metrics_have_only_bounded_attributes() {
        let session = session();
        session.record_operation(
            Operation::HotspotStart,
            Duration::from_secs(2),
            Some(ErrorKind::Permission),
        );
        let mut collected = ResourceMetrics::default();
        session.reader.collect(&mut collected).unwrap();
        let metrics = collected
            .scope_metrics()
            .flat_map(|scope| scope.metrics())
            .collect::<Vec<_>>();
        let counter = metrics
            .iter()
            .find(|metric| metric.name() == "vrghotspot.errors")
            .unwrap();
        let AggregatedMetrics::U64(MetricData::Sum(sum)) = counter.data() else {
            panic!("expected counter")
        };
        let point = sum.data_points().next().unwrap();
        assert_eq!(point.value(), 1);
        assert_eq!(point.attributes().count(), 2);
        let names = collected
            .resource()
            .iter()
            .map(|(key, _)| key.as_str().to_owned())
            .collect::<Vec<_>>();
        assert!(
            !names
                .iter()
                .any(|key| key.contains("installation") || key.contains("host.name"))
        );
        session.shutdown();
    }

    #[test]
    fn disabled_sessions_discard_measurements_and_logs() {
        let session = session();
        session.enabled.store(false, Ordering::Release);
        session.record_operation(Operation::HotspotStart, Duration::from_secs(1), None);
        session.log(&tracing::Level::ERROR, "vrghotspot::app");
        assert!(session.queued_logs.lock().unwrap().is_empty());
        let mut collected = ResourceMetrics::default();
        session.reader.collect(&mut collected).unwrap();
        assert_eq!(
            collected
                .scope_metrics()
                .flat_map(|scope| scope.metrics())
                .count(),
            0
        );
        session.shutdown();
    }

    #[test]
    fn operational_logs_are_bounded_and_do_not_include_raw_errors() {
        let session = session();
        for _ in 0..MAX_QUEUED_LOGS + 4 {
            session.record_operation(
                Operation::SubscriptionImport,
                Duration::from_millis(2),
                Some(ErrorKind::Subscription),
            );
        }
        let records = session.queued_logs.lock().unwrap();
        assert_eq!(records.len(), MAX_QUEUED_LOGS);
        assert!(records.iter().all(|(record, _)| {
            format!("{:?}", record.body()).contains("application operation completed")
        }));
        drop(records);
        session.shutdown();
    }

    #[test]
    fn operational_logs_carry_the_timestamps_the_otlp_encoder_requires() {
        let session = session();
        session.record_operation(Operation::CoreStart, Duration::from_millis(5), None);
        let records = session.queued_logs.lock().unwrap();
        let (record, _) = records.first().unwrap();
        assert!(record.timestamp().is_some());
        assert!(
            record.observed_timestamp().is_some(),
            "a missing observed timestamp aborts the process inside the OTLP encoder"
        );
        drop(records);
        session.shutdown();
    }
}
