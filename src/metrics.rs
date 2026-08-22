//! Prometheus metrics for the Sentiel ingestion pipeline (issue #4).

use prometheus::{
    Encoder, Histogram, HistogramOpts, IntCounter, IntCounterVec, Opts, Registry, TextEncoder,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct Metrics {
    registry: Arc<Registry>,
    pub events_ingested: IntCounterVec,
    pub dlp_violations: IntCounter,
    pub anomaly_alerts: IntCounter,
    pub ingest_latency: Histogram,
}

impl Metrics {
    pub fn new() -> anyhow::Result<Self> {
        let registry = Arc::new(Registry::new());
        let events_ingested = IntCounterVec::new(
            Opts::new(
                "sentiel_events_ingested_total",
                "Events ingested by source and type",
            ),
            &["source", "event_type"],
        )?;
        let dlp_violations =
            IntCounter::new("sentiel_dlp_violations_total", "DLP violations detected")?;
        let anomaly_alerts =
            IntCounter::new("sentiel_anomaly_alerts_total", "Anomaly alerts raised")?;
        let ingest_latency = Histogram::with_opts(HistogramOpts::new(
            "sentiel_ingest_duration_seconds",
            "Event ingest latency",
        ))?;
        registry.register(Box::new(events_ingested.clone()))?;
        registry.register(Box::new(dlp_violations.clone()))?;
        registry.register(Box::new(anomaly_alerts.clone()))?;
        registry.register(Box::new(ingest_latency.clone()))?;
        Ok(Self {
            registry,
            events_ingested,
            dlp_violations,
            anomaly_alerts,
            ingest_latency,
        })
    }

    /// Render all metrics in Prometheus text exposition format.
    pub fn render(&self) -> String {
        let encoder = TextEncoder::new();
        let mut buffer = Vec::new();
        if let Err(e) = encoder.encode(&self.registry.gather(), &mut buffer) {
            tracing::error!("metrics encode failed: {e}");
            return String::new();
        }
        String::from_utf8(buffer).unwrap_or_default()
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new().expect("default metrics")
    }
}
