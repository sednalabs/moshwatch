// SPDX-License-Identifier: AGPL-3.0-or-later

pub mod config;
pub mod identity;
pub mod observability;
pub mod protocol;
pub mod time;

pub use config::{
    AppConfig, HealthThresholds, MetricsConfig, OtlpMetricsConfig, PrometheusMetricsConfig,
    RuntimePaths, remove_socket_if_present, set_socket_owner_only,
};
pub use identity::{ObserverInfo, discover_observer_info};
pub use observability::{
    METRIC_CATALOG, MetricCardinality, MetricDescriptor, MetricId, MetricKind, MetricLabelSchema,
    MetricPrivacy, MetricType, MetricsDetailLevel, MetricsDetailTier, metric_catalog,
    metric_descriptor,
};
pub use protocol::{
    ADAPTER_CONTRACT_VERSION, API_SCHEMA_VERSION, AdapterExportSurface,
    ApiAdapterCapabilitiesResponse, ApiAppConfig, ApiCoherenceExportResponse,
    ApiCoherenceSessionResponse, ApiCoherenceSessionsResponse, ApiConfigResponse,
    ApiHistoryResponse, ApiMetricsConfig, ApiSessionControlResponse, ApiSessionResponse,
    ApiSessionsResponse, COHERENCE_EXPORT_VERSION, CoherenceAdjudication,
    CoherenceContinuitySummary, CoherenceExportEnvelope, CoherenceExportGuarantees,
    CoherenceRedactionProfile, CoherenceRouteEpoch, CoherenceSafetyBoundary,
    CoherenceSessionReport, CoherenceSessionSnapshot, EventStreamEvent, EventStreamFrame,
    HealthState, HistorySample, MetricPoint, RetransmitWindowBreakdown, SessionControlAction,
    SessionKind, SessionMetrics, SessionPeerInfo, SessionSnapshot, SessionSummary, TelemetryEvent,
    TelemetryEventKind, adapter_export_surfaces, build_coherence_export,
    build_coherence_session_report, build_coherence_snapshot_from_summary, classify_health,
    stable_digest_label,
};
