// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared API, event-stream, and telemetry protocol contracts.
//!
//! ## Rationale
//! `moshwatch-core` is the narrow contract surface shared by the daemon, UI,
//! and any future API consumers. Keeping these types in one place makes schema
//! changes explicit.
//!
//! ## Security Boundaries
//! * These types describe local observability data only; they do not verify
//!   trust by themselves.
//! * `None` on optional metrics generally means "unknown or unavailable", not
//!   zero.
//! * Event-stream frames are latest-state snapshots, not a durable replay log.
//!
//! ## References
//! * `docs/design/modularisation-and-boundaries.md`

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Version number for the exported API and event-stream schema.
///
/// Bump this only when a consumer-visible contract changes.
pub const API_SCHEMA_VERSION: u32 = 5;

/// Version string for redacted coherence exports.
pub const COHERENCE_EXPORT_VERSION: &str = "moshwatch-coherence-export-v1";

/// Version string for the out-of-process adapter contract.
pub const ADAPTER_CONTRACT_VERSION: &str = "moshwatch-adapter-contract-v1";

/// Schema version implied by REST responses from daemons older than v4.
pub const LEGACY_REST_SCHEMA_VERSION: u32 = 2;

fn default_rest_schema_version() -> u32 {
    LEGACY_REST_SCHEMA_VERSION
}

/// Session classification used throughout the API and history surface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SessionKind {
    /// Session with verified local telemetry from the instrumented server.
    Instrumented,
    /// Session discovered via `/proc` only, without verified telemetry.
    Legacy,
}

/// High-level operator health state derived from configured thresholds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    /// No configured latency, silence, or retransmit threshold is currently breached.
    Ok,
    /// At least one warning threshold is currently breached.
    Degraded,
    /// At least one critical threshold is currently breached.
    Critical,
    /// Legacy discovery-only session without verified telemetry.
    Legacy,
}

/// Lifecycle event emitted by the instrumented `mosh-server-real` wrapper.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryEventKind {
    /// Session start/open event.
    SessionOpen,
    /// Periodic metrics update from a live session.
    SessionTick,
    /// Session close/shutdown event.
    SessionClose,
}

/// Raw counter deltas used to explain a retransmit percentage window.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(default)]
pub struct RetransmitWindowBreakdown {
    /// Total transmissions in the window: state updates + retransmits + empty ACKs.
    pub transmissions_total: Option<u64>,
    /// Total retransmit packets observed in the window.
    pub retransmits_total: Option<u64>,
    /// Total state-update packets observed in the window.
    pub state_updates_total: Option<u64>,
    /// Total empty ACK packets observed in the window.
    pub empty_acks_total: Option<u64>,
}

/// Current per-session live metrics and bounded window summaries.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SessionMetrics {
    /// Smoothed round-trip time in milliseconds.
    pub srtt_ms: Option<f64>,
    /// RTT variation estimate in milliseconds.
    pub rttvar_ms: Option<f64>,
    /// Most recent raw RTT sample in milliseconds.
    pub last_rtt_ms: Option<f64>,
    /// Time since the daemon last heard session traffic, in milliseconds.
    pub last_heard_age_ms: Option<u64>,
    /// Time since the remote state last advanced, in milliseconds.
    pub remote_state_age_ms: Option<u64>,
    /// Monotonic total transmitted packets reported by telemetry.
    pub packets_tx_total: Option<u64>,
    /// Monotonic total received packets reported by telemetry.
    pub packets_rx_total: Option<u64>,
    /// Monotonic total retransmitted packets reported by telemetry.
    pub retransmits_total: Option<u64>,
    /// Monotonic total transmitted empty ACK packets.
    pub empty_acks_tx_total: Option<u64>,
    /// Monotonic total transmitted state-update packets.
    pub state_updates_tx_total: Option<u64>,
    /// Monotonic total received state-update packets.
    pub state_updates_rx_total: Option<u64>,
    /// Monotonic total duplicate state packets received.
    pub duplicate_states_rx_total: Option<u64>,
    /// Monotonic total out-of-order state packets received.
    pub out_of_order_states_rx_total: Option<u64>,
    /// Retransmit ratio over the trailing 10-second window, or `None` when unknown.
    pub retransmit_pct_10s: Option<f64>,
    /// Retransmit ratio over the trailing 60-second window, or `None` when unknown.
    pub retransmit_pct_60s: Option<f64>,
    /// Whether the daemon has at least 10 seconds of history for the window.
    pub retransmit_window_10s_complete: bool,
    /// Whether the daemon has at least 60 seconds of history for the window.
    pub retransmit_window_60s_complete: bool,
    /// Raw counter math behind the 10-second retransmit window.
    pub retransmit_window_10s_breakdown: RetransmitWindowBreakdown,
    /// Raw counter math behind the 60-second retransmit window.
    pub retransmit_window_60s_breakdown: RetransmitWindowBreakdown,
}

/// Single history point used by session-detail sparklines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricPoint {
    /// Sample timestamp in Unix milliseconds.
    pub unix_ms: i64,
    /// Smoothed RTT sample at this point, if known.
    pub srtt_ms: Option<f64>,
    /// 10-second retransmit percentage at this point, if known.
    pub retransmit_pct_10s: Option<f64>,
    /// Remote-state age at this point, if known.
    pub remote_state_age_ms: Option<u64>,
    /// Remote client address currently attached at this point, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_client_addr: Option<String>,
}

/// Redacted route epoch inferred from endpoint continuity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CoherenceRouteEpoch {
    /// Zero-based epoch index in chronological order.
    pub epoch_index: usize,
    /// First sample timestamp for this epoch.
    pub start_unix_ms: i64,
    /// Last sample timestamp for this epoch.
    pub end_unix_ms: i64,
    /// Number of samples represented by this epoch.
    pub sample_count: usize,
    /// Stable digest label for the endpoint, never the endpoint value itself.
    pub endpoint_label: Option<String>,
    /// Endpoint values are never retained in coherence exports.
    pub endpoint_value_retained: bool,
}

/// Metadata-only continuity summary for one observed session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CoherenceContinuitySummary {
    pub stable_session_identity: bool,
    pub route_epoch_count: usize,
    pub route_shift_count: usize,
    pub history_sample_count: usize,
    pub max_sample_gap_ms: Option<i64>,
    pub recovery_after_drift: bool,
    pub liveness_signal_present: bool,
    pub packet_counter_signal_present: bool,
    pub retransmit_signal_present: bool,
}

/// Defensive adjudication over one coherence report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CoherenceAdjudication {
    pub decision: String,
    pub confidence_score: f64,
    pub false_stitch_rejected: bool,
    pub caveats: Vec<String>,
}

/// Hard privacy boundary carried with coherence exports.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoherenceSafetyBoundary {
    pub defensive_observability_only: bool,
    pub packet_payload_retained: bool,
    pub raw_packet_capture_retained: bool,
    pub session_keys_retained: bool,
    pub terminal_content_retained: bool,
    pub endpoint_values_redacted: bool,
    pub application_semantics_inferred: bool,
}

/// Compact coherence status used in latest-state event frames.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CoherenceSessionSnapshot {
    pub session_id_label: String,
    pub kind: SessionKind,
    pub health: HealthState,
    pub route_shift_observed: bool,
    pub endpoint_values_retained: bool,
    pub confidence_score: f64,
}

/// Full metadata-only coherence report for one session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CoherenceSessionReport {
    pub report_version: String,
    pub observer_label: String,
    pub session_id_label: String,
    pub display_session_id_present: bool,
    pub kind: SessionKind,
    pub health: HealthState,
    pub udp_port_observed: bool,
    pub route_epochs: Vec<CoherenceRouteEpoch>,
    pub continuity: CoherenceContinuitySummary,
    pub adjudication: CoherenceAdjudication,
    pub safety_boundary: CoherenceSafetyBoundary,
}

/// Response body for `GET /v1/coherence/sessions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCoherenceSessionsResponse {
    #[serde(default = "default_rest_schema_version")]
    pub schema_version: u32,
    pub observer: crate::identity::ObserverInfo,
    pub generated_at_unix_ms: i64,
    pub total_sessions: usize,
    pub truncated_session_count: usize,
    pub sessions: Vec<CoherenceSessionReport>,
}

/// Response body for `GET /v1/coherence/sessions/:id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCoherenceSessionResponse {
    #[serde(default = "default_rest_schema_version")]
    pub schema_version: u32,
    pub observer: crate::identity::ObserverInfo,
    pub generated_at_unix_ms: i64,
    pub session: CoherenceSessionReport,
}

/// Redaction metadata for coherence exports.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoherenceRedactionProfile {
    pub profile_id: String,
    pub endpoint_values_retained: bool,
    pub session_id_values_retained: bool,
    pub observer_values_retained: bool,
    pub packet_or_terminal_content_retained: bool,
}

/// Privacy and interpretation guarantees attached to a coherence export.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoherenceExportGuarantees {
    pub packet_payload_retained: bool,
    pub terminal_content_retained: bool,
    pub session_keys_retained: bool,
    pub endpoint_values_retained: bool,
    pub application_semantics_inferred: bool,
}

/// Metadata-only export envelope for one coherence report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CoherenceExportEnvelope {
    pub schema_version: u32,
    pub export_version: String,
    pub generated_at_unix_ms: i64,
    pub observer_label: String,
    pub session_id_label: String,
    pub report: CoherenceSessionReport,
    pub redaction: CoherenceRedactionProfile,
    pub export_guarantees: CoherenceExportGuarantees,
    pub export_digest: String,
}

/// Response body for `GET /v1/coherence/exports/:id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCoherenceExportResponse {
    #[serde(default = "default_rest_schema_version")]
    pub schema_version: u32,
    pub observer: crate::identity::ObserverInfo,
    pub generated_at_unix_ms: i64,
    pub export: CoherenceExportEnvelope,
}

/// One stable export surface available to out-of-process adapters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterExportSurface {
    pub surface_id: String,
    pub route_template: String,
    pub export_version: String,
    pub privacy_profile: String,
    pub description: String,
    pub stable_for_external_adapters: bool,
}

/// Response body for `GET /v1/adapter/capabilities`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiAdapterCapabilitiesResponse {
    #[serde(default = "default_rest_schema_version")]
    pub schema_version: u32,
    pub observer: crate::identity::ObserverInfo,
    pub generated_at_unix_ms: i64,
    pub adapter_contract_version: String,
    pub daemon_loads_external_code: bool,
    pub export_surfaces: Vec<AdapterExportSurface>,
}

/// Live peer state derived from verified telemetry.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SessionPeerInfo {
    /// Current client endpoint reported by the most recent telemetry update.
    pub current_client_addr: Option<String>,
    /// Last known client endpoint seen for this session, even if the client is currently absent.
    pub last_client_addr: Option<String>,
    /// Previous non-null client endpoint when the client roamed to a new address.
    pub previous_client_addr: Option<String>,
    /// Last Unix-millisecond timestamp where telemetry reported a non-null client endpoint.
    pub last_client_seen_at_unix_ms: Option<i64>,
    /// Unix-millisecond timestamp when the session last changed to a different non-null client endpoint.
    pub client_addr_changed_at_unix_ms: Option<i64>,
}

/// Exported live summary for one tracked session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    /// Stable daemon-assigned session identity.
    pub session_id: String,
    /// Human-facing session label reported by telemetry when available.
    pub display_session_id: Option<String>,
    /// Current process id of the tracked `mosh-server`.
    pub pid: i32,
    /// Session classification.
    pub kind: SessionKind,
    /// Current derived health state.
    pub health: HealthState,
    /// Process start time in Unix milliseconds used for PID-reuse protection.
    pub started_at_unix_ms: i64,
    /// Last time this session was observed by telemetry or discovery.
    pub last_observed_unix_ms: i64,
    /// When telemetry counters were last reset during this session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counter_reset_unix_ms: Option<i64>,
    /// Bound local address when known.
    pub bind_addr: Option<String>,
    /// Bound UDP port when known.
    pub udp_port: Option<u16>,
    /// Last known remote client address when known. Compatibility alias for `peer.last_client_addr`.
    pub client_addr: Option<String>,
    /// Explicit live peer state derived from telemetry.
    #[serde(default)]
    pub peer: SessionPeerInfo,
    /// Sanitized command line used for operator display.
    pub cmdline: String,
    /// Current metrics for the session.
    pub metrics: SessionMetrics,
}

/// Session summary plus bounded history for detail views.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSnapshot {
    #[serde(flatten)]
    /// Flattened current session summary.
    pub summary: SessionSummary,
    /// Total history points retained internally for this session.
    pub total_history_points: usize,
    /// Number of oldest points omitted from `history` due to export caps.
    pub truncated_history_points: usize,
    /// Exported history slice in chronological order.
    pub history: Vec<MetricPoint>,
}

impl SessionSnapshot {
    /// Discard detail history and keep only the session summary.
    pub fn into_summary(self) -> SessionSummary {
        self.summary
    }
}

impl SessionSummary {
    /// Attach an exported history slice to this summary.
    pub fn with_history(
        self,
        total_history_points: usize,
        truncated_history_points: usize,
        history: Vec<MetricPoint>,
    ) -> SessionSnapshot {
        SessionSnapshot {
            summary: self,
            total_history_points,
            truncated_history_points,
            history,
        }
    }
}

/// List stable out-of-process export surfaces.
pub fn adapter_export_surfaces() -> Vec<AdapterExportSurface> {
    vec![AdapterExportSurface {
        surface_id: "coherence_export".to_string(),
        route_template: "/v1/coherence/exports/{session_id}".to_string(),
        export_version: COHERENCE_EXPORT_VERSION.to_string(),
        privacy_profile: "metadata-only-redaction-v1".to_string(),
        description: "Redacted route-continuity export for external diagnostics adapters."
            .to_string(),
        stable_for_external_adapters: true,
    }]
}

/// Build a stable redacted label for identity-bearing values.
pub fn stable_digest_label(value: &str, prefix: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let hex = format!("{digest:x}");
    format!("{prefix}-{}", &hex[..12])
}

fn endpoint_label(value: Option<&str>) -> Option<String> {
    value
        .filter(|value| !value.trim().is_empty())
        .map(|value| stable_digest_label(value, "endpoint"))
}

fn observer_label(observer: &crate::identity::ObserverInfo) -> String {
    stable_digest_label(
        &format!("{}:{}", observer.node_name, observer.system_id),
        "observer",
    )
}

fn safety_boundary() -> CoherenceSafetyBoundary {
    CoherenceSafetyBoundary {
        defensive_observability_only: true,
        packet_payload_retained: false,
        raw_packet_capture_retained: false,
        session_keys_retained: false,
        terminal_content_retained: false,
        endpoint_values_redacted: true,
        application_semantics_inferred: false,
    }
}

/// Build a compact redacted coherence status from a live session summary.
pub fn build_coherence_snapshot_from_summary(summary: &SessionSummary) -> CoherenceSessionSnapshot {
    let route_shift_observed = summary.peer.previous_client_addr.is_some()
        && summary.peer.last_client_addr.is_some()
        && summary.peer.client_addr_changed_at_unix_ms.is_some()
        && summary.peer.previous_client_addr != summary.peer.last_client_addr;
    let confidence_score = if summary.kind == SessionKind::Instrumented {
        if route_shift_observed { 90.0 } else { 72.0 }
    } else {
        25.0
    };
    CoherenceSessionSnapshot {
        session_id_label: stable_digest_label(&summary.session_id, "session"),
        kind: summary.kind.clone(),
        health: summary.health.clone(),
        route_shift_observed,
        endpoint_values_retained: false,
        confidence_score,
    }
}

/// Build a full metadata-only coherence report from one session snapshot.
pub fn build_coherence_session_report(
    observer: &crate::identity::ObserverInfo,
    snapshot: &SessionSnapshot,
) -> CoherenceSessionReport {
    let summary = &snapshot.summary;
    let mut points: Vec<(i64, Option<String>, bool, bool, bool)> = snapshot
        .history
        .iter()
        .map(|point| {
            (
                point.unix_ms,
                endpoint_label(point.current_client_addr.as_deref()),
                point.remote_state_age_ms.is_some(),
                point.srtt_ms.is_some() || point.retransmit_pct_10s.is_some(),
                false,
            )
        })
        .collect();
    if points.is_empty() {
        points.push((
            summary.last_observed_unix_ms,
            endpoint_label(
                summary
                    .peer
                    .current_client_addr
                    .as_deref()
                    .or(summary.peer.last_client_addr.as_deref())
                    .or(summary.client_addr.as_deref()),
            ),
            summary.metrics.last_heard_age_ms.is_some()
                || summary.metrics.remote_state_age_ms.is_some(),
            summary.metrics.srtt_ms.is_some()
                || summary.metrics.last_rtt_ms.is_some()
                || summary.metrics.retransmit_pct_10s.is_some()
                || summary.metrics.retransmit_pct_60s.is_some(),
            summary.metrics.packets_tx_total.is_some()
                || summary.metrics.packets_rx_total.is_some(),
        ));
    }
    points.sort_by_key(|point| point.0);

    let mut route_epochs: Vec<CoherenceRouteEpoch> = Vec::new();
    for (unix_ms, label, _, _, _) in &points {
        match route_epochs.last_mut() {
            Some(epoch) if epoch.endpoint_label == *label => {
                epoch.end_unix_ms = *unix_ms;
                epoch.sample_count += 1;
            }
            _ => {
                route_epochs.push(CoherenceRouteEpoch {
                    epoch_index: route_epochs.len(),
                    start_unix_ms: *unix_ms,
                    end_unix_ms: *unix_ms,
                    sample_count: 1,
                    endpoint_label: label.clone(),
                    endpoint_value_retained: false,
                });
            }
        }
    }

    let max_sample_gap_ms = points
        .windows(2)
        .map(|window| window[1].0.saturating_sub(window[0].0))
        .max();
    let history_sample_count = snapshot.history.len();
    let route_shift_count = route_epochs.len().saturating_sub(1);
    let liveness_signal_present = points.iter().any(|(_, _, liveness, _, _)| *liveness)
        || summary.metrics.last_heard_age_ms.is_some()
        || summary.metrics.remote_state_age_ms.is_some();
    let packet_counter_signal_present = points.iter().any(|(_, _, _, _, packets)| *packets)
        || summary.metrics.packets_tx_total.is_some()
        || summary.metrics.packets_rx_total.is_some();
    let retransmit_signal_present = summary.metrics.retransmit_pct_10s.is_some()
        || summary.metrics.retransmit_pct_60s.is_some()
        || snapshot
            .history
            .iter()
            .any(|point| point.retransmit_pct_10s.is_some());
    let stable_session_identity =
        !summary.session_id.trim().is_empty() && summary.kind == SessionKind::Instrumented;
    let recovery_after_drift = route_shift_count > 0
        && liveness_signal_present
        && (packet_counter_signal_present || summary.metrics.state_updates_rx_total.is_some());
    let continuity = CoherenceContinuitySummary {
        stable_session_identity,
        route_epoch_count: route_epochs.len(),
        route_shift_count,
        history_sample_count,
        max_sample_gap_ms,
        recovery_after_drift,
        liveness_signal_present,
        packet_counter_signal_present,
        retransmit_signal_present,
    };
    let confidence_score = coherence_confidence_score(&continuity, summary.udp_port.is_some());
    let decision = if confidence_score >= 85.0 && route_shift_count > 0 {
        "coherent_roaming_session_observed"
    } else if confidence_score >= 70.0 {
        "coherent_session_observed_without_roaming_claim"
    } else {
        "insufficient_coherence_signal"
    };
    let mut caveats = vec![
        "metadata-only defensive observability".to_string(),
        "does not retain Mosh session keys, packet contents, terminal content, or packet captures"
            .to_string(),
    ];
    if route_shift_count == 0 {
        caveats.push("no endpoint drift observed in the exported window".to_string());
    }
    CoherenceSessionReport {
        report_version: "moshwatch-coherence-session-report-v1".to_string(),
        observer_label: observer_label(observer),
        session_id_label: stable_digest_label(&summary.session_id, "session"),
        display_session_id_present: summary.display_session_id.is_some(),
        kind: summary.kind.clone(),
        health: summary.health.clone(),
        udp_port_observed: summary.udp_port.is_some(),
        route_epochs,
        continuity,
        adjudication: CoherenceAdjudication {
            decision: decision.to_string(),
            confidence_score,
            false_stitch_rejected: true,
            caveats,
        },
        safety_boundary: safety_boundary(),
    }
}

fn coherence_confidence_score(
    continuity: &CoherenceContinuitySummary,
    udp_port_observed: bool,
) -> f64 {
    let mut score = 0.0;
    if continuity.stable_session_identity {
        score += 20.0;
    }
    if udp_port_observed {
        score += 10.0;
    }
    if continuity.route_epoch_count >= 1 {
        score += 10.0;
    }
    if continuity.route_shift_count >= 1 {
        score += 20.0;
    }
    if continuity.recovery_after_drift {
        score += 20.0;
    }
    if continuity.liveness_signal_present {
        score += 10.0;
    }
    if continuity.packet_counter_signal_present {
        score += 10.0;
    }
    score
}

/// Build a redacted metadata-only export envelope from one session report.
pub fn build_coherence_export(
    observer: &crate::identity::ObserverInfo,
    generated_at_unix_ms: i64,
    snapshot: &SessionSnapshot,
) -> CoherenceExportEnvelope {
    let report = build_coherence_session_report(observer, snapshot);
    let digest_input = serde_json::to_vec(&report).unwrap_or_default();
    let digest = Sha256::digest(&digest_input);
    CoherenceExportEnvelope {
        schema_version: API_SCHEMA_VERSION,
        export_version: COHERENCE_EXPORT_VERSION.to_string(),
        generated_at_unix_ms,
        observer_label: report.observer_label.clone(),
        session_id_label: report.session_id_label.clone(),
        report,
        redaction: CoherenceRedactionProfile {
            profile_id: "metadata-only-redaction-v1".to_string(),
            endpoint_values_retained: false,
            session_id_values_retained: false,
            observer_values_retained: false,
            packet_or_terminal_content_retained: false,
        },
        export_guarantees: CoherenceExportGuarantees {
            packet_payload_retained: false,
            terminal_content_retained: false,
            session_keys_retained: false,
            endpoint_values_retained: false,
            application_semantics_inferred: false,
        },
        export_digest: format!("{digest:x}"),
    }
}

/// Derive operator health from the session kind, live metrics, and thresholds.
///
/// Legacy sessions remain `HealthState::Legacy` because they lack verified
/// telemetry. Instrumented sessions use warning and critical thresholds across
/// latency, silence, and retransmit ratios.
pub fn classify_health(
    kind: &SessionKind,
    metrics: &SessionMetrics,
    thresholds: &crate::config::HealthThresholds,
) -> HealthState {
    if *kind == SessionKind::Legacy {
        return HealthState::Legacy;
    }

    let rtt_critical = metrics
        .srtt_ms
        .is_some_and(|value| value >= thresholds.critical_rtt_ms as f64);
    let rtt_warn = metrics
        .srtt_ms
        .is_some_and(|value| value >= thresholds.warn_rtt_ms as f64);
    let retransmit_critical = metrics
        .retransmit_pct_60s
        .is_some_and(|value| value >= thresholds.critical_retransmit_pct);
    let retransmit_warn = metrics
        .retransmit_pct_10s
        .is_some_and(|value| value >= thresholds.warn_retransmit_pct)
        || metrics
            .retransmit_pct_60s
            .is_some_and(|value| value >= thresholds.warn_retransmit_pct);
    let silence_critical = metrics
        .last_heard_age_ms
        .is_some_and(|value| value >= thresholds.critical_silence_ms);
    let silence_warn = metrics
        .last_heard_age_ms
        .is_some_and(|value| value >= thresholds.warn_silence_ms);

    if rtt_critical || retransmit_critical || silence_critical {
        HealthState::Critical
    } else if rtt_warn || retransmit_warn || silence_warn {
        HealthState::Degraded
    } else {
        HealthState::Ok
    }
}

/// Response body for `GET /v1/sessions`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSessionsResponse {
    #[serde(default = "default_rest_schema_version")]
    /// Exported API schema version for this response body. Missing values decode as the legacy v2 REST schema.
    pub schema_version: u32,
    /// Observer identity of the reporting daemon.
    pub observer: crate::identity::ObserverInfo,
    /// Response generation time in Unix milliseconds.
    pub generated_at_unix_ms: i64,
    /// Total tracked sessions before truncation.
    pub total_sessions: usize,
    /// Number of sessions omitted from `sessions` due to export caps.
    pub truncated_session_count: usize,
    /// Total sessions dropped or rejected because of tracking caps.
    pub dropped_sessions_total: u64,
    /// Exported live summaries in display order.
    pub sessions: Vec<SessionSummary>,
}

/// Response body for `GET /v1/sessions/:id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSessionResponse {
    #[serde(default = "default_rest_schema_version")]
    /// Exported API schema version for this response body. Missing values decode as the legacy v2 REST schema.
    pub schema_version: u32,
    /// Observer identity of the reporting daemon.
    pub observer: crate::identity::ObserverInfo,
    /// Response generation time in Unix milliseconds.
    pub generated_at_unix_ms: i64,
    /// Detailed snapshot for the requested session.
    pub session: SessionSnapshot,
}

/// Supported control actions for tracked sessions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionControlAction {
    /// Request graceful termination of the tracked process with `SIGTERM`.
    Terminate,
}

/// Response body for successful session control requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiSessionControlResponse {
    #[serde(default = "default_rest_schema_version")]
    /// Exported API schema version for this response body. Missing values decode as the legacy v2 REST schema.
    pub schema_version: u32,
    /// Observer identity of the reporting daemon.
    pub observer: crate::identity::ObserverInfo,
    /// Response generation time in Unix milliseconds.
    pub generated_at_unix_ms: i64,
    /// Stable daemon-assigned session identity.
    pub session_id: String,
    /// Process id that received the control action.
    pub pid: i32,
    /// Control action that was requested.
    pub action: SessionControlAction,
}

/// Backward-compatible metrics shape for `GET /v1/config`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiMetricsConfig {
    /// TCP metrics listener address when enabled.
    #[serde(default)]
    pub listen_addr: Option<String>,
    /// Whether non-loopback Prometheus binds are allowed.
    pub allow_non_loopback: bool,
    /// Prometheus detail tier for local scraping.
    #[serde(default)]
    pub detail_tier: crate::MetricsDetailTier,
    /// OTLP metrics export configuration.
    #[serde(default)]
    pub otlp: crate::config::OtlpMetricsConfig,
}

/// Effective daemon configuration shape returned by `GET /v1/config`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiAppConfig {
    pub refresh_ms: u64,
    pub discovery_interval_ms: u64,
    pub cleanup_interval_ms: u64,
    pub history_secs: u64,
    pub max_tracked_sessions: usize,
    pub max_session_detail_points: usize,
    pub thresholds: crate::config::HealthThresholds,
    pub stream: crate::config::EventStreamConfig,
    pub persistence: crate::config::PersistenceConfig,
    #[serde(default)]
    pub metrics: ApiMetricsConfig,
}

impl Default for ApiMetricsConfig {
    fn default() -> Self {
        Self {
            listen_addr: None,
            allow_non_loopback: false,
            detail_tier: crate::MetricsDetailTier::PerSession,
            otlp: crate::config::OtlpMetricsConfig::default(),
        }
    }
}

impl From<&crate::config::AppConfig> for ApiAppConfig {
    fn from(config: &crate::config::AppConfig) -> Self {
        Self {
            refresh_ms: config.refresh_ms,
            discovery_interval_ms: config.discovery_interval_ms,
            cleanup_interval_ms: config.cleanup_interval_ms,
            history_secs: config.history_secs,
            max_tracked_sessions: config.max_tracked_sessions,
            max_session_detail_points: config.max_session_detail_points,
            thresholds: config.thresholds.clone(),
            stream: config.stream.clone(),
            persistence: config.persistence.clone(),
            metrics: ApiMetricsConfig {
                listen_addr: config.metrics.prometheus.listen_addr.clone(),
                allow_non_loopback: config.metrics.prometheus.allow_non_loopback,
                detail_tier: config.metrics.prometheus.detail_tier,
                otlp: config.metrics.otlp.clone(),
            },
        }
    }
}

/// Response body for `GET /v1/config`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfigResponse {
    #[serde(default = "default_rest_schema_version")]
    /// Exported API schema version for this response body. Missing values decode as the legacy v2 REST schema.
    pub schema_version: u32,
    /// Observer identity of the reporting daemon.
    pub observer: crate::identity::ObserverInfo,
    /// Response generation time in Unix milliseconds.
    pub generated_at_unix_ms: i64,
    /// Effective daemon configuration.
    pub config: ApiAppConfig,
}

/// Persisted history sample for one session at one recording point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistorySample {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Observer identity recorded with the sample when available.
    pub observer: Option<crate::identity::ObserverInfo>,
    /// Sample recording time in Unix milliseconds.
    pub recorded_at_unix_ms: i64,
    /// Stable daemon-assigned session identity.
    pub session_id: String,
    /// Human-facing session label when available.
    pub display_session_id: Option<String>,
    /// Process id at the time of sampling.
    pub pid: i32,
    /// Session classification at the time of sampling.
    pub kind: SessionKind,
    /// Derived health state at the time of sampling.
    pub health: HealthState,
    /// Process start time in Unix milliseconds.
    pub started_at_unix_ms: i64,
    /// When telemetry counters were last reset during this session.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counter_reset_unix_ms: Option<i64>,
    /// Bound local address when known.
    pub bind_addr: Option<String>,
    /// Bound UDP port when known.
    pub udp_port: Option<u16>,
    /// Last known remote client address when known. Compatibility alias for older consumers.
    pub client_addr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Remote client address currently attached at the sample point, when known.
    pub current_client_addr: Option<String>,
    /// Metrics snapshot recorded with the sample.
    pub metrics: SessionMetrics,
}

/// Response body for `GET /v1/history/:id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiHistoryResponse {
    #[serde(default = "default_rest_schema_version")]
    /// Exported API schema version for this response body. Missing values decode as the legacy v2 REST schema.
    pub schema_version: u32,
    /// Observer identity of the reporting daemon.
    pub observer: crate::identity::ObserverInfo,
    /// Response generation time in Unix milliseconds.
    pub generated_at_unix_ms: i64,
    /// Requested session identity.
    pub session_id: String,
    /// Returned history samples in chronological order.
    pub samples: Vec<HistorySample>,
}

/// Event kind carried by the latest-state NDJSON stream.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EventStreamEvent {
    /// Full latest-state snapshot frame.
    Snapshot,
    /// Heartbeat frame emitted to keep an idle stream fresh.
    Heartbeat,
}

/// Single NDJSON frame emitted by `GET /v1/events/stream`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventStreamFrame {
    /// Event-stream schema version.
    pub schema_version: u32,
    /// Observer identity of the reporting daemon.
    pub observer: crate::identity::ObserverInfo,
    /// Frame kind.
    pub event: EventStreamEvent,
    /// Monotonic sequence for snapshot frames; heartbeats carry `None`.
    pub sequence: Option<u64>,
    /// Frame generation time in Unix milliseconds.
    pub generated_at_unix_ms: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Total tracked sessions before truncation, for snapshot frames only.
    pub total_sessions: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Number of omitted sessions, for snapshot frames only.
    pub truncated_session_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Total dropped sessions due to tracking caps, for snapshot frames only.
    pub dropped_sessions_total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Latest exported session set, for snapshot frames only.
    pub sessions: Option<Vec<SessionSummary>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Redacted coherence status for snapshot frames only.
    pub coherence_sessions: Option<Vec<CoherenceSessionSnapshot>>,
}

/// Raw telemetry payload sent by the instrumented `mosh-server-real`.
///
/// The daemon validates this against verified local process metadata before
/// trusting it, and may rewrite some fields from the verified peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryEvent {
    /// Session lifecycle event kind.
    pub event: TelemetryEventKind,
    #[serde(default, alias = "session_id")]
    /// Human-facing session label reported by the peer when available.
    pub display_session_id: Option<String>,
    /// Process id reported by the peer before daemon verification.
    pub pid: i32,
    /// Peer-observed event timestamp in Unix milliseconds.
    pub unix_ms: i64,
    /// Peer-reported process start time in Unix milliseconds.
    pub started_at_unix_ms: Option<i64>,
    /// Bound local address when known.
    pub bind_addr: Option<String>,
    /// Bound UDP port when known.
    pub udp_port: Option<u16>,
    /// Remote client address when known.
    pub client_addr: Option<String>,
    /// Time since last heard traffic, in milliseconds.
    pub last_heard_age_ms: Option<u64>,
    /// Time since remote state last advanced, in milliseconds.
    pub remote_state_age_ms: Option<u64>,
    /// Smoothed RTT in milliseconds.
    pub srtt_ms: Option<f64>,
    /// RTT variation estimate in milliseconds.
    pub rttvar_ms: Option<f64>,
    /// Most recent raw RTT sample in milliseconds.
    pub last_rtt_ms: Option<f64>,
    /// Monotonic total transmitted packets.
    pub packets_tx_total: Option<u64>,
    /// Monotonic total received packets.
    pub packets_rx_total: Option<u64>,
    /// Monotonic total retransmitted packets.
    pub retransmits_total: Option<u64>,
    /// Monotonic total transmitted empty ACK packets.
    pub empty_acks_tx_total: Option<u64>,
    /// Monotonic total transmitted state-update packets.
    pub state_updates_tx_total: Option<u64>,
    /// Monotonic total received state-update packets.
    pub state_updates_rx_total: Option<u64>,
    /// Monotonic total duplicate state packets received.
    pub duplicate_states_rx_total: Option<u64>,
    /// Monotonic total out-of-order state packets received.
    pub out_of_order_states_rx_total: Option<u64>,
    /// Sanitized command line of the sending process when available.
    pub cmdline: Option<String>,
    /// Optional shutdown hint from the peer.
    pub shutdown: Option<bool>,
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::{
        ApiConfigResponse, ApiHistoryResponse, ApiSessionControlResponse, ApiSessionResponse,
        ApiSessionsResponse, HealthState, HistorySample, LEGACY_REST_SCHEMA_VERSION, MetricPoint,
        SessionControlAction, SessionKind, SessionMetrics, SessionPeerInfo, SessionSummary,
        build_coherence_export, build_coherence_session_report, classify_health,
    };
    use crate::{
        config::{AppConfig, HealthThresholds},
        identity::ObserverInfo,
    };

    fn observer() -> ObserverInfo {
        ObserverInfo {
            node_name: "node-1".to_string(),
            system_id: "system-1".to_string(),
        }
    }

    fn session_summary() -> SessionSummary {
        SessionSummary {
            session_id: "instrumented:1000:42".to_string(),
            display_session_id: Some("display-1".to_string()),
            pid: 42,
            kind: SessionKind::Instrumented,
            health: HealthState::Ok,
            started_at_unix_ms: 1_000,
            last_observed_unix_ms: 2_000,
            counter_reset_unix_ms: None,
            bind_addr: Some("127.0.0.1".to_string()),
            udp_port: Some(60001),
            client_addr: Some("192.0.2.1:60001".to_string()),
            peer: SessionPeerInfo {
                current_client_addr: Some("192.0.2.1:60001".to_string()),
                last_client_addr: Some("192.0.2.1:60001".to_string()),
                ..SessionPeerInfo::default()
            },
            cmdline: "mosh-server-real".to_string(),
            metrics: SessionMetrics::default(),
        }
    }

    fn strip_schema_version(mut value: Value) -> Value {
        value
            .as_object_mut()
            .expect("response should encode as object")
            .remove("schema_version");
        value
    }

    #[test]
    fn rest_responses_accept_missing_schema_version_from_v2_daemons() {
        let sessions: ApiSessionsResponse = serde_json::from_value(strip_schema_version(
            serde_json::to_value(ApiSessionsResponse {
                schema_version: super::API_SCHEMA_VERSION,
                observer: observer(),
                generated_at_unix_ms: 2_000,
                total_sessions: 1,
                truncated_session_count: 0,
                dropped_sessions_total: 0,
                sessions: vec![session_summary()],
            })
            .expect("encode sessions response"),
        ))
        .expect("decode sessions response without schema_version");
        assert_eq!(sessions.schema_version, LEGACY_REST_SCHEMA_VERSION);

        let session: ApiSessionResponse = serde_json::from_value(strip_schema_version(
            serde_json::to_value(ApiSessionResponse {
                schema_version: super::API_SCHEMA_VERSION,
                observer: observer(),
                generated_at_unix_ms: 2_000,
                session: session_summary().with_history(0, 0, Vec::new()),
            })
            .expect("encode session response"),
        ))
        .expect("decode session response without schema_version");
        assert_eq!(session.schema_version, LEGACY_REST_SCHEMA_VERSION);

        let control: ApiSessionControlResponse = serde_json::from_value(strip_schema_version(
            serde_json::to_value(ApiSessionControlResponse {
                schema_version: super::API_SCHEMA_VERSION,
                observer: observer(),
                generated_at_unix_ms: 2_000,
                session_id: "instrumented:1000:42".to_string(),
                pid: 42,
                action: SessionControlAction::Terminate,
            })
            .expect("encode control response"),
        ))
        .expect("decode control response without schema_version");
        assert_eq!(control.schema_version, LEGACY_REST_SCHEMA_VERSION);

        let config: ApiConfigResponse = serde_json::from_value(strip_schema_version(
            serde_json::to_value(ApiConfigResponse {
                schema_version: super::API_SCHEMA_VERSION,
                observer: observer(),
                generated_at_unix_ms: 2_000,
                config: (&AppConfig::default()).into(),
            })
            .expect("encode config response"),
        ))
        .expect("decode config response without schema_version");
        assert_eq!(config.schema_version, LEGACY_REST_SCHEMA_VERSION);

        let history: ApiHistoryResponse = serde_json::from_value(strip_schema_version(
            serde_json::to_value(ApiHistoryResponse {
                schema_version: super::API_SCHEMA_VERSION,
                observer: observer(),
                generated_at_unix_ms: 2_000,
                session_id: "instrumented:1000:42".to_string(),
                samples: Vec::new(),
            })
            .expect("encode history response"),
        ))
        .expect("decode history response without schema_version");
        assert_eq!(history.schema_version, LEGACY_REST_SCHEMA_VERSION);
    }

    #[test]
    fn history_sample_defaults_counter_reset_marker_when_missing() {
        let payload = serde_json::json!({
            "observer": observer(),
            "recorded_at_unix_ms": 2_000,
            "session_id": "instrumented:1000:42",
            "display_session_id": "display-1",
            "pid": 42,
            "kind": "instrumented",
            "health": "ok",
            "started_at_unix_ms": 1_000,
            "bind_addr": "127.0.0.1",
            "udp_port": 60001,
            "client_addr": "192.0.2.1:60001",
            "current_client_addr": "192.0.2.1:60001",
            "metrics": SessionMetrics::default(),
        });
        let sample: HistorySample =
            serde_json::from_value(payload).expect("decode history sample without reset marker");
        assert_eq!(sample.counter_reset_unix_ms, None);
    }

    #[test]
    fn history_sample_serializes_counter_reset_marker_when_present() {
        let sample = HistorySample {
            observer: Some(observer()),
            recorded_at_unix_ms: 2_000,
            session_id: "instrumented:1000:42".to_string(),
            display_session_id: Some("display-1".to_string()),
            pid: 42,
            kind: SessionKind::Instrumented,
            health: HealthState::Ok,
            started_at_unix_ms: 1_000,
            counter_reset_unix_ms: Some(1_500),
            bind_addr: Some("127.0.0.1".to_string()),
            udp_port: Some(60001),
            client_addr: Some("192.0.2.1:60001".to_string()),
            current_client_addr: Some("192.0.2.1:60001".to_string()),
            metrics: SessionMetrics::default(),
        };
        let encoded = serde_json::to_value(sample).expect("encode history sample");
        assert_eq!(encoded["counter_reset_unix_ms"], serde_json::json!(1_500));
    }

    #[test]
    fn coherence_export_redacts_route_drift_and_keeps_privacy_guarantees() {
        let mut summary = session_summary();
        summary.peer.previous_client_addr = Some("198.51.100.9:60001".to_string());
        summary.peer.current_client_addr = Some("203.0.113.7:62000".to_string());
        summary.peer.last_client_addr = Some("203.0.113.7:62000".to_string());
        summary.peer.client_addr_changed_at_unix_ms = Some(2_000);
        summary.metrics.packets_tx_total = Some(10);
        summary.metrics.packets_rx_total = Some(9);
        let snapshot = summary.with_history(
            2,
            0,
            vec![
                MetricPoint {
                    unix_ms: 1_000,
                    srtt_ms: Some(18.0),
                    retransmit_pct_10s: Some(0.0),
                    remote_state_age_ms: Some(4),
                    current_client_addr: Some("198.51.100.9:60001".to_string()),
                },
                MetricPoint {
                    unix_ms: 2_000,
                    srtt_ms: Some(22.0),
                    retransmit_pct_10s: Some(0.5),
                    remote_state_age_ms: Some(5),
                    current_client_addr: Some("203.0.113.7:62000".to_string()),
                },
            ],
        );

        let report = build_coherence_session_report(&observer(), &snapshot);
        assert_eq!(report.continuity.route_epoch_count, 2);
        assert_eq!(report.continuity.route_shift_count, 1);
        assert!(report.continuity.recovery_after_drift);
        assert_eq!(
            report.adjudication.decision,
            "coherent_roaming_session_observed"
        );
        assert!(report.adjudication.confidence_score >= 90.0);
        assert!(report.safety_boundary.defensive_observability_only);
        assert!(!report.safety_boundary.packet_payload_retained);
        assert!(!report.safety_boundary.raw_packet_capture_retained);
        assert!(!report.safety_boundary.session_keys_retained);
        assert!(
            report
                .route_epochs
                .iter()
                .all(|epoch| !epoch.endpoint_value_retained)
        );

        let export = build_coherence_export(&observer(), 3_000, &snapshot);
        assert_eq!(export.export_version, super::COHERENCE_EXPORT_VERSION);
        assert_eq!(export.export_digest.len(), 64);
        assert!(!export.redaction.endpoint_values_retained);
        assert!(!export.export_guarantees.packet_payload_retained);
        assert!(!export.export_guarantees.application_semantics_inferred);
        let serialized = serde_json::to_string(&export).expect("serialize coherence export");
        assert!(!serialized.contains("198.51.100.9"));
        assert!(!serialized.contains("203.0.113.7"));
        assert!(!serialized.contains("instrumented:1000:42"));
        assert!(!serialized.contains("node-1"));
        assert!(!serialized.contains("system-1"));
    }

    #[test]
    fn legacy_sessions_stay_legacy() {
        let metrics = SessionMetrics::default();
        assert_eq!(
            classify_health(&SessionKind::Legacy, &metrics, &HealthThresholds::default()),
            HealthState::Legacy
        );
    }

    #[test]
    fn critical_latency_beats_other_signals() {
        let metrics = SessionMetrics {
            srtt_ms: Some(1_500.0),
            ..SessionMetrics::default()
        };
        assert_eq!(
            classify_health(
                &SessionKind::Instrumented,
                &metrics,
                &HealthThresholds::default()
            ),
            HealthState::Critical
        );
    }

    #[test]
    fn degraded_retransmit_ratio_marks_session_degraded() {
        let metrics = SessionMetrics {
            retransmit_pct_10s: Some(4.5),
            ..SessionMetrics::default()
        };
        assert_eq!(
            classify_health(
                &SessionKind::Instrumented,
                &metrics,
                &HealthThresholds::default()
            ),
            HealthState::Degraded
        );
    }

    #[test]
    fn critical_retransmit_requires_sustained_window() {
        let metrics = SessionMetrics {
            retransmit_pct_10s: Some(40.0),
            retransmit_pct_60s: Some(8.0),
            ..SessionMetrics::default()
        };
        assert_eq!(
            classify_health(
                &SessionKind::Instrumented,
                &metrics,
                &HealthThresholds::default()
            ),
            HealthState::Degraded
        );
    }

    #[test]
    fn remote_state_age_does_not_trigger_silence_health() {
        let metrics = SessionMetrics {
            remote_state_age_ms: Some(60_000),
            ..SessionMetrics::default()
        };
        assert_eq!(
            classify_health(
                &SessionKind::Instrumented,
                &metrics,
                &HealthThresholds::default()
            ),
            HealthState::Ok
        );
    }

    #[test]
    fn api_metrics_config_defaults_when_detail_tier_missing() {
        let payload = serde_json::json!({
            "observer": {"node_name": "node-1", "system_id": "system-1"},
            "generated_at_unix_ms": 1,
            "config": {
                "refresh_ms": 1000,
                "discovery_interval_ms": 5000,
                "cleanup_interval_ms": 10000,
                "history_secs": 900,
                "max_tracked_sessions": 2048,
                "max_session_detail_points": 900,
                "thresholds": crate::config::HealthThresholds::default(),
                "stream": crate::config::EventStreamConfig::default(),
                "persistence": crate::config::PersistenceConfig::default(),
                "metrics": {
                    "listen_addr": null,
                    "allow_non_loopback": false,
                    "otlp": crate::config::OtlpMetricsConfig::default()
                }
            }
        });

        let parsed: super::ApiConfigResponse =
            serde_json::from_value(payload).expect("deserialize API config response");
        assert_eq!(
            parsed.config.metrics.detail_tier,
            crate::MetricsDetailTier::PerSession
        );
        assert_eq!(parsed.config.metrics.listen_addr, None);
    }

    #[test]
    fn api_metrics_config_serializes_null_listen_addr_for_disabled_listener() {
        let mut config = crate::config::AppConfig::default();
        config.metrics.prometheus.listen_addr = None;
        let payload = super::ApiConfigResponse {
            schema_version: super::API_SCHEMA_VERSION,
            observer: crate::identity::ObserverInfo {
                node_name: "node-1".to_string(),
                system_id: "system-1".to_string(),
            },
            generated_at_unix_ms: 1,
            config: (&config).into(),
        };
        let value = serde_json::to_value(payload).expect("serialize API config response");
        assert!(value["config"]["metrics"]["listen_addr"].is_null());
    }
}
