package telemetry

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds every PHParmor Prometheus metric. Metrics for controls that
// are not implemented yet are added in the milestone that implements them.
type Metrics struct {
	reg *prometheus.Registry

	Requests         *prometheus.CounterVec
	Decisions        *prometheus.CounterVec
	RequestDuration  prometheus.Histogram
	UpstreamDuration prometheus.Histogram
	ConfigReloads    *prometheus.CounterVec
}

// NewMetrics registers all metrics on a private registry. bufferInflight and
// spoolBytes report the request-body bytes currently held in memory and in
// the spool directory.
func NewMetrics(bufferInflight, spoolBytes func() float64) *Metrics {
	reg := prometheus.NewRegistry()
	m := &Metrics{
		reg: reg,
		Requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "phparmor_requests_total",
			Help: "Requests handled, by configured host label, route label and status.",
		}, []string{"host", "route", "status"}),
		Decisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "phparmor_decisions_total",
			Help: "Control decisions, by control ID and outcome.",
		}, []string{"control", "outcome"}),
		RequestDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "phparmor_request_duration_seconds",
			Help:    "Total request duration as seen by PHParmor.",
			Buckets: prometheus.ExponentialBuckets(0.0005, 2, 16),
		}),
		UpstreamDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "phparmor_upstream_duration_seconds",
			Help:    "Time from sending the upstream request to receiving response headers.",
			Buckets: prometheus.ExponentialBuckets(0.0005, 2, 16),
		}),
		ConfigReloads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "phparmor_config_reloads_total",
			Help: "Config reload attempts, by result (ok or error).",
		}, []string{"result"}),
	}
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.Requests, m.Decisions, m.RequestDuration, m.UpstreamDuration, m.ConfigReloads,
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "phparmor_buffer_bytes_inflight",
			Help: "Request body bytes currently reserved in the global memory budget.",
		}, bufferInflight),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "phparmor_spool_bytes",
			Help: "Request body bytes currently reserved in the spool directory quota.",
		}, spoolBytes),
	)
	return m
}

// Handler serves the metrics in the Prometheus exposition format.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.reg, promhttp.HandlerOpts{})
}
