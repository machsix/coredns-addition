package addition

import (
	"github.com/coredns/coredns/plugin"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// templateMatchesCount is the counter of template regex matches.
	templateMatchesCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "addition",
		Name:      "matches_total",
		Help:      "Counter of template regex matches.",
	}, []string{"server", "zone", "view", "class", "type"})
	// templateFailureCount is the counter of go template failures.
	templateFailureCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "addition",
		Name:      "template_failures_total",
		Help:      "Counter of go template failures.",
	}, []string{"server", "zone", "view", "class", "type", "section", "addition"})
	// templateRRFailureCount is the counter of mis-templated RRs.
	templateRRFailureCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: "addition",
		Name:      "rr_failures_total",
		Help:      "Counter of mis-templated RRs.",
	}, []string{"server", "zone", "view", "class", "type", "section", "addition"})
)
