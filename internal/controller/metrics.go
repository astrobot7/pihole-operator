package controller

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

var (
	labels = []string{"namespace", "cluster"}

	replicaSyncs = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pihole_operator_replica_syncs_total",
		Help: "Per-replica configuration syncs, by result (success or error).",
	}, append(labels, "result"))

	syncChanges = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pihole_operator_sync_changes_total",
		Help: "Pi-hole API writes made to bring replicas in line with the CRs.",
	}, labels)

	gravityRebuilds = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pihole_operator_gravity_rebuilds_total",
		Help: "Gravity rebuilds triggered by list changes, by result.",
	}, append(labels, "result"))

	gravityDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "pihole_operator_gravity_duration_seconds",
		Help:    "Time taken by operator-triggered gravity rebuilds.",
		Buckets: []float64{5, 15, 30, 60, 120, 300, 600, 900},
	}, labels)

	replicasReady = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pihole_operator_replicas_ready",
		Help: "Replicas currently answering DNS.",
	}, labels)

	replicasSynced = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pihole_operator_replicas_synced",
		Help: "Replicas whose configuration matches the CRs with no gravity rebuild pending.",
	}, labels)

	clusterSynced = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pihole_operator_cluster_synced",
		Help: "1 when every desired replica is ready and synced, else 0.",
	}, labels)
)

func init() {
	metrics.Registry.MustRegister(replicaSyncs, syncChanges, gravityRebuilds, gravityDuration,
		replicasReady, replicasSynced, clusterSynced)
}

// forgetClusterMetrics drops every series of a deleted cluster.
func forgetClusterMetrics(namespace, cluster string) {
	l := prometheus.Labels{"namespace": namespace, "cluster": cluster}
	for _, v := range []interface{ DeletePartialMatch(prometheus.Labels) int }{
		replicaSyncs, syncChanges, gravityRebuilds, gravityDuration, replicasReady, replicasSynced, clusterSynced,
	} {
		v.DeletePartialMatch(l)
	}
}
