package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// ClusterReference points at a PiholeCluster in the same namespace.
type ClusterReference struct {
	// name of the PiholeCluster.
	// +kubebuilder:validation:MinLength=1
	// +required
	Name string `json:"name"`
}

// ConfigStatus is shared by the configuration CRDs (blocklists, domains, records).
type ConfigStatus struct {
	// observedGeneration is the generation last processed by the operator.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// conditions describe whether this object has been applied to every replica.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// Condition types used across the API.
const (
	ConditionAvailable = "Available"
	ConditionSynced    = "Synced"
	ConditionDegraded  = "Degraded"
)
