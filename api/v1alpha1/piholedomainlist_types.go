package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// DomainKind is how a domain entry is matched.
// +kubebuilder:validation:Enum=exact;regex
type DomainKind string

// DomainAction is what Pi-hole does with a matching query.
// +kubebuilder:validation:Enum=allow;deny
type DomainAction string

const (
	DomainKindExact DomainKind   = "exact"
	DomainKindRegex DomainKind   = "regex"
	DomainAllow     DomainAction = "allow"
	DomainDeny      DomainAction = "deny"
)

// DomainEntry is one allow or deny rule.
type DomainEntry struct {
	// domain name, or a regular expression when kind is regex.
	// +kubebuilder:validation:MinLength=1
	// +required
	Domain string `json:"domain"`

	// kind of match.
	// +kubebuilder:default=exact
	// +optional
	Kind DomainKind `json:"kind,omitempty"`

	// action taken for matching queries.
	// +required
	Action DomainAction `json:"action"`

	// enabled toggles the entry without removing it.
	// +kubebuilder:default=true
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// comment stored in Pi-hole.
	// +optional
	Comment string `json:"comment,omitempty"`
}

// PiholeDomainListSpec defines the desired state of PiholeDomainList.
type PiholeDomainListSpec struct {
	// clusterRef is the PiholeCluster these entries are applied to.
	// +required
	ClusterRef ClusterReference `json:"clusterRef"`

	// entries to apply.
	// +kubebuilder:validation:MinItems=1
	// +required
	Entries []DomainEntry `json:"entries"`

	// groups the entries are assigned to. Empty means the Default group.
	// +optional
	Groups []string `json:"groups,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=phdl
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=`.spec.clusterRef.name`
// +kubebuilder:printcolumn:name="Synced",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].status`

// PiholeDomainList declares exact or regex allow/deny rules for a PiholeCluster.
type PiholeDomainList struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`
	// +required
	Spec PiholeDomainListSpec `json:"spec"`
	// +optional
	Status ConfigStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// PiholeDomainListList contains a list of PiholeDomainList.
type PiholeDomainListList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []PiholeDomainList `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &PiholeDomainList{}, &PiholeDomainListList{})
		return nil
	})
}
