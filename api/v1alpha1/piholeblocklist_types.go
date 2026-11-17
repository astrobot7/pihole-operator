package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// ListType says whether a subscribed list blocks or allows its domains.
// +kubebuilder:validation:Enum=block;allow
type ListType string

const (
	ListTypeBlock ListType = "block"
	ListTypeAllow ListType = "allow"
)

// ListSource is one subscribed list URL.
type ListSource struct {
	// url of the list.
	// +kubebuilder:validation:Pattern=`^(https?|file)://.+`
	// +required
	URL string `json:"url"`

	// enabled toggles the list without removing it.
	// +kubebuilder:default=true
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// comment is stored in Pi-hole next to the operator's ownership marker.
	// +optional
	Comment string `json:"comment,omitempty"`
}

// PiholeBlocklistSpec defines the desired state of PiholeBlocklist.
type PiholeBlocklistSpec struct {
	// clusterRef is the PiholeCluster these lists are applied to.
	// +required
	ClusterRef ClusterReference `json:"clusterRef"`

	// type of every list in this object.
	// +kubebuilder:default=block
	// +optional
	Type ListType `json:"type,omitempty"`

	// lists to subscribe to.
	// +kubebuilder:validation:MinItems=1
	// +listType=map
	// +listMapKey=url
	// +required
	Lists []ListSource `json:"lists"`

	// groups the lists are assigned to. Empty means the Default group.
	// +optional
	Groups []string `json:"groups,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=phbl
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=`.spec.clusterRef.name`
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.type`
// +kubebuilder:printcolumn:name="Synced",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].status`

// PiholeBlocklist subscribes a PiholeCluster to adlist URLs.
type PiholeBlocklist struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`
	// +required
	Spec PiholeBlocklistSpec `json:"spec"`
	// +optional
	Status ConfigStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// PiholeBlocklistList contains a list of PiholeBlocklist.
type PiholeBlocklistList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []PiholeBlocklist `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &PiholeBlocklist{}, &PiholeBlocklistList{})
		return nil
	})
}
