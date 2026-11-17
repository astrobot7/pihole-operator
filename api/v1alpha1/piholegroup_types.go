package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// PiholeGroupSpec defines the desired state of PiholeGroup.
// +kubebuilder:validation:XValidation:rule="!has(self.name) || self.name != 'Default' || !has(self.description)",message="the Default group's description cannot be changed"
type PiholeGroupSpec struct {
	// clusterRef is the PiholeCluster this group is created in.
	// +required
	ClusterRef ClusterReference `json:"clusterRef"`

	// name of the group in Pi-hole. Defaults to metadata.name. Use "Default"
	// to assign clients to Pi-hole's built-in group.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	// +optional
	Name string `json:"name,omitempty"`

	// description is stored as the group's comment.
	// +optional
	Description string `json:"description,omitempty"`

	// enabled toggles every list, domain and client assignment of the group.
	// +kubebuilder:default=true
	// +optional
	Enabled *bool `json:"enabled,omitempty"`

	// clients assigned to this group: IPv4/IPv6 addresses, CIDR subnets,
	// MAC addresses, hostnames, or interfaces written as ":eth0".
	// +kubebuilder:validation:MaxItems=1000
	// +listType=set
	// +optional
	Clients []string `json:"clients,omitempty"`

	// excludeFromDefault removes this group's clients from the Default group,
	// so only lists and domains assigned to this group (or other groups the
	// client belongs to) apply to them. Pi-hole otherwise keeps every client
	// in Default.
	// +optional
	ExcludeFromDefault bool `json:"excludeFromDefault,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=phg
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=`.spec.clusterRef.name`
// +kubebuilder:printcolumn:name="Group",type=string,JSONPath=`.spec.name`
// +kubebuilder:printcolumn:name="Synced",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].status`

// PiholeGroup declares a Pi-hole group and the clients assigned to it.
// Blocklists and domain lists opt into the group through spec.groups.
type PiholeGroup struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`
	// +required
	Spec PiholeGroupSpec `json:"spec"`
	// +optional
	Status ConfigStatus `json:"status,omitzero"`
}

// GroupName is the Pi-hole group name: spec.name, or metadata.name when unset.
func (g *PiholeGroup) GroupName() string {
	if g.Spec.Name != "" {
		return g.Spec.Name
	}
	return g.Name
}

// +kubebuilder:object:root=true

// PiholeGroupList contains a list of PiholeGroup.
type PiholeGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []PiholeGroup `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &PiholeGroup{}, &PiholeGroupList{})
		return nil
	})
}
