package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// ARecord maps a host name to an address (A or AAAA).
type ARecord struct {
	// host name.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +required
	Host string `json:"host"`
	// ip address, IPv4 or IPv6.
	// +kubebuilder:validation:MaxLength=45
	// +kubebuilder:validation:XValidation:rule="isIP(self)",message="must be a valid IP address"
	// +required
	IP string `json:"ip"`
}

// CNAMERecord aliases a host name to a target.
type CNAMERecord struct {
	// host name of the alias.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +required
	Host string `json:"host"`
	// target the alias resolves to.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +required
	Target string `json:"target"`
	// ttl in seconds. Zero leaves it to Pi-hole.
	// +kubebuilder:validation:Minimum=0
	// +optional
	TTL int32 `json:"ttl,omitempty"`
}

// PiholeLocalRecordSpec defines the desired state of PiholeLocalRecord.
// +kubebuilder:validation:XValidation:rule="size(self.a) + size(self.cname) > 0",message="at least one a or cname record is required"
type PiholeLocalRecordSpec struct {
	// clusterRef is the PiholeCluster these records are served by.
	// +required
	ClusterRef ClusterReference `json:"clusterRef"`

	// a records.
	// +kubebuilder:validation:MaxItems=2000
	// +kubebuilder:default={}
	// +optional
	A []ARecord `json:"a"`

	// cname records.
	// +kubebuilder:validation:MaxItems=2000
	// +kubebuilder:default={}
	// +optional
	CNAME []CNAMERecord `json:"cname"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=phlr
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=`.spec.clusterRef.name`
// +kubebuilder:printcolumn:name="Synced",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].status`

// PiholeLocalRecord declares local DNS and CNAME records for a PiholeCluster.
type PiholeLocalRecord struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`
	// +required
	Spec PiholeLocalRecordSpec `json:"spec"`
	// +optional
	Status ConfigStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// PiholeLocalRecordList contains a list of PiholeLocalRecord.
type PiholeLocalRecordList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []PiholeLocalRecord `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &PiholeLocalRecord{}, &PiholeLocalRecordList{})
		return nil
	})
}
