package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// PiholeAAAARecordSpec defines the desired state of PiholeAAAARecord.
type PiholeAAAARecordSpec struct {
	// clusterRef is the PiholeCluster that serves this record.
	// +required
	ClusterRef ClusterReference `json:"clusterRef"`

	// hostname the record answers for, e.g. nas.home.lan.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?(\.[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?)*\.?$`
	// +required
	Hostname string `json:"hostname"`

	// ip is the IPv6 address returned for hostname.
	// +kubebuilder:validation:MaxLength=45
	// +kubebuilder:validation:XValidation:rule="isIP(self) && ip(self).family() == 6",message="must be an IPv6 address"
	// +required
	IP string `json:"ip"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=phaaaa
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=`.spec.clusterRef.name`
// +kubebuilder:printcolumn:name="Hostname",type=string,JSONPath=`.spec.hostname`
// +kubebuilder:printcolumn:name="IP",type=string,JSONPath=`.spec.ip`
// +kubebuilder:printcolumn:name="Synced",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].status`

// PiholeAAAARecord is one local AAAA record (hostname to IPv6 address).
type PiholeAAAARecord struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`
	// +required
	Spec PiholeAAAARecordSpec `json:"spec"`
	// +optional
	Status ConfigStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// PiholeAAAARecordList contains a list of PiholeAAAARecord.
type PiholeAAAARecordList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []PiholeAAAARecord `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &PiholeAAAARecord{}, &PiholeAAAARecordList{})
		return nil
	})
}
