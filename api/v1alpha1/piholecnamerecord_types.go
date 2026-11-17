package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// PiholeCNAMERecordSpec defines the desired state of PiholeCNAMERecord.
// +kubebuilder:validation:XValidation:rule="self.hostname.lowerAscii() != self.target.lowerAscii()",message="a CNAME cannot point at itself"
type PiholeCNAMERecordSpec struct {
	// clusterRef is the PiholeCluster that serves this record.
	// +required
	ClusterRef ClusterReference `json:"clusterRef"`

	// hostname is the alias, e.g. files.home.lan.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?(\.[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?)*\.?$`
	// +required
	Hostname string `json:"hostname"`

	// target is the name the alias resolves to. Pi-hole only answers for
	// targets it knows: a local A/AAAA record or a cached upstream answer.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?(\.[A-Za-z0-9_]([A-Za-z0-9_-]*[A-Za-z0-9_])?)*\.?$`
	// +required
	Target string `json:"target"`

	// ttl in seconds. Unset leaves it to Pi-hole.
	// +kubebuilder:validation:Minimum=1
	// +optional
	TTL *int32 `json:"ttl,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=phcname
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=`.spec.clusterRef.name`
// +kubebuilder:printcolumn:name="Hostname",type=string,JSONPath=`.spec.hostname`
// +kubebuilder:printcolumn:name="Target",type=string,JSONPath=`.spec.target`
// +kubebuilder:printcolumn:name="Synced",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].status`

// PiholeCNAMERecord is one local CNAME record (alias to target).
type PiholeCNAMERecord struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`
	// +required
	Spec PiholeCNAMERecordSpec `json:"spec"`
	// +optional
	Status ConfigStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// PiholeCNAMERecordList contains a list of PiholeCNAMERecord.
type PiholeCNAMERecordList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []PiholeCNAMERecord `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &PiholeCNAMERecord{}, &PiholeCNAMERecordList{})
		return nil
	})
}
