package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// PrunePolicy controls which Pi-hole entries the operator may delete.
// +kubebuilder:validation:Enum=ManagedOnly;All
type PrunePolicy string

const (
	// PruneManagedOnly deletes only entries the operator created.
	PruneManagedOnly PrunePolicy = "ManagedOnly"
	// PruneAll deletes every entry not declared in a CR, including ones added in the web UI.
	PruneAll PrunePolicy = "All"
)

// PiholeClusterSpec defines the desired state of PiholeCluster.
type PiholeClusterSpec struct {
	// replicas is the number of Pi-hole pods. Each pod is a full, independent Pi-hole.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=2
	// +optional
	Replicas *int32 `json:"replicas,omitempty"`

	// image is the Pi-hole container image. Only Pi-hole v6 (2025.x and later) is supported.
	// +kubebuilder:default="docker.io/pihole/pihole:2025.11.0"
	// +optional
	Image string `json:"image,omitempty"`

	// imagePullPolicy for the Pi-hole container.
	// +optional
	ImagePullPolicy corev1.PullPolicy `json:"imagePullPolicy,omitempty"`

	// adminPasswordSecretRef selects the key holding the web UI password.
	// If unset, the operator generates a Secret named <cluster>-admin.
	// +optional
	AdminPasswordSecretRef *corev1.SecretKeySelector `json:"adminPasswordSecretRef,omitempty"`

	// upstreams are the DNS servers Pi-hole forwards to, e.g. "1.1.1.1" or "9.9.9.9#53".
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:default={"1.1.1.1","1.0.0.1"}
	// +optional
	Upstreams []string `json:"upstreams,omitempty"`

	// timezone sets TZ in the container.
	// +kubebuilder:default=UTC
	// +optional
	Timezone string `json:"timezone,omitempty"`

	// ftl sets extra pihole.toml keys as FTLCONF_<key> env vars, e.g. {"dns_dnssec": "true"}.
	// Keys set here become read-only in the web UI.
	// +optional
	FTL map[string]string `json:"ftl,omitempty"`

	// dnsService configures the Service that exposes port 53.
	// +optional
	DNSService ServiceSpec `json:"dnsService,omitempty"`

	// webService configures the Service that exposes the admin UI and API on port 80.
	// +optional
	WebService ServiceSpec `json:"webService,omitempty"`

	// storage configures the per-pod volume for /etc/pihole.
	// +kubebuilder:default={}
	// +optional
	Storage StorageSpec `json:"storage,omitempty"`

	// resources for the Pi-hole container. Gravity rebuilds need noticeably more memory than steady state.
	// +optional
	Resources corev1.ResourceRequirements `json:"resources,omitempty"`

	// prunePolicy controls whether entries created outside the operator are removed.
	// +kubebuilder:default=ManagedOnly
	// +optional
	PrunePolicy PrunePolicy `json:"prunePolicy,omitempty"`

	// syncInterval is how often the operator re-checks every replica for drift.
	// +kubebuilder:default="5m"
	// +optional
	SyncInterval *metav1.Duration `json:"syncInterval,omitempty"`

	// podTemplate is strategic-merged over the pod template the operator
	// generates. Containers, volumes and env vars merge by name, so you can
	// patch the "pihole" container, add sidecars and volumes, or set
	// scheduling, security context and service account.
	//
	// The operator always owns: the selector labels, the pihole.io/config-hash
	// annotation, and FTLCONF_webserver_api_password on the pihole container.
	// When affinity is unset, a preferred anti-affinity across nodes is added.
	// To replace the PVC with your own storage, set storage.size to "0" and
	// define a volume named "data" here.
	// +optional
	PodTemplate *corev1.PodTemplateSpec `json:"podTemplate,omitempty"`
}

// ServiceSpec is the subset of Service settings the operator exposes.
type ServiceSpec struct {
	// type of the Service.
	// +kubebuilder:validation:Enum=ClusterIP;NodePort;LoadBalancer
	// +optional
	Type corev1.ServiceType `json:"type,omitempty"`

	// loadBalancerIP requests a specific address from the load balancer implementation.
	// +optional
	LoadBalancerIP string `json:"loadBalancerIP,omitempty"`

	// externalTrafficPolicy. Local keeps real client IPs visible to Pi-hole.
	// +kubebuilder:validation:Enum=Cluster;Local
	// +optional
	ExternalTrafficPolicy corev1.ServiceExternalTrafficPolicy `json:"externalTrafficPolicy,omitempty"`

	// annotations added to the Service, e.g. for MetalLB IP sharing.
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

// StorageSpec configures the /etc/pihole volume.
type StorageSpec struct {
	// size of each PVC. Defaults to 1Gi. Set "0" to use an emptyDir, which
	// loses gravity and query history on every restart.
	// +kubebuilder:default="1Gi"
	// +optional
	Size *resource.Quantity `json:"size,omitempty"`

	// storageClassName for the PVCs.
	// +optional
	StorageClassName *string `json:"storageClassName,omitempty"`
}

// ReplicaStatus is the sync state of a single pod.
type ReplicaStatus struct {
	// pod name.
	Pod string `json:"pod"`
	// ready reports whether the pod answers DNS.
	Ready bool `json:"ready"`
	// syncedHash is the hash of the desired config last applied to this pod.
	// +optional
	SyncedHash string `json:"syncedHash,omitempty"`
	// lastSyncTime is when the operator last converged this pod.
	// +optional
	LastSyncTime *metav1.Time `json:"lastSyncTime,omitempty"`
	// gravityPending is true when lists changed and gravity has not been rebuilt yet.
	// +optional
	GravityPending bool `json:"gravityPending,omitempty"`
	// message holds the last sync error, if any.
	// +optional
	Message string `json:"message,omitempty"`
}

// PiholeClusterStatus defines the observed state of PiholeCluster.
type PiholeClusterStatus struct {
	// observedGeneration is the generation last processed by the operator.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// readyReplicas is the number of pods answering DNS.
	// +optional
	ReadyReplicas int32 `json:"readyReplicas,omitempty"`

	// desiredHash is the hash of the configuration built from all child CRs.
	// +optional
	DesiredHash string `json:"desiredHash,omitempty"`

	// replicas holds per-pod sync state.
	// +listType=map
	// +listMapKey=pod
	// +optional
	Replicas []ReplicaStatus `json:"replicas,omitempty"`

	// managedHosts and managedCNAMEs are the local records the operator applied.
	// They let it remove its own stale records without touching hand-made ones.
	// +optional
	ManagedHosts []string `json:"managedHosts,omitempty"`
	// +optional
	ManagedCNAMEs []string `json:"managedCNAMEs,omitempty"`

	// lastGravityUpdate is when the operator last rebuilt gravity on a replica.
	// +optional
	LastGravityUpdate *metav1.Time `json:"lastGravityUpdate,omitempty"`

	// conditions: Available, Synced, Degraded.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=phc
// +kubebuilder:printcolumn:name="Replicas",type=integer,JSONPath=`.spec.replicas`
// +kubebuilder:printcolumn:name="Ready",type=integer,JSONPath=`.status.readyReplicas`
// +kubebuilder:printcolumn:name="Synced",type=string,JSONPath=`.status.conditions[?(@.type=="Synced")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// PiholeCluster runs a set of Pi-hole replicas that share one declarative configuration.
type PiholeCluster struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`
	// +required
	Spec PiholeClusterSpec `json:"spec"`
	// +optional
	Status PiholeClusterStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// PiholeClusterList contains a list of PiholeCluster.
type PiholeClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []PiholeCluster `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &PiholeCluster{}, &PiholeClusterList{})
		return nil
	})
}
