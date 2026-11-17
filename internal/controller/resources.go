package controller

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
	"k8s.io/utils/ptr"

	piholev1alpha1 "github.com/astrobot7/pihole-operator/api/v1alpha1"
)

const (
	labelCluster    = "pihole.io/cluster"
	labelName       = "app.kubernetes.io/name"
	labelManagedBy  = "app.kubernetes.io/managed-by"
	annConfigHash   = "pihole.io/config-hash"
	passwordKey     = "password"
	dataVolume      = "data"
	defaultImage    = "docker.io/pihole/pihole:2025.11.0"
	webPort         = 80
	portHTTP        = "http"
	piholeContainer = "pihole"
	passwordEnv     = "FTLCONF_webserver_api_password"
)

func selectorLabels(c *piholev1alpha1.PiholeCluster) map[string]string {
	return map[string]string{labelName: "pihole", labelCluster: c.Name}
}

func commonLabels(c *piholev1alpha1.PiholeCluster) map[string]string {
	l := selectorLabels(c)
	l[labelManagedBy] = "pihole-operator"
	return l
}

func headlessName(c *piholev1alpha1.PiholeCluster) string { return c.Name + "-headless" }
func dnsName(c *piholev1alpha1.PiholeCluster) string      { return c.Name + "-dns" }
func webName(c *piholev1alpha1.PiholeCluster) string      { return c.Name + "-web" }
func adminSecretName(c *piholev1alpha1.PiholeCluster) string {
	return c.Name + "-admin"
}

// passwordRef returns where the admin password lives.
func passwordRef(c *piholev1alpha1.PiholeCluster) corev1.SecretKeySelector {
	if c.Spec.AdminPasswordSecretRef != nil {
		return *c.Spec.AdminPasswordSecretRef
	}
	return corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: adminSecretName(c)}, Key: passwordKey}
}

// ftlEnv returns the FTLCONF_* settings that define a pod's static config.
// Keys set this way are read-only in Pi-hole, so they cannot drift.
func ftlEnv(c *piholev1alpha1.PiholeCluster) []corev1.EnvVar {
	upstreams := c.Spec.Upstreams
	if len(upstreams) == 0 {
		upstreams = []string{"1.1.1.1", "1.0.0.1"}
	}
	tz := c.Spec.Timezone
	if tz == "" {
		tz = "UTC"
	}
	settings := map[string]string{
		// Queries arrive from pod and node subnets; the default LOCAL mode would refuse them.
		"dns_listeningMode": "ALL",
		"dns_upstreams":     strings.Join(upstreams, ";"),
		"webserver_port":    fmt.Sprintf("%d", webPort),
	}
	maps.Copy(settings, c.Spec.FTL) // user overrides last
	keys := slices.Sorted(maps.Keys(settings))
	env := make([]corev1.EnvVar, 0, 1+len(keys))
	env = append(env, corev1.EnvVar{Name: "TZ", Value: tz})
	for _, k := range keys {
		env = append(env, corev1.EnvVar{Name: "FTLCONF_" + k, Value: settings[k]})
	}
	return env
}

// configHash covers everything that requires a pod restart to apply.
func configHash(c *piholev1alpha1.PiholeCluster, password string) string {
	h := sha256.New()
	for _, e := range ftlEnv(c) {
		_, _ = fmt.Fprintf(h, "%s=%s\n", e.Name, e.Value)
	}
	_, _ = fmt.Fprintf(h, "password=%s\n", password)
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// storageSize returns the PVC size, or zero for emptyDir.
func storageSize(c *piholev1alpha1.PiholeCluster) resource.Quantity {
	if c.Spec.Storage.Size == nil {
		return resource.MustParse("1Gi")
	}
	return *c.Spec.Storage.Size
}

// mutateStatefulSet sets the desired spec on sts. Immutable fields (selector,
// volumeClaimTemplates, serviceName) are only set on create.
func mutateStatefulSet(sts *appsv1.StatefulSet, c *piholev1alpha1.PiholeCluster, hash string) error {
	sts.Labels = commonLabels(c)
	if sts.CreationTimestamp.IsZero() {
		sts.Spec.Selector = &metav1.LabelSelector{MatchLabels: selectorLabels(c)}
		sts.Spec.ServiceName = headlessName(c)
		sts.Spec.PodManagementPolicy = appsv1.ParallelPodManagement
		if size := storageSize(c); !size.IsZero() {
			sts.Spec.VolumeClaimTemplates = []corev1.PersistentVolumeClaim{{
				ObjectMeta: metav1.ObjectMeta{Name: dataVolume, Labels: selectorLabels(c)},
				Spec: corev1.PersistentVolumeClaimSpec{
					AccessModes:      []corev1.PersistentVolumeAccessMode{corev1.ReadWriteOnce},
					StorageClassName: c.Spec.Storage.StorageClassName,
					Resources:        corev1.VolumeResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceStorage: size}},
				},
			}}
		}
	}
	sts.Spec.Replicas = new(ptr.Deref(c.Spec.Replicas, 2))
	sts.Spec.UpdateStrategy = appsv1.StatefulSetUpdateStrategy{Type: appsv1.RollingUpdateStatefulSetStrategyType}

	image := c.Spec.Image
	if image == "" {
		image = defaultImage
	}
	ref := passwordRef(c)
	env := append(ftlEnv(c), corev1.EnvVar{
		Name:      passwordEnv,
		ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &ref},
	})

	var volumes []corev1.Volume
	if !hasClaim(sts.Spec.VolumeClaimTemplates, dataVolume) {
		volumes = []corev1.Volume{{Name: dataVolume, VolumeSource: corev1.VolumeSource{EmptyDir: &corev1.EmptyDirVolumeSource{}}}}
	}

	affinity := &corev1.Affinity{PodAntiAffinity: &corev1.PodAntiAffinity{
		PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{{
			Weight: 100,
			PodAffinityTerm: corev1.PodAffinityTerm{
				TopologyKey:   corev1.LabelHostname,
				LabelSelector: &metav1.LabelSelector{MatchLabels: selectorLabels(c)},
			},
		}},
	}}
	if c.Spec.PodTemplate != nil && c.Spec.PodTemplate.Spec.Affinity != nil {
		affinity = nil // the user's affinity replaces the default instead of merging into it
	}

	tmpl := corev1.PodTemplateSpec{
		ObjectMeta: metav1.ObjectMeta{
			Labels:      selectorLabels(c),
			Annotations: map[string]string{annConfigHash: hash},
		},
		Spec: corev1.PodSpec{
			Affinity: affinity,
			Volumes:  volumes,
			Containers: []corev1.Container{{
				Name:            piholeContainer,
				Image:           image,
				ImagePullPolicy: c.Spec.ImagePullPolicy,
				Env:             env,
				Ports: []corev1.ContainerPort{
					{Name: "dns-udp", ContainerPort: 53, Protocol: corev1.ProtocolUDP},
					{Name: "dns-tcp", ContainerPort: 53, Protocol: corev1.ProtocolTCP},
					{Name: portHTTP, ContainerPort: webPort, Protocol: corev1.ProtocolTCP},
				},
				Resources: c.Spec.Resources,
				// Keep answering while kube-proxy drops this endpoint, so rollouts lose no queries.
				Lifecycle: &corev1.Lifecycle{PreStop: &corev1.LifecycleHandler{
					Exec: &corev1.ExecAction{Command: []string{"sleep", "8"}},
				}},
				VolumeMounts: []corev1.VolumeMount{{Name: dataVolume, MountPath: "/etc/pihole"}},
				StartupProbe: &corev1.Probe{
					ProbeHandler:     corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/api/info/login", Port: intstr.FromInt32(webPort)}},
					PeriodSeconds:    5,
					FailureThreshold: 60, // first boot builds gravity before FTL answers
				},
				ReadinessProbe: &corev1.Probe{
					ProbeHandler: corev1.ProbeHandler{Exec: &corev1.ExecAction{
						Command: []string{"dig", "+short", "+tries=1", "+time=2", "@127.0.0.1", "pi.hole"},
					}},
					PeriodSeconds:  10,
					TimeoutSeconds: 5,
				},
				LivenessProbe: &corev1.Probe{
					ProbeHandler:     corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Path: "/api/info/login", Port: intstr.FromInt32(webPort)}},
					PeriodSeconds:    20,
					TimeoutSeconds:   5,
					FailureThreshold: 3,
				},
			}},
		},
	}

	merged, err := applyPodTemplate(tmpl, c.Spec.PodTemplate)
	if err != nil {
		return fmt.Errorf("spec.podTemplate: %w", err)
	}
	enforceOwnedFields(&merged, c, hash, env[len(env)-1])
	sts.Spec.Template = merged
	return nil
}

func hasClaim(claims []corev1.PersistentVolumeClaim, name string) bool {
	for _, c := range claims {
		if c.Name == name {
			return true
		}
	}
	return false
}

// applyPodTemplate strategic-merges the user's template over base, the same
// way kubectl patch does: lists with merge keys (containers, volumes, env,
// ports, volumeMounts) merge by name, everything else is replaced.
func applyPodTemplate(base corev1.PodTemplateSpec, user *corev1.PodTemplateSpec) (corev1.PodTemplateSpec, error) {
	if user == nil {
		return base, nil
	}
	// A user volume with a source replaces the same-named default outright.
	// Merging would combine two sources (e.g. emptyDir + hostPath) into one
	// invalid volume, because a typed patch carries no $retainKeys directive.
	for _, uv := range user.Spec.Volumes {
		if uv.VolumeSource != (corev1.VolumeSource{}) {
			base.Spec.Volumes = slices.DeleteFunc(slices.Clone(base.Spec.Volumes),
				func(v corev1.Volume) bool { return v.Name == uv.Name })
		}
	}
	baseJSON, err := json.Marshal(base)
	if err != nil {
		return base, err
	}
	patchJSON, err := json.Marshal(user)
	if err != nil {
		return base, err
	}
	out, err := strategicpatch.StrategicMergePatch(baseJSON, patchJSON, corev1.PodTemplateSpec{})
	if err != nil {
		return base, err
	}
	var merged corev1.PodTemplateSpec
	if err := json.Unmarshal(out, &merged); err != nil {
		return base, err
	}
	return merged, nil
}

// enforceOwnedFields re-applies what the operator depends on, whatever the
// user's template said: pods must match the StatefulSet selector, carry the
// config hash that drives restarts, and use the password the operator
// authenticates with.
func enforceOwnedFields(t *corev1.PodTemplateSpec, c *piholev1alpha1.PiholeCluster, hash string, password corev1.EnvVar) {
	if t.Labels == nil {
		t.Labels = map[string]string{}
	}
	maps.Copy(t.Labels, selectorLabels(c))
	if t.Annotations == nil {
		t.Annotations = map[string]string{}
	}
	t.Annotations[annConfigHash] = hash
	for i := range t.Spec.Containers {
		ct := &t.Spec.Containers[i]
		if ct.Name != piholeContainer {
			continue
		}
		ct.Env = slices.DeleteFunc(ct.Env, func(e corev1.EnvVar) bool { return e.Name == password.Name })
		ct.Env = append(ct.Env, password)
	}
}

func mutateHeadless(svc *corev1.Service, c *piholev1alpha1.PiholeCluster) {
	svc.Labels = commonLabels(c)
	svc.Spec.ClusterIP = corev1.ClusterIPNone
	svc.Spec.PublishNotReadyAddresses = true
	svc.Spec.Selector = selectorLabels(c)
	svc.Spec.Ports = []corev1.ServicePort{{Name: portHTTP, Port: webPort, TargetPort: intstr.FromInt32(webPort), Protocol: corev1.ProtocolTCP}}
}

func mutateExposed(svc *corev1.Service, c *piholev1alpha1.PiholeCluster, spec piholev1alpha1.ServiceSpec, ports []corev1.ServicePort) {
	svc.Labels = maps.Clone(spec.Labels)
	if svc.Labels == nil {
		svc.Labels = map[string]string{}
	}
	maps.Copy(svc.Labels, commonLabels(c)) // operator labels win
	svc.Annotations = spec.Annotations
	svc.Spec.Selector = selectorLabels(c)
	typ := spec.Type
	if typ == "" {
		typ = corev1.ServiceTypeClusterIP
	}
	svc.Spec.Type = typ
	svc.Spec.LoadBalancerIP = spec.LoadBalancerIP //nolint:staticcheck // still the most portable way to request an address
	if typ == corev1.ServiceTypeClusterIP {
		svc.Spec.ExternalTrafficPolicy = ""
	} else if spec.ExternalTrafficPolicy != "" {
		svc.Spec.ExternalTrafficPolicy = spec.ExternalTrafficPolicy
	}
	// Keep allocated NodePorts so updates do not churn them.
	existing := map[string]int32{}
	for _, p := range svc.Spec.Ports {
		existing[p.Name] = p.NodePort
	}
	for i := range ports {
		if typ != corev1.ServiceTypeClusterIP {
			ports[i].NodePort = existing[ports[i].Name]
		}
	}
	svc.Spec.Ports = ports
}

func dnsPorts() []corev1.ServicePort {
	return []corev1.ServicePort{
		{Name: "dns-udp", Port: 53, TargetPort: intstr.FromString("dns-udp"), Protocol: corev1.ProtocolUDP},
		{Name: "dns-tcp", Port: 53, TargetPort: intstr.FromString("dns-tcp"), Protocol: corev1.ProtocolTCP},
	}
}

func webPorts() []corev1.ServicePort {
	return []corev1.ServicePort{{Name: portHTTP, Port: webPort, TargetPort: intstr.FromString(portHTTP), Protocol: corev1.ProtocolTCP}}
}

func mutatePDB(pdb *policyv1.PodDisruptionBudget, c *piholev1alpha1.PiholeCluster) {
	pdb.Labels = commonLabels(c)
	pdb.Spec.Selector = &metav1.LabelSelector{MatchLabels: selectorLabels(c)}
	pdb.Spec.MaxUnavailable = new(intstr.FromInt32(1))
	pdb.Spec.MinAvailable = nil
}

func sortedPods(pods []corev1.Pod) []corev1.Pod {
	slices.SortFunc(pods, func(a, b corev1.Pod) int { return strings.Compare(a.Name, b.Name) })
	return pods
}

func podReady(p *corev1.Pod) bool {
	if p.DeletionTimestamp != nil || p.Status.PodIP == "" {
		return false
	}
	for _, c := range p.Status.Conditions {
		if c.Type == corev1.PodReady {
			return c.Status == corev1.ConditionTrue
		}
	}
	return false
}
