package controller

import (
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	piholev1alpha1 "github.com/astrobot7/pihole-operator/api/v1alpha1"
)

func buildSTS(t *testing.T, c *piholev1alpha1.PiholeCluster) *appsv1.StatefulSet {
	t.Helper()
	sts := &appsv1.StatefulSet{}
	if err := mutateStatefulSet(sts, c, "h1"); err != nil {
		t.Fatalf("mutateStatefulSet: %v", err)
	}
	return sts
}

func container(t *testing.T, pod corev1.PodSpec, name string) corev1.Container {
	t.Helper()
	for _, c := range pod.Containers {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("container %q not found", name)
	return corev1.Container{}
}

func env(c corev1.Container) map[string]corev1.EnvVar {
	m := map[string]corev1.EnvVar{}
	for _, e := range c.Env {
		m[e.Name] = e
	}
	return m
}

func TestPodTemplateMerge(t *testing.T) {
	c := &piholev1alpha1.PiholeCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "home", Namespace: "dns"},
		Spec: piholev1alpha1.PiholeClusterSpec{
			PodTemplate: &corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      map[string]string{"team": "net", labelCluster: "hijack"},
					Annotations: map[string]string{"prometheus.io/scrape": "true", annConfigHash: "user"},
				},
				Spec: corev1.PodSpec{
					NodeSelector:       map[string]string{"kubernetes.io/arch": "arm64"},
					ServiceAccountName: "pihole",
					Containers: []corev1.Container{
						{
							Name: "pihole",
							Env: []corev1.EnvVar{
								{Name: "FTLCONF_misc_etc_dnsmasq_d", Value: "true"},
								{Name: passwordEnv, Value: "user-must-not-win"},
							},
							Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("1Gi")}},
						},
						{Name: "exporter", Image: "ekofr/pihole-exporter:v1.0.0"},
					},
				},
			},
		},
	}
	sts := buildSTS(t, c)
	tpl := sts.Spec.Template

	if tpl.Labels["team"] != "net" || tpl.Labels[labelCluster] != "home" {
		t.Errorf("labels = %v: want user label kept and selector label enforced", tpl.Labels)
	}
	if tpl.Annotations["prometheus.io/scrape"] != "true" || tpl.Annotations[annConfigHash] != "h1" {
		t.Errorf("annotations = %v: want user annotation kept and config hash enforced", tpl.Annotations)
	}
	if tpl.Spec.NodeSelector["kubernetes.io/arch"] != "arm64" || tpl.Spec.ServiceAccountName != "pihole" {
		t.Errorf("pod-level fields not applied: %+v", tpl.Spec)
	}
	if tpl.Spec.Affinity == nil || tpl.Spec.Affinity.PodAntiAffinity == nil {
		t.Error("default anti-affinity dropped although the user set none")
	}

	ph := container(t, tpl.Spec, "pihole")
	if ph.Image != defaultImage || ph.ReadinessProbe == nil || ph.Lifecycle == nil {
		t.Errorf("operator defaults lost on the pihole container: %+v", ph)
	}
	e := env(ph)
	if e["FTLCONF_misc_etc_dnsmasq_d"].Value != "true" || e["FTLCONF_dns_listeningMode"].Value != "ALL" {
		t.Errorf("env not merged by name: %v", e)
	}
	if pw := e[passwordEnv]; pw.Value != "" || pw.ValueFrom == nil || pw.ValueFrom.SecretKeyRef.Name != "home-admin" {
		t.Errorf("password env must stay operator-owned, got %+v", pw)
	}
	if got := ph.Resources.Limits[corev1.ResourceMemory]; got.String() != "1Gi" {
		t.Errorf("resources from template not applied: %v", ph.Resources)
	}
	if container(t, tpl.Spec, "exporter").Image != "ekofr/pihole-exporter:v1.0.0" {
		t.Error("sidecar not added")
	}
}

func TestPodTemplateAffinityReplacesDefault(t *testing.T) {
	c := &piholev1alpha1.PiholeCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "home"},
		Spec: piholev1alpha1.PiholeClusterSpec{PodTemplate: &corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Affinity: &corev1.Affinity{NodeAffinity: &corev1.NodeAffinity{
				RequiredDuringSchedulingIgnoredDuringExecution: &corev1.NodeSelector{NodeSelectorTerms: []corev1.NodeSelectorTerm{{
					MatchExpressions: []corev1.NodeSelectorRequirement{{Key: "dns", Operator: corev1.NodeSelectorOpExists}},
				}}},
			}},
		}}},
	}
	aff := buildSTS(t, c).Spec.Template.Spec.Affinity
	if aff.NodeAffinity == nil || aff.PodAntiAffinity != nil {
		t.Fatalf("user affinity should replace the default: %+v", aff)
	}
}

func TestPodTemplateCustomDataVolume(t *testing.T) {
	zero := resource.MustParse("0")
	c := &piholev1alpha1.PiholeCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "home"},
		Spec: piholev1alpha1.PiholeClusterSpec{
			Storage: piholev1alpha1.StorageSpec{Size: &zero},
			PodTemplate: &corev1.PodTemplateSpec{Spec: corev1.PodSpec{Volumes: []corev1.Volume{{
				Name:         dataVolume,
				VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/srv/pihole"}},
			}}}},
		},
	}
	sts := buildSTS(t, c)
	if len(sts.Spec.VolumeClaimTemplates) != 0 {
		t.Fatal("size 0 must not create a PVC")
	}
	vols := sts.Spec.Template.Spec.Volumes
	if len(vols) != 1 || vols[0].HostPath == nil || vols[0].EmptyDir != nil {
		t.Fatalf("user data volume should replace the emptyDir, got %+v", vols)
	}
}

func TestNoPodTemplateIsUnchanged(t *testing.T) {
	c := &piholev1alpha1.PiholeCluster{ObjectMeta: metav1.ObjectMeta{Name: "home"}}
	sts := buildSTS(t, c)
	if n := len(sts.Spec.Template.Spec.Containers); n != 1 {
		t.Fatalf("want only the pihole container, got %d", n)
	}
	if len(sts.Spec.VolumeClaimTemplates) != 1 {
		t.Fatal("default storage should create a PVC")
	}
}
