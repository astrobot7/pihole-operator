package controller

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus/testutil"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	eventsv1 "k8s.io/api/events/v1"
	policyv1 "k8s.io/api/policy/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	piholev1alpha1 "github.com/astrobot7/pihole-operator/api/v1alpha1"
	"github.com/astrobot7/pihole-operator/internal/piholeapi"
	"github.com/astrobot7/pihole-operator/internal/piholeapi/fakepihole"
)

const (
	timeout  = 20 * time.Second
	interval = 200 * time.Millisecond
)

func envMap(c corev1.Container) map[string]string {
	m := map[string]string{}
	for _, e := range c.Env {
		m[e.Name] = e.Value
	}
	return m
}

// makeReadyPod stands in for the kubelet: it creates a pod like the StatefulSet would and marks it Ready.
func makeReadyPod(ns, cluster string, idx int, ip string) {
	var sts appsv1.StatefulSet
	Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: cluster}, &sts)).To(Succeed())
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: cluster + "-" + string(rune('0'+idx)), Namespace: ns,
			Labels:      sts.Spec.Template.Labels,
			Annotations: sts.Spec.Template.Annotations,
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "pihole", Image: "pihole"}}},
	}
	Expect(k8sClient.Create(ctx, pod)).To(Succeed())
	pod.Status = corev1.PodStatus{
		PodIP: ip, Phase: corev1.PodRunning,
		Conditions: []corev1.PodCondition{{Type: corev1.PodReady, Status: corev1.ConditionTrue}},
	}
	Expect(k8sClient.Status().Update(ctx, pod)).To(Succeed())
}

func clusterCondition(ns, name, typ string) func() metav1.ConditionStatus {
	return func() metav1.ConditionStatus {
		var c piholev1alpha1.PiholeCluster
		if err := k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &c); err != nil {
			return ""
		}
		if cond := meta.FindStatusCondition(c.Status.Conditions, typ); cond != nil {
			return cond.Status
		}
		return ""
	}
}

var _ = Describe("PiholeCluster controller", func() {
	It("creates the workload with safe defaults", func() {
		ns := "workload"
		Expect(k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})).To(Succeed())
		Expect(k8sClient.Create(ctx, &piholev1alpha1.PiholeCluster{
			ObjectMeta: metav1.ObjectMeta{Name: "home", Namespace: ns},
			Spec: piholev1alpha1.PiholeClusterSpec{
				Replicas:   ptr.To[int32](3),
				Upstreams:  []string{"9.9.9.9", "149.112.112.112"},
				FTL:        map[string]string{"dns_dnssec": "true"},
				DNSService: piholev1alpha1.ServiceSpec{Type: corev1.ServiceTypeLoadBalancer, ExternalTrafficPolicy: corev1.ServiceExternalTrafficPolicyLocal},
			},
		})).To(Succeed())

		var sts appsv1.StatefulSet
		Eventually(func() error {
			return k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "home"}, &sts)
		}, timeout, interval).Should(Succeed())
		Expect(*sts.Spec.Replicas).To(Equal(int32(3)))
		Expect(sts.Spec.VolumeClaimTemplates).To(HaveLen(1))
		Expect(sts.Spec.Template.Annotations).To(HaveKey(annConfigHash))
		env := envMap(sts.Spec.Template.Spec.Containers[0])
		Expect(env).To(HaveKeyWithValue("FTLCONF_dns_listeningMode", "ALL"))
		Expect(env).To(HaveKeyWithValue("FTLCONF_dns_upstreams", "9.9.9.9;149.112.112.112"))
		Expect(env).To(HaveKeyWithValue("FTLCONF_dns_dnssec", "true"))

		var secret corev1.Secret
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "home-admin"}, &secret)).To(Succeed())
		Expect(secret.Data[passwordKey]).NotTo(BeEmpty())

		var dns corev1.Service
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "home-dns"}, &dns)).To(Succeed())
		Expect(dns.Spec.Type).To(Equal(corev1.ServiceTypeLoadBalancer))
		Expect(dns.Spec.ExternalTrafficPolicy).To(Equal(corev1.ServiceExternalTrafficPolicyLocal))
		Expect(dns.Spec.Ports).To(HaveLen(2))

		var pdb policyv1.PodDisruptionBudget
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "home"}, &pdb)).To(Succeed())
		Expect(pdb.Spec.MaxUnavailable.IntValue()).To(Equal(1))

		By("keeping the generated password across reconciles and rolling pods on upstream change")
		oldHash := sts.Spec.Template.Annotations[annConfigHash]
		var c piholev1alpha1.PiholeCluster
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "home"}, &c)).To(Succeed())
		c.Spec.Upstreams = []string{"1.1.1.1"}
		Expect(k8sClient.Update(ctx, &c)).To(Succeed())
		Eventually(func() string {
			_ = k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "home"}, &sts)
			return sts.Spec.Template.Annotations[annConfigHash]
		}, timeout, interval).ShouldNot(Equal(oldHash))
		var again corev1.Secret
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "home-admin"}, &again)).To(Succeed())
		Expect(again.Data[passwordKey]).To(Equal(secret.Data[passwordKey]))
	})

	It("syncs configuration CRs to every replica and prunes on delete", func() {
		ns := "sync"
		Expect(k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})).To(Succeed())
		Expect(k8sClient.Create(ctx, &piholev1alpha1.PiholeCluster{
			ObjectMeta: metav1.ObjectMeta{Name: "lan", Namespace: ns},
			Spec: piholev1alpha1.PiholeClusterSpec{
				Replicas:     ptr.To[int32](2),
				SyncInterval: &metav1.Duration{Duration: time.Second},
			},
		})).To(Succeed())
		Eventually(func() error {
			return k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "lan"}, &appsv1.StatefulSet{})
		}, timeout, interval).Should(Succeed())

		// A hand-made list from the web UI that must survive ManagedOnly pruning.
		f0, f1 := fakeFor("10.1.0.10"), fakeFor("10.1.0.11")
		f0.Mutate(func(s *fakepihole.State) {
			s.Lists = append(s.Lists, fakeList("https://handmade", "Migrated"))
		})
		makeReadyPod(ns, "lan", 0, "10.1.0.10")
		makeReadyPod(ns, "lan", 1, "10.1.0.11")

		bl := &piholev1alpha1.PiholeBlocklist{
			ObjectMeta: metav1.ObjectMeta{Name: "ads", Namespace: ns},
			Spec: piholev1alpha1.PiholeBlocklistSpec{
				ClusterRef: piholev1alpha1.ClusterReference{Name: "lan"},
				Lists:      []piholev1alpha1.ListSource{{URL: "https://lists.example/ads.txt"}},
			},
		}
		Expect(k8sClient.Create(ctx, bl)).To(Succeed())
		Expect(k8sClient.Create(ctx, &piholev1alpha1.PiholeDomainList{
			ObjectMeta: metav1.ObjectMeta{Name: "rules", Namespace: ns},
			Spec: piholev1alpha1.PiholeDomainListSpec{
				ClusterRef: piholev1alpha1.ClusterReference{Name: "lan"},
				Groups:     []string{"kids"},
				Entries:    []piholev1alpha1.DomainEntry{{Domain: "games.example", Action: piholev1alpha1.DomainDeny}},
			},
		})).To(Succeed())
		Expect(k8sClient.Create(ctx, &piholev1alpha1.PiholeGroup{
			ObjectMeta: metav1.ObjectMeta{Name: "kids", Namespace: ns},
			Spec: piholev1alpha1.PiholeGroupSpec{
				ClusterRef:         piholev1alpha1.ClusterReference{Name: "lan"},
				Description:        "kids devices",
				ExcludeFromDefault: true,
				Clients:            []string{"10.20.0.0/24", "aa:bb:cc:dd:ee:ff"},
			},
		})).To(Succeed())
		lanRef := piholev1alpha1.ClusterReference{Name: "lan"}
		Expect(k8sClient.Create(ctx, &piholev1alpha1.PiholeARecord{
			ObjectMeta: metav1.ObjectMeta{Name: "nas", Namespace: ns},
			Spec:       piholev1alpha1.PiholeARecordSpec{ClusterRef: lanRef, Hostname: "nas.lan", IP: "10.0.0.5"},
		})).To(Succeed())
		Expect(k8sClient.Create(ctx, &piholev1alpha1.PiholeAAAARecord{
			ObjectMeta: metav1.ObjectMeta{Name: "nas-v6", Namespace: ns},
			Spec:       piholev1alpha1.PiholeAAAARecordSpec{ClusterRef: lanRef, Hostname: "nas.lan", IP: "fd00::5"},
		})).To(Succeed())
		Expect(k8sClient.Create(ctx, &piholev1alpha1.PiholeCNAMERecord{
			ObjectMeta: metav1.ObjectMeta{Name: "files", Namespace: ns},
			Spec:       piholev1alpha1.PiholeCNAMERecordSpec{ClusterRef: lanRef, Hostname: "files.lan", Target: "nas.lan"},
		})).To(Succeed())

		for _, f := range []*fakepihole.Pihole{f0, f1} {
			Eventually(func(g Gomega) {
				s := f.Snapshot()
				g.Expect(s.Domains).To(HaveLen(1))
				g.Expect(s.Hosts).To(Equal([]string{"10.0.0.5 nas.lan", "fd00::5 nas.lan"}))
				g.Expect(s.CNAMEs).To(Equal([]string{"files.lan,nas.lan"}))
				g.Expect(addresses(s)).To(ContainElement("https://lists.example/ads.txt"))
				g.Expect(s.GravityRuns).To(Equal(1), "gravity runs once per pod after lists change")
				g.Expect(s.Clients).To(HaveLen(2))
				kids := -1
				for _, gr := range s.Groups {
					if gr.Name == "kids" {
						kids = gr.ID
						g.Expect(gr.Comment).To(HavePrefix("kids devices ["))
					}
				}
				g.Expect(kids).To(BeNumerically(">", 0))
				g.Expect(s.Domains[0].Groups).To(Equal([]int{kids}), "domain list's group resolves to the declared group")
				for _, c := range s.Clients {
					g.Expect(c.Groups).To(Equal([]int{kids}), "excludeFromDefault keeps clients out of Default")
				}
			}, timeout, interval).Should(Succeed())
		}
		Eventually(clusterCondition(ns, "lan", piholev1alpha1.ConditionSynced), timeout, interval).Should(Equal(metav1.ConditionTrue))
		Consistently(func() int { return f0.Snapshot().GravityRuns }, 2*time.Second, interval).Should(Equal(1),
			"periodic resyncs with no list changes must not rebuild gravity")

		By("exporting metrics and events")
		Expect(testutil.ToFloat64(clusterSynced.WithLabelValues(ns, "lan"))).To(Equal(1.0))
		Expect(testutil.ToFloat64(replicasSynced.WithLabelValues(ns, "lan"))).To(Equal(2.0))
		Expect(testutil.ToFloat64(gravityRebuilds.WithLabelValues(ns, "lan", "success"))).To(Equal(2.0))
		Eventually(func() []string {
			var evs eventsv1.EventList
			_ = k8sClient.List(ctx, &evs, client.InNamespace(ns))
			var reasons []string
			for _, e := range evs.Items {
				if e.Regarding.Name == "lan" {
					reasons = append(reasons, e.Reason)
				}
			}
			return reasons
		}, timeout, interval).Should(ContainElements("Synced", "GravityRebuilt"))

		By("removing a group's assignments when its CR is deleted")
		Expect(k8sClient.Delete(ctx, &piholev1alpha1.PiholeGroup{ObjectMeta: metav1.ObjectMeta{Name: "kids", Namespace: ns}})).To(Succeed())
		Eventually(func() int { return len(f1.Snapshot().Clients) }, timeout, interval).Should(Equal(0))
		Eventually(func() metav1.ConditionStatus {
			var got piholev1alpha1.PiholeBlocklist
			_ = k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "ads"}, &got)
			if c := meta.FindStatusCondition(got.Status.Conditions, piholev1alpha1.ConditionSynced); c != nil {
				return c.Status
			}
			return ""
		}, timeout, interval).Should(Equal(metav1.ConditionTrue))

		By("reporting a CNAME that clashes with an existing one")
		Expect(k8sClient.Create(ctx, &piholev1alpha1.PiholeCNAMERecord{
			ObjectMeta: metav1.ObjectMeta{Name: "zz-files", Namespace: ns},
			Spec:       piholev1alpha1.PiholeCNAMERecordSpec{ClusterRef: lanRef, Hostname: "files.lan", Target: "other.lan"},
		})).To(Succeed())
		Eventually(func() string {
			var got piholev1alpha1.PiholeCNAMERecord
			_ = k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "zz-files"}, &got)
			if c := meta.FindStatusCondition(got.Status.Conditions, piholev1alpha1.ConditionSynced); c != nil && c.Status == metav1.ConditionFalse {
				return c.Reason + ": " + c.Message
			}
			return ""
		}, timeout, interval).Should(And(HavePrefix("Conflict: "), ContainSubstring("sync/files")))
		Expect(f0.Snapshot().CNAMEs).To(Equal([]string{"files.lan,nas.lan"}), "the losing CNAME must not reach Pi-hole")

		By("repairing drift made in the web UI")
		f1.Mutate(func(s *fakepihole.State) { s.Domains = nil })
		Eventually(func() int { return len(f1.Snapshot().Domains) }, timeout, interval).Should(Equal(1))

		By("removing lists when their CR is deleted, keeping hand-made ones")
		Expect(k8sClient.Delete(ctx, bl)).To(Succeed())
		Eventually(func() []string { return addresses(f0.Snapshot()) }, timeout, interval).Should(Equal([]string{"https://handmade"}))
		Eventually(func() []string { return addresses(f1.Snapshot()) }, timeout, interval).Should(BeEmpty())
		Eventually(func() int { return f1.Snapshot().GravityRuns }, timeout, interval).Should(Equal(2))
	})

	It("keeps podTemplate metadata and sidecars through the API server", func() {
		ns := "podtemplate"
		Expect(k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})).To(Succeed())
		Expect(k8sClient.Create(ctx, &piholev1alpha1.PiholeCluster{
			ObjectMeta: metav1.ObjectMeta{Name: "pt", Namespace: ns},
			Spec: piholev1alpha1.PiholeClusterSpec{PodTemplate: &corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels:      map[string]string{"team": "net"},
					Annotations: map[string]string{"prometheus.io/scrape": "true"},
				},
				Spec: corev1.PodSpec{
					PriorityClassName: "system-cluster-critical",
					Containers:        []corev1.Container{{Name: "exporter", Image: "ekofr/pihole-exporter:v1.0.0"}},
				},
			}},
		})).To(Succeed())

		var sts appsv1.StatefulSet
		Eventually(func() error {
			return k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "pt"}, &sts)
		}, timeout, interval).Should(Succeed())
		tpl := sts.Spec.Template
		Expect(tpl.Labels).To(HaveKeyWithValue("team", "net"))
		Expect(tpl.Labels).To(HaveKeyWithValue(labelCluster, "pt"))
		Expect(tpl.Annotations).To(HaveKeyWithValue("prometheus.io/scrape", "true"))
		Expect(tpl.Spec.PriorityClassName).To(Equal("system-cluster-critical"))
		Expect(tpl.Spec.Containers).To(HaveLen(2))
	})

	It("rejects records that fail validation", func() {
		ns := "default"
		ref := piholev1alpha1.ClusterReference{Name: "any"}
		Expect(k8sClient.Create(ctx, &piholev1alpha1.PiholeARecord{
			ObjectMeta: metav1.ObjectMeta{Name: "v6-in-a", Namespace: ns},
			Spec:       piholev1alpha1.PiholeARecordSpec{ClusterRef: ref, Hostname: "x.lan", IP: "fd00::1"},
		})).To(MatchError(ContainSubstring("must be an IPv4 address")))
		Expect(k8sClient.Create(ctx, &piholev1alpha1.PiholeAAAARecord{
			ObjectMeta: metav1.ObjectMeta{Name: "v4-in-aaaa", Namespace: ns},
			Spec:       piholev1alpha1.PiholeAAAARecordSpec{ClusterRef: ref, Hostname: "x.lan", IP: "10.0.0.1"},
		})).To(MatchError(ContainSubstring("must be an IPv6 address")))
		Expect(k8sClient.Create(ctx, &piholev1alpha1.PiholeCNAMERecord{
			ObjectMeta: metav1.ObjectMeta{Name: "loop", Namespace: ns},
			Spec:       piholev1alpha1.PiholeCNAMERecordSpec{ClusterRef: ref, Hostname: "A.lan", Target: "a.lan"},
		})).To(MatchError(ContainSubstring("cannot point at itself")))
		Expect(k8sClient.Create(ctx, &piholev1alpha1.PiholeARecord{
			ObjectMeta: metav1.ObjectMeta{Name: "bad-host", Namespace: ns},
			Spec:       piholev1alpha1.PiholeARecordSpec{ClusterRef: ref, Hostname: "has space.lan", IP: "10.0.0.1"},
		})).To(MatchError(ContainSubstring("spec.hostname")))
	})

	It("reports a missing admin secret", func() {
		ns := "nosecret"
		Expect(k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}})).To(Succeed())
		Expect(k8sClient.Create(ctx, &piholev1alpha1.PiholeCluster{
			ObjectMeta: metav1.ObjectMeta{Name: "x", Namespace: ns},
			Spec: piholev1alpha1.PiholeClusterSpec{AdminPasswordSecretRef: &corev1.SecretKeySelector{
				LocalObjectReference: corev1.LocalObjectReference{Name: "missing"}, Key: "pw",
			}},
		})).To(Succeed())
		Eventually(func() string {
			var c piholev1alpha1.PiholeCluster
			_ = k8sClient.Get(ctx, types.NamespacedName{Namespace: ns, Name: "x"}, &c)
			if cond := meta.FindStatusCondition(c.Status.Conditions, piholev1alpha1.ConditionAvailable); cond != nil {
				return cond.Reason
			}
			return ""
		}, timeout, interval).Should(Equal("PasswordUnavailable"))
	})
})

func addresses(s fakepihole.State) []string {
	out := make([]string, 0, len(s.Lists))
	for _, l := range s.Lists {
		out = append(out, l.Address)
	}
	return out
}

func fakeList(addr, comment string) piholeapi.List {
	return piholeapi.List{Address: addr, Type: "block", Comment: comment, Enabled: true, Groups: []int{0}}
}
