package controller

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/recorder"

	piholev1alpha1 "github.com/astrobot7/pihole-operator/api/v1alpha1"
	"github.com/astrobot7/pihole-operator/internal/piholesync"
)

const (
	clusterRefIndex = ".spec.clusterRef.name"
	gravityTimeout  = 15 * time.Minute
	syncTimeout     = 2 * time.Minute
	notSyncedRetry  = 10 * time.Second
)

// gravityRunner is implemented by piholeapi.Client.
type gravityRunner interface {
	RunGravity(ctx context.Context) error
}

// PiholeClusterReconciler reconciles a PiholeCluster and every configuration
// object that references it.
type PiholeClusterReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// Recorder emits Kubernetes events. Optional.
	Recorder recorder.EventRecorder
	// NewClient overrides how Pi-hole API clients are built (tests).
	NewClient ClientFactory
	pool      *clientPool
}

// event records an event on the cluster. related is the pod involved, if
// any; it keeps per-pod events from being folded into one series.
func (r *PiholeClusterReconciler) event(c *piholev1alpha1.PiholeCluster, related runtime.Object, typ, reason, action, note string, args ...any) {
	if r.Recorder != nil {
		r.Recorder.Eventf(c, related, typ, reason, action, note, args...)
	}
}

// +kubebuilder:rbac:groups=pihole.io,resources=piholeclusters;piholeblocklists;piholedomainlists;piholelocalrecords;piholegroups,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=pihole.io,resources=piholeclusters/status;piholeblocklists/status;piholedomainlists/status;piholelocalrecords/status;piholegroups/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=events.k8s.io,resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=pihole.io,resources=piholeclusters/finalizers,verbs=update
// +kubebuilder:rbac:groups=apps,resources=statefulsets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=services;secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=pods,verbs=get;list;watch
// +kubebuilder:rbac:groups=policy,resources=poddisruptionbudgets,verbs=get;list;watch;create;update;patch;delete

func (r *PiholeClusterReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var c piholev1alpha1.PiholeCluster
	if err := r.Get(ctx, req.NamespacedName, &c); err != nil {
		if apierrors.IsNotFound(err) {
			r.pool.retain(ctx, req.String(), nil)
			forgetClusterMetrics(req.Namespace, req.Name)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !c.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil
	}
	orig := c.DeepCopy()

	password, err := r.ensureAdminSecret(ctx, &c)
	if err != nil {
		r.setCondition(&c, piholev1alpha1.ConditionAvailable, false, "PasswordUnavailable", err.Error())
		r.event(&c, nil, corev1.EventTypeWarning, "PasswordUnavailable", "ReadSecret", "%s", err.Error())
		return ctrl.Result{}, errors.Join(err, r.patchStatus(ctx, orig, &c))
	}
	hash := configHash(&c, password)

	if err := r.ensureWorkload(ctx, &c, hash); err != nil {
		return ctrl.Result{}, err
	}

	var pods corev1.PodList
	if err := r.List(ctx, &pods, client.InNamespace(c.Namespace), client.MatchingLabels(selectorLabels(&c))); err != nil {
		return ctrl.Result{}, err
	}

	desired, children, err := r.desiredState(ctx, &c)
	if err != nil {
		return ctrl.Result{}, err
	}

	synced := r.syncPods(ctx, &c, sortedPods(pods.Items), desired, hash, password)

	wantReplicas := ptr.Deref(c.Spec.Replicas, 2)
	fullySynced := synced && c.Status.ReadyReplicas == wantReplicas
	c.Status.ObservedGeneration = c.Generation
	if fullySynced {
		c.Status.ManagedHosts, c.Status.ManagedCNAMEs = desired.Hosts, desired.CNAMEs
	} else {
		// Some pods may still hold records we no longer want; keep remembering them.
		c.Status.ManagedHosts = union(c.Status.ManagedHosts, desired.Hosts)
		c.Status.ManagedCNAMEs = union(c.Status.ManagedCNAMEs, desired.CNAMEs)
	}

	if c.Status.ReadyReplicas > 0 {
		r.setCondition(&c, piholev1alpha1.ConditionAvailable, true, "DNSServing",
			fmt.Sprintf("%d/%d replicas answering DNS", c.Status.ReadyReplicas, wantReplicas))
	} else {
		r.setCondition(&c, piholev1alpha1.ConditionAvailable, false, "NoReadyReplicas", "no replica is answering DNS")
	}
	r.setCondition(&c, piholev1alpha1.ConditionDegraded, c.Status.ReadyReplicas < wantReplicas, "ReplicasNotReady",
		fmt.Sprintf("%d/%d replicas ready", c.Status.ReadyReplicas, wantReplicas))

	labels := []string{c.Namespace, c.Name}
	replicasReady.WithLabelValues(labels...).Set(float64(c.Status.ReadyReplicas))
	replicasSynced.WithLabelValues(labels...).Set(float64(countSynced(&c)))
	clusterSynced.WithLabelValues(labels...).Set(ternary(fullySynced, 1.0, 0.0))

	msg := syncMessage(&c, wantReplicas)
	r.setCondition(&c, piholev1alpha1.ConditionSynced, fullySynced, ternary(fullySynced, "Converged", "Converging"), msg)

	if err := r.patchStatus(ctx, orig, &c); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.updateChildren(ctx, children, fullySynced, msg); err != nil {
		log.Error(err, "updating child status")
	}

	if !fullySynced {
		return ctrl.Result{RequeueAfter: notSyncedRetry}, nil
	}
	interval := 5 * time.Minute
	if c.Spec.SyncInterval != nil && c.Spec.SyncInterval.Duration > 0 {
		interval = c.Spec.SyncInterval.Duration
	}
	return ctrl.Result{RequeueAfter: interval}, nil
}

// ensureAdminSecret returns the admin password, generating a Secret if the
// user did not reference one. An existing generated password is never changed.
func (r *PiholeClusterReconciler) ensureAdminSecret(ctx context.Context, c *piholev1alpha1.PiholeCluster) (string, error) {
	ref := passwordRef(c)
	if c.Spec.AdminPasswordSecretRef == nil {
		s := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: ref.Name, Namespace: c.Namespace}}
		_, err := controllerutil.CreateOrUpdate(ctx, r.Client, s, func() error {
			s.Labels = commonLabels(c)
			if len(s.Data[passwordKey]) == 0 {
				b := make([]byte, 18)
				if _, err := rand.Read(b); err != nil {
					return err
				}
				if s.Data == nil {
					s.Data = map[string][]byte{}
				}
				s.Data[passwordKey] = []byte(base64.RawURLEncoding.EncodeToString(b))
			}
			return controllerutil.SetControllerReference(c, s, r.Scheme)
		})
		if err != nil {
			return "", fmt.Errorf("admin secret: %w", err)
		}
		return string(s.Data[passwordKey]), nil
	}
	var s corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: c.Namespace, Name: ref.Name}, &s); err != nil {
		return "", fmt.Errorf("admin secret %s: %w", ref.Name, err)
	}
	pw := s.Data[ref.Key]
	if len(pw) == 0 {
		return "", fmt.Errorf("admin secret %s has no key %q", ref.Name, ref.Key)
	}
	return string(pw), nil
}

type owned struct {
	obj    client.Object
	mutate func() error
}

func (r *PiholeClusterReconciler) ensureWorkload(ctx context.Context, c *piholev1alpha1.PiholeCluster, hash string) error {
	headless := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: headlessName(c), Namespace: c.Namespace}}
	dns := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: dnsName(c), Namespace: c.Namespace}}
	web := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: webName(c), Namespace: c.Namespace}}
	pdb := &policyv1.PodDisruptionBudget{ObjectMeta: metav1.ObjectMeta{Name: c.Name, Namespace: c.Namespace}}
	sts := &appsv1.StatefulSet{ObjectMeta: metav1.ObjectMeta{Name: c.Name, Namespace: c.Namespace}}
	objs := []owned{
		{headless, func() error { mutateHeadless(headless, c); return nil }},
		{dns, func() error { mutateExposed(dns, c, c.Spec.DNSService, dnsPorts()); return nil }},
		{web, func() error { mutateExposed(web, c, c.Spec.WebService, webPorts()); return nil }},
		{pdb, func() error { mutatePDB(pdb, c); return nil }},
		{sts, func() error { return mutateStatefulSet(sts, c, hash) }},
	}
	for _, o := range objs {
		if _, err := controllerutil.CreateOrUpdate(ctx, r.Client, o.obj, func() error {
			if err := o.mutate(); err != nil {
				return err
			}
			return controllerutil.SetControllerReference(c, o.obj, r.Scheme)
		}); err != nil {
			return fmt.Errorf("%T %s: %w", o.obj, o.obj.GetName(), err)
		}
	}
	return nil
}

// childObject gives uniform access to the config CRs' status.
type childObject interface {
	object() client.Object
	status() *piholev1alpha1.ConfigStatus
}

type blocklist struct {
	*piholev1alpha1.PiholeBlocklist
}
type domainList struct {
	*piholev1alpha1.PiholeDomainList
}
type localRecord struct {
	*piholev1alpha1.PiholeLocalRecord
}

type group struct {
	*piholev1alpha1.PiholeGroup
}

func (b blocklist) status() *piholev1alpha1.ConfigStatus   { return &b.Status }
func (d domainList) status() *piholev1alpha1.ConfigStatus  { return &d.Status }
func (l localRecord) status() *piholev1alpha1.ConfigStatus { return &l.Status }
func (b blocklist) object() client.Object                  { return b.PiholeBlocklist }
func (d domainList) object() client.Object                 { return d.PiholeDomainList }
func (l localRecord) object() client.Object                { return l.PiholeLocalRecord }
func (g group) status() *piholev1alpha1.ConfigStatus       { return &g.Status }
func (g group) object() client.Object                      { return g.PiholeGroup }

func (r *PiholeClusterReconciler) desiredState(ctx context.Context, c *piholev1alpha1.PiholeCluster) (piholesync.Desired, []childObject, error) {
	opts := []client.ListOption{client.InNamespace(c.Namespace), client.MatchingFields{clusterRefIndex: c.Name}}
	var bl piholev1alpha1.PiholeBlocklistList
	var dl piholev1alpha1.PiholeDomainListList
	var lr piholev1alpha1.PiholeLocalRecordList
	var gl piholev1alpha1.PiholeGroupList
	if err := r.List(ctx, &gl, opts...); err != nil {
		return piholesync.Desired{}, nil, err
	}
	if err := r.List(ctx, &bl, opts...); err != nil {
		return piholesync.Desired{}, nil, err
	}
	if err := r.List(ctx, &dl, opts...); err != nil {
		return piholesync.Desired{}, nil, err
	}
	if err := r.List(ctx, &lr, opts...); err != nil {
		return piholesync.Desired{}, nil, err
	}
	var children []childObject
	for i := range bl.Items {
		children = append(children, blocklist{&bl.Items[i]})
	}
	for i := range dl.Items {
		children = append(children, domainList{&dl.Items[i]})
	}
	for i := range lr.Items {
		children = append(children, localRecord{&lr.Items[i]})
	}
	for i := range gl.Items {
		children = append(children, group{&gl.Items[i]})
	}
	return piholesync.Build(bl.Items, dl.Items, lr.Items, gl.Items), children, nil
}

// syncPods converges every ready pod and then rebuilds gravity on at most one
// pod, so only one replica is under gravity load at a time. It fills in
// c.Status.Replicas and ReadyReplicas and reports whether every ready pod is
// converged with nothing pending.
func (r *PiholeClusterReconciler) syncPods(ctx context.Context, c *piholev1alpha1.PiholeCluster, pods []corev1.Pod,
	desired piholesync.Desired, hash, password string) bool {
	log := logf.FromContext(ctx)
	desiredHash := desired.Hash()
	clusterKey := c.Namespace + "/" + c.Name
	prev := map[string]piholev1alpha1.ReplicaStatus{}
	for _, rs := range c.Status.Replicas {
		prev[rs.Pod] = rs
	}

	opt := piholesync.Options{
		PruneAll:       c.Spec.PrunePolicy == piholev1alpha1.PruneAll,
		PreviousHosts:  c.Status.ManagedHosts,
		PreviousCNAMEs: c.Status.ManagedCNAMEs,
	}
	keep := map[poolKey]bool{}
	clients := map[string]piholesync.API{}
	statuses := []piholev1alpha1.ReplicaStatus{}
	var ready int32
	allSynced := true

	for i := range pods {
		p := &pods[i]
		rs := piholev1alpha1.ReplicaStatus{Pod: p.Name, Ready: podReady(p)}
		if old, seen := prev[p.Name]; seen {
			rs.SyncedHash, rs.LastSyncTime, rs.GravityPending = old.SyncedHash, old.LastSyncTime, old.GravityPending
		}
		if !rs.Ready {
			rs.Message = "waiting for pod to answer DNS"
			statuses = append(statuses, rs)
			allSynced = false
			continue
		}
		ready++
		if h := p.Annotations[annConfigHash]; h != "" && h != hash {
			// Old pod during a rollout: its password may differ, so skip until replaced.
			rs.Message = "waiting for rollout"
			statuses = append(statuses, rs)
			allSynced = false
			continue
		}
		k := poolKey{cluster: clusterKey, podUID: string(p.UID), podIP: p.Status.PodIP, passHash: hashString(password)}
		keep[k] = true
		api := r.pool.get(k, password)
		clients[p.Name] = api

		sctx, cancel := context.WithTimeout(ctx, syncTimeout)
		res, err := piholesync.Converge(sctx, api, desired, opt)
		cancel()
		if res.ListsChanged {
			rs.GravityPending = true
		}
		syncChanges.WithLabelValues(c.Namespace, c.Name).Add(float64(res.Changes))
		if err != nil {
			log.Error(err, "sync failed", "pod", p.Name)
			rs.Message = truncate(err.Error(), 512)
			allSynced = false
			replicaSyncs.WithLabelValues(c.Namespace, c.Name, "error").Inc()
			r.event(c, p, corev1.EventTypeWarning, "SyncFailed", "Sync", "%s: %s", p.Name, truncate(err.Error(), 512))
		} else {
			rs.SyncedHash = desiredHash
			rs.LastSyncTime = new(metav1.Now())
			replicaSyncs.WithLabelValues(c.Namespace, c.Name, "success").Inc()
			if res.Changes > 0 {
				log.Info("synced", "pod", p.Name, "changes", res.Changes)
				r.event(c, p, corev1.EventTypeNormal, "Synced", "Sync", "applied %d change(s) to %s", res.Changes, p.Name)
			}
		}
		statuses = append(statuses, rs)
	}
	r.pool.retain(ctx, clusterKey, keep)

	podByName := map[string]runtime.Object{}
	for i := range pods {
		podByName[pods[i].Name] = &pods[i]
	}

	// Rebuild gravity on the first pending pod only.
	for i := range statuses {
		rs := &statuses[i]
		api, ok := clients[rs.Pod]
		if !rs.GravityPending || !ok {
			continue
		}
		gr, ok := api.(gravityRunner)
		if !ok {
			rs.GravityPending = false
			break
		}
		gctx, cancel := context.WithTimeout(ctx, gravityTimeout)
		start := time.Now()
		err := gr.RunGravity(gctx)
		cancel()
		took := time.Since(start)
		gravityDuration.WithLabelValues(c.Namespace, c.Name).Observe(took.Seconds())
		if err != nil {
			log.Error(err, "gravity failed", "pod", rs.Pod)
			rs.Message = "gravity: " + truncate(err.Error(), 500)
			gravityRebuilds.WithLabelValues(c.Namespace, c.Name, "error").Inc()
			r.event(c, podByName[rs.Pod], corev1.EventTypeWarning, "GravityFailed", "RebuildGravity", "%s: %s", rs.Pod, truncate(err.Error(), 500))
		} else {
			log.Info("gravity rebuilt", "pod", rs.Pod, "took", took.Round(time.Second))
			gravityRebuilds.WithLabelValues(c.Namespace, c.Name, "success").Inc()
			r.event(c, podByName[rs.Pod], corev1.EventTypeNormal, "GravityRebuilt", "RebuildGravity", "%s rebuilt gravity in %s", rs.Pod, took.Round(time.Second))
			rs.GravityPending = false
			c.Status.LastGravityUpdate = new(metav1.Now())
		}
		break
	}
	for _, rs := range statuses {
		if rs.GravityPending || rs.SyncedHash != desiredHash {
			allSynced = false
		}
	}

	c.Status.Replicas = statuses
	c.Status.ReadyReplicas = ready
	c.Status.DesiredHash = desiredHash
	return allSynced
}

func countSynced(c *piholev1alpha1.PiholeCluster) int {
	n := 0
	for _, rs := range c.Status.Replicas {
		if rs.Ready && rs.Message == "" && !rs.GravityPending && rs.SyncedHash == c.Status.DesiredHash {
			n++
		}
	}
	return n
}

func syncMessage(c *piholev1alpha1.PiholeCluster, want int32) string {
	var parts []string
	synced := 0
	for _, rs := range c.Status.Replicas {
		switch {
		case rs.Message != "":
			parts = append(parts, rs.Pod+": "+rs.Message)
		case rs.GravityPending:
			parts = append(parts, rs.Pod+": gravity rebuild pending")
		case rs.SyncedHash == c.Status.DesiredHash:
			synced++
		}
	}
	head := fmt.Sprintf("%d/%d replicas synced", synced, want)
	if len(parts) == 0 {
		return head
	}
	return truncate(head+"; "+strings.Join(parts, "; "), 1024)
}

func (r *PiholeClusterReconciler) updateChildren(ctx context.Context, children []childObject, synced bool, msg string) error {
	var errs []error
	for _, child := range children {
		ch := child.object()
		before := ch.DeepCopyObject().(client.Object)
		st := child.status()
		changed := st.ObservedGeneration != ch.GetGeneration()
		st.ObservedGeneration = ch.GetGeneration()
		if meta.SetStatusCondition(&st.Conditions, metav1.Condition{
			Type: piholev1alpha1.ConditionSynced, Status: boolStatus(synced),
			Reason: ternary(synced, "Applied", "Pending"), Message: msg, ObservedGeneration: ch.GetGeneration(),
		}) {
			changed = true
		}
		if !changed {
			continue
		}
		if err := r.Status().Patch(ctx, ch, client.MergeFrom(before)); client.IgnoreNotFound(err) != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (r *PiholeClusterReconciler) setCondition(c *piholev1alpha1.PiholeCluster, typ string, ok bool, reason, msg string) {
	meta.SetStatusCondition(&c.Status.Conditions, metav1.Condition{
		Type: typ, Status: boolStatus(ok), Reason: reason, Message: msg, ObservedGeneration: c.Generation,
	})
}

func (r *PiholeClusterReconciler) patchStatus(ctx context.Context, orig, c *piholev1alpha1.PiholeCluster) error {
	return client.IgnoreNotFound(r.Status().Patch(ctx, c, client.MergeFrom(orig)))
}

func indexClusterRef[T client.Object](ctx context.Context, mgr ctrl.Manager, obj T, name func(T) string) error {
	return mgr.GetFieldIndexer().IndexField(ctx, obj, clusterRefIndex, func(o client.Object) []string {
		return []string{name(o.(T))}
	})
}

func enqueueCluster[T client.Object](name func(T) string) handler.EventHandler {
	return handler.EnqueueRequestsFromMapFunc(func(_ context.Context, o client.Object) []reconcile.Request {
		t, ok := o.(T)
		if !ok {
			return nil
		}
		n := name(t)
		if n == "" {
			return nil
		}
		return []reconcile.Request{{NamespacedName: types.NamespacedName{Namespace: o.GetNamespace(), Name: n}}}
	})
}

// SetupWithManager sets up the controller with the Manager.
func (r *PiholeClusterReconciler) SetupWithManager(mgr ctrl.Manager) error {
	r.pool = newClientPool(r.NewClient)
	ctx := context.Background()
	blRef := func(o *piholev1alpha1.PiholeBlocklist) string { return o.Spec.ClusterRef.Name }
	dlRef := func(o *piholev1alpha1.PiholeDomainList) string { return o.Spec.ClusterRef.Name }
	lrRef := func(o *piholev1alpha1.PiholeLocalRecord) string { return o.Spec.ClusterRef.Name }
	grRef := func(o *piholev1alpha1.PiholeGroup) string { return o.Spec.ClusterRef.Name }
	if err := indexClusterRef(ctx, mgr, &piholev1alpha1.PiholeGroup{}, grRef); err != nil {
		return err
	}
	if err := indexClusterRef(ctx, mgr, &piholev1alpha1.PiholeBlocklist{}, blRef); err != nil {
		return err
	}
	if err := indexClusterRef(ctx, mgr, &piholev1alpha1.PiholeDomainList{}, dlRef); err != nil {
		return err
	}
	if err := indexClusterRef(ctx, mgr, &piholev1alpha1.PiholeLocalRecord{}, lrRef); err != nil {
		return err
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&piholev1alpha1.PiholeCluster{}).
		Owns(&appsv1.StatefulSet{}).
		Owns(&corev1.Service{}).
		Owns(&corev1.Secret{}).
		Owns(&policyv1.PodDisruptionBudget{}).
		Watches(&piholev1alpha1.PiholeBlocklist{}, enqueueCluster(blRef)).
		Watches(&piholev1alpha1.PiholeDomainList{}, enqueueCluster(dlRef)).
		Watches(&piholev1alpha1.PiholeLocalRecord{}, enqueueCluster(lrRef)).
		Watches(&piholev1alpha1.PiholeGroup{}, enqueueCluster(grRef)).
		// Pod readiness changes and restarts trigger a sync so new replicas converge quickly.
		Watches(&corev1.Pod{}, enqueueCluster(func(o *corev1.Pod) string { return o.Labels[labelCluster] })).
		Named("piholecluster").
		Complete(r)
}

func union(a, b []string) []string {
	out := append(slices.Clone(a), b...)
	slices.Sort(out)
	return slices.Compact(out)
}

func hashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func boolStatus(b bool) metav1.ConditionStatus {
	if b {
		return metav1.ConditionTrue
	}
	return metav1.ConditionFalse
}

func ternary[T any](cond bool, a, b T) T {
	if cond {
		return a
	}
	return b
}
