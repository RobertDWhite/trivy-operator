package operator_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/ext"
	"github.com/aquasecurity/trivy-operator/pkg/operator"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/aquasecurity/trivy-operator/pkg/vulnerabilityreport"
	"github.com/go-logr/logr"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

// Run against an isolated API server, never the configured production cluster.
func TestClusterPartitionTTLWatchEnvtest(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("requires isolated envtest API binaries")
	}
	env := &envtest.Environment{CRDDirectoryPaths: []string{filepath.Join("..", "..", "deploy", "helm", "crds")}, ErrorIfCRDPathMissing: true}
	cfg, err := env.Start()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, env.Stop()) })
	scheme := trivyoperator.NewScheme()
	direct, err := client.New(cfg, client.Options{Scheme: scheme})
	require.NoError(t, err)
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{Scheme: scheme, Metrics: metricsserver.Options{BindAddress: "0"}, HealthProbeBindAddress: "0"})
	require.NoError(t, err)
	reconciler := &operator.TTLReportReconciler{Logger: logr.Discard(), Config: etc.Config{Namespace: "test", VulnerabilityScannerEnabled: true}, Client: mgr.GetClient(), Clock: ext.NewSystemClock()}
	require.NoError(t, reconciler.SetupWithManager(mgr))
	ctx, cancel := context.WithCancel(context.Background())
	report := v1alpha1.VulnerabilityReport{ObjectMeta: metav1.ObjectMeta{Name: "cluster-partition", Annotations: map[string]string{v1alpha1.TTLReportAnnotation: "3s"}}}
	report.Report.UpdateTimestamp = metav1.Now()
	for i := 0; i < 16; i++ {
		report.Report.Vulnerabilities = append(report.Report.Vulnerabilities, v1alpha1.Vulnerability{VulnerabilityID: fmt.Sprintf("CVE-fixture-%d", i), Resource: "fixture", Severity: v1alpha1.SeverityHigh, Title: strings.Repeat("fixture ", 128)})
	}
	report.Report.Summary.HighCount = 16
	parts, err := vulnerabilityreport.PartitionReport(report, 4096)
	require.NoError(t, err)
	require.Greater(t, len(parts), 1)
	for _, part := range parts {
		obj := &v1alpha1.ClusterVulnerabilityReport{ObjectMeta: part.ObjectMeta, Report: part.Report}
		require.NoError(t, direct.Create(ctx, obj))
	}
	for _, name := range []string{"no-ttl", "unexpired"} {
		obj := &v1alpha1.ClusterVulnerabilityReport{ObjectMeta: metav1.ObjectMeta{Name: name}, Report: report.Report}
		if name == "unexpired" {
			obj.Annotations = map[string]string{v1alpha1.TTLReportAnnotation: "10m"}
		}
		require.NoError(t, direct.Create(ctx, obj))
	}
	var before v1alpha1.ClusterVulnerabilityReportList
	require.NoError(t, direct.List(ctx, &before))
	require.Len(t, before.Items, len(parts)+2)
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case e := <-done:
			require.NoError(t, e)
		case <-time.After(10 * time.Second):
			t.Error("manager failed to stop")
		}
	})
	require.True(t, mgr.GetCache().WaitForCacheSync(ctx))
	require.Eventually(t, func() bool {
		var list v1alpha1.ClusterVulnerabilityReportList
		if direct.List(ctx, &list) != nil {
			return false
		}
		return len(list.Items) == 2
	}, 20*time.Second, 200*time.Millisecond)
	for _, name := range []string{"no-ttl", "unexpired"} {
		require.NoError(t, direct.Get(ctx, client.ObjectKey{Name: name}, &v1alpha1.ClusterVulnerabilityReport{}))
	}
	t.Logf("Live cluster-scoped watch expired %d partition objects; no-TTL and unexpired reports survived", len(parts))
}
