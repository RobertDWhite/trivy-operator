package metrics

import (
	"strings"
	"testing"

	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/aquasecurity/trivy-operator/pkg/vulnerabilityreport"
	"github.com/go-logr/logr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestPartitionMetricsCountOnlyCompleteLogicalReports(t *testing.T) {
	r := v1alpha1.VulnerabilityReport{ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "test"}}
	for i := 0; i < 20; i++ {
		r.Report.Vulnerabilities = append(r.Report.Vulnerabilities, v1alpha1.Vulnerability{VulnerabilityID: "CVE-test", Severity: v1alpha1.SeverityHigh, Title: strings.Repeat("x", 1000)})
	}
	r.Report.Summary.HighCount = 20
	parts, err := vulnerabilityreport.PartitionReport(r, 4096)
	require.NoError(t, err)
	require.Greater(t, len(parts), 2)
	for _, partial := range []bool{false, true} {
		t.Run(map[bool]string{true: "missing_part", false: "complete"}[partial], func(t *testing.T) {
			objects := []client.Object{}
			for i := range parts {
				if partial && i == 0 {
					continue
				}
				objects = append(objects, parts[i].DeepCopy())
			}
			c := fake.NewClientBuilder().WithScheme(trivyoperator.NewScheme()).WithObjects(objects...).Build()
			registry := prometheus.NewPedanticRegistry()
			collector := NewResourcesMetricsCollector(logr.Discard(), etc.Config{}, trivyoperator.GetDefaultConfig(), c)
			require.NoError(t, registry.Register(collector))
			families, err := registry.Gather()
			require.NoError(t, err)
			var high, incomplete float64
			for _, f := range families {
				if f.GetName() == "trivy_vulnerability_report_incomplete_sets" {
					for _, m := range f.Metric {
						incomplete += m.GetGauge().GetValue()
					}
				}
				if f.GetName() == "trivy_image_vulnerabilities" {
					for _, m := range f.Metric {
						for _, l := range m.Label {
							if l.GetName() == "severity" && l.GetValue() == "High" {
								high += m.GetGauge().GetValue()
							}
						}
					}
				}
			}
			if partial {
				require.Equal(t, float64(1), incomplete)
				require.Zero(t, high)
			} else {
				require.Zero(t, incomplete)
				require.Equal(t, float64(20), high)
			}
		})
	}
}
