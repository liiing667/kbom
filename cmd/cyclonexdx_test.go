package cmd

import (
	"slices"
	"testing"
	"time"

	cyclonedx "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"

	"github.com/rad-security/kbom/internal/model"
)

func sampleKBOM() *model.KBOM {
	generatedAt := time.Date(2026, 11, 12, 10, 30, 0, 0, time.UTC)
	img := model.Image{
		FullName: "registry.k8s.io/coredns/coredns:v1.12.0",
		Name:     "registry.k8s.io/coredns/coredns",
		Version:  "v1.12.0",
		Digest:   "sha256:aaaa",
	}

	return &model.KBOM{
		ID:          "kbom-id",
		GeneratedAt: generatedAt,
		GeneratedBy: model.Tool{Vendor: "RAD Security", Name: "kbom", Version: "0.1.0"},
		Cluster: model.Cluster{
			Name:       "test-cluster",
			K8sVersion: "1.35.8",
			NodesCount: 1,
			Nodes: []model.Node{
				{
					Name:     "node-a",
					Hostname: "node-a",
					Capacity: &model.Capacity{
						CPU:              "2",
						Memory:           "8Gi",
						Pods:             "11",
						EphemeralStorage: "100Gi",
					},
					Allocatable: &model.Capacity{
						CPU:              "1930m",
						Memory:           "6Gi",
						Pods:             "11",
						EphemeralStorage: "90Gi",
					},
				},
			},
			Components: model.Components{
				Images: []model.Image{img},
				Addons: []model.Addon{{
					Name:     "coredns",
					Category: "dns",
					Version:  "v1.12.0",
					Images:   []string{img.FullName},
				}},
				Resources: map[string]model.ResourceList{
					"clusterroles": {
						Kind:       "ClusterRole",
						APIVersion: "rbac.authorization.k8s.io/v1",
						Resources:  []model.Resource{{Name: "admin"}},
					},
					"namespaces": {
						Kind:       "Namespace",
						APIVersion: "v1",
						Resources:  []model.Resource{{Name: "kube-system"}},
					},
				},
			},
		},
	}
}

func TestTransformToCycloneDXDeterministic(t *testing.T) {
	kbom := sampleKBOM()

	first := transformToCycloneDXBOM(kbom)
	second := transformToCycloneDXBOM(kbom)

	assert.Equal(t, "2026-11-12T10:30:00Z", first.Metadata.Timestamp)
	assert.Equal(t, first.Metadata.Timestamp, second.Metadata.Timestamp)
	assert.NotEmpty(t, first.SerialNumber)
	assert.Equal(t, first.SerialNumber, second.SerialNumber)

	assert.Equal(t, *first.Components, *second.Components)
	assert.Equal(t, *first.Dependencies, *second.Dependencies)

	componentRefs := make([]string, 0, len(*first.Components))
	for _, c := range *first.Components {
		componentRefs = append(componentRefs, c.BOMRef)
	}
	assert.True(t, slices.IsSorted(componentRefs), "components must be sorted by BOMRef: %v", componentRefs)

	depRefs := make([]string, 0, len(*first.Dependencies))
	for _, d := range *first.Dependencies {
		depRefs = append(depRefs, d.Ref)
		for _, ref := range *d.Dependencies {
			assert.Contains(t, componentRefs, ref, "dependency %q references unknown component", ref)
		}
		assert.True(t, slices.IsSorted(*d.Dependencies), "dependency refs of %q must be sorted: %v", d.Ref, *d.Dependencies)
	}
	assert.True(t, slices.IsSorted(depRefs), "dependencies must be sorted by ref: %v", depRefs)
}

func TestTransformToCycloneDXSerialChangesWithContent(t *testing.T) {
	first := transformToCycloneDXBOM(sampleKBOM())

	changed := sampleKBOM()
	changed.Cluster.Components.Resources["configmaps"] = model.ResourceList{
		Kind:       "ConfigMap",
		APIVersion: "v1",
		Resources:  []model.Resource{{Name: "new-config", Namespace: "default"}},
	}
	second := transformToCycloneDXBOM(changed)

	assert.NotEqual(t, first.SerialNumber, second.SerialNumber)

	timestampChanged := sampleKBOM()
	timestampChanged.GeneratedAt = timestampChanged.GeneratedAt.Add(time.Hour)
	third := transformToCycloneDXBOM(timestampChanged)
	assert.NotEqual(t, first.SerialNumber, third.SerialNumber)
	assert.Equal(t, "2026-11-12T11:30:00Z", third.Metadata.Timestamp)
}

func TestTransformToCycloneDXNilNodeCapacity(t *testing.T) {
	kbom := sampleKBOM()
	kbom.Cluster.Nodes[0].Capacity = nil
	kbom.Cluster.Nodes[0].Allocatable = nil

	var bom *cyclonedx.BOM
	assert.NotPanics(t, func() {
		bom = transformToCycloneDXBOM(kbom)
	})

	for _, c := range *bom.Components {
		if c.Type != cyclonedx.ComponentTypePlatform || c.Name != "node-a" {
			continue
		}

		for _, p := range *c.Properties {
			assert.NotContains(t, p.Name, "capacity")
			assert.NotContains(t, p.Name, "allocatable")
		}
	}
}

func TestTransformToCycloneDXWithoutLocation(t *testing.T) {
	kbom := &model.KBOM{Cluster: model.Cluster{Name: "test-cluster", K8sVersion: "1.35.8"}}

	assert.NotPanics(t, func() {
		bom := transformToCycloneDXBOM(kbom)
		assert.NotNil(t, bom.Metadata.Component)
	})
}

func TestTransformToCycloneDXUniqueResourceRefs(t *testing.T) {
	kbom := &model.KBOM{Cluster: model.Cluster{
		Name:       "test-cluster",
		K8sVersion: "1.35.8",
		Components: model.Components{Resources: map[string]model.ResourceList{
			"clusterroles": {
				Kind:       "ClusterRole",
				APIVersion: "rbac.authorization.k8s.io/v1",
				Resources:  []model.Resource{{Name: "admin"}},
			},
			"clusterrolebindings": {
				Kind:       "ClusterRoleBinding",
				APIVersion: "rbac.authorization.k8s.io/v1",
				Resources:  []model.Resource{{Name: "admin"}},
			},
		}},
	}}

	bom := transformToCycloneDXBOM(kbom)

	refs := map[string]bool{}
	for _, c := range *bom.Components {
		assert.False(t, refs[c.BOMRef], "duplicate bom-ref %s for %s", c.BOMRef, c.Name)
		refs[c.BOMRef] = true
	}
	assert.Len(t, refs, 2)
}

func TestTransformToCycloneDXAddons(t *testing.T) {
	img := model.Image{
		FullName: "registry.k8s.io/coredns/coredns:v1.12.0",
		Name:     "registry.k8s.io/coredns/coredns",
		Version:  "v1.12.0",
	}
	kbom := &model.KBOM{Cluster: model.Cluster{
		Name:       "test-cluster",
		K8sVersion: "1.35.8",
		Components: model.Components{
			Images: []model.Image{img},
			Addons: []model.Addon{{
				Name:     "coredns",
				Category: "dns",
				Version:  "v1.12.0",
				CPE:      "cpe:2.3:a:coredns.io:coredns:1.12.0:*:*:*:*:*:*:*",
				Images:   []string{img.FullName},
			}},
		},
	}}

	bom := transformToCycloneDXBOM(kbom)

	assert.Equal(t, "cpe:2.3:a:kubernetes:kubernetes:1.35.8:*:*:*:*:*:*:*", bom.Metadata.Component.CPE)
	assert.Equal(t, "pkg:golang/k8s.io/kubernetes@v1.35.8", bom.Metadata.Component.PackageURL)

	var addonRef string
	for _, c := range *bom.Components {
		if c.Name == "coredns" {
			addonRef = c.BOMRef
			assert.Equal(t, "v1.12.0", c.Version)
			assert.Equal(t, "cpe:2.3:a:coredns.io:coredns:1.12.0:*:*:*:*:*:*:*", c.CPE)
			assert.Contains(t, *c.Properties, cyclonedx.Property{Name: "rad:kbom:k8s:addon:category", Value: "dns"})
		}
	}
	assert.NotEmpty(t, addonRef, "addon component is missing")

	deps := map[string][]string{}
	for _, d := range *bom.Dependencies {
		deps[d.Ref] = *d.Dependencies
	}
	assert.Equal(t, []string{img.PkgID()}, deps[addonRef])
	assert.Contains(t, deps[kbom.Cluster.BOMRef()], addonRef)
}
