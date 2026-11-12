package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"slices"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/mitchellh/hashstructure/v2"

	"github.com/rad-security/kbom/internal/addons"
	"github.com/rad-security/kbom/internal/model"
)

const (
	CdxPrefix           = "cdx:"
	RADPrefix           = "rad:kbom:"
	K8sComponentType    = "k8s:component:type"
	K8sComponentName    = "k8s:component:name"
	K8sComponentVersion = "k8s:component:version"

	ClusterType   = "cluster"
	NodeType      = "node"
	ContainerType = "container"
)

// cdxNamespace is a fixed UUIDv5 namespace used to derive deterministic BOM
// serial numbers from the BOM content. Its value is arbitrary but stable.
var cdxNamespace = uuid.Must(uuid.FromBytes([]byte{
	0x6b, 0x62, 0x6f, 0x6d, 0x2d, 0x63, 0x79, 0x63,
	0x6c, 0x6f, 0x6e, 0x65, 0x64, 0x78, 0x2d, 0x31,
}))

func locationProperties(loc *model.Location) []cyclonedx.Property {
	if loc == nil {
		return nil
	}

	var properties []cyclonedx.Property
	if loc.Name != "" && loc.Name != "unknown" {
		properties = append(properties, cyclonedx.Property{
			Name:  RADPrefix + "k8s:cluster:location:name",
			Value: loc.Name,
		})
	}

	if loc.Region != "" {
		properties = append(properties, cyclonedx.Property{
			Name:  RADPrefix + "k8s:cluster:location:region",
			Value: loc.Region,
		})
	}

	if loc.Zone != "" {
		properties = append(properties, cyclonedx.Property{
			Name:  RADPrefix + "k8s:cluster:location:zone",
			Value: loc.Zone,
		})
	}

	return properties
}

// deterministicTimestamp returns the BOM timestamp derived from the original
// KBOM generation time, so repeated exports of the same snapshot are identical.
func deterministicTimestamp(kbom *model.KBOM) string {
	if !kbom.GeneratedAt.IsZero() {
		return kbom.GeneratedAt.UTC().Format(time.RFC3339)
	}

	return time.Now().UTC().Format(time.RFC3339)
}

// deterministicSerialNumber derives a stable UUIDv5 URN from the encoded BOM
// content. Any change to the BOM (components, dependencies, metadata) changes
// the serial number, while identical content always yields the same serial.
func deterministicSerialNumber(bom *cyclonedx.BOM) string {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(bom); err != nil {
		return uuid.Nil.URN()
	}

	return uuid.NewSHA1(cdxNamespace, buf.Bytes()).URN()
}

// nodeCapacityProperties appends capacity/allocatable properties only when the
// corresponding data is present. Older KBOM snapshots may have nil capacity,
// which must not break the conversion.
func nodeCapacityProperties(properties []cyclonedx.Property, prefix string, capacity *model.Capacity) []cyclonedx.Property {
	if capacity == nil {
		return properties
	}

	return append(properties,
		cyclonedx.Property{
			Name:  RADPrefix + "k8s:node:" + prefix + ":cpu",
			Value: capacity.CPU,
		},
		cyclonedx.Property{
			Name:  RADPrefix + "k8s:node:" + prefix + ":memory",
			Value: capacity.Memory,
		},
		cyclonedx.Property{
			Name:  RADPrefix + "k8s:node:" + prefix + ":pods",
			Value: capacity.Pods,
		},
		cyclonedx.Property{
			Name:  RADPrefix + "k8s:node:" + prefix + ":ephemeralStorage",
			Value: capacity.EphemeralStorage,
		},
	)
}

func lessComponent(a, b cyclonedx.Component) int {
	switch {
	case a.BOMRef < b.BOMRef:
		return -1
	case a.BOMRef > b.BOMRef:
		return 1
	case a.Type < b.Type:
		return -1
	case a.Type > b.Type:
		return 1
	case a.Name < b.Name:
		return -1
	case a.Name > b.Name:
		return 1
	default:
		return 0
	}
}

func transformToCycloneDXBOM(kbom *model.KBOM) *cyclonedx.BOM { //nolint:funlen
	cdxBOM := cyclonedx.NewBOM()

	cdxBOM.Metadata = &cyclonedx.Metadata{
		Timestamp: deterministicTimestamp(kbom),
		Tools: &cyclonedx.ToolsChoice{
			Components: &[]cyclonedx.Component{
				{
					Type:     cyclonedx.ComponentTypeApplication,
					Supplier: &cyclonedx.OrganizationalEntity{Name: kbom.GeneratedBy.Vendor},
					Name:     kbom.GeneratedBy.Name,
					Version:  kbom.GeneratedBy.Version,
				},
			},
		},
	}

	components := []cyclonedx.Component{}
	dependencies := []cyclonedx.Dependency{}
	clusterProperties := []cyclonedx.Property{
		{
			Name:  CdxPrefix + K8sComponentType,
			Value: ClusterType,
		},
		{
			Name:  CdxPrefix + "k8s:component:name",
			Value: kbom.Cluster.Name,
		},
		{
			Name:  RADPrefix + "k8s:cluster:nodes",
			Value: fmt.Sprintf("%d", kbom.Cluster.NodesCount),
		},
	}

	if kbom.Cluster.ID != "" {
		clusterProperties = append(clusterProperties, cyclonedx.Property{
			Name:  RADPrefix + "k8s:cluster:id",
			Value: kbom.Cluster.ID,
		})
	}

	clusterProperties = append(clusterProperties, locationProperties(kbom.Cluster.Location)...)

	clusterComponent := cyclonedx.Component{
		BOMRef:     kbom.Cluster.BOMRef(),
		Type:       cyclonedx.ComponentTypePlatform,
		Name:       kbom.Cluster.BOMName(),
		Version:    kbom.Cluster.K8sVersion,
		CPE:        addons.CPE(addons.KubernetesCPEProduct, kbom.Cluster.K8sVersion),
		PackageURL: kbom.Cluster.PackageURL(),
		Properties: &clusterProperties,
	}
	cdxBOM.Metadata.Component = &clusterComponent

	clusterDependencies := make(map[string]string)
	for i := range kbom.Cluster.Nodes {
		n := kbom.Cluster.Nodes[i]
		bomRef := id(n)
		nodeProperties := []cyclonedx.Property{
			{
				Name:  CdxPrefix + K8sComponentType,
				Value: NodeType,
			},
			{
				Name:  CdxPrefix + K8sComponentName,
				Value: n.Name,
			},
			{
				Name:  RADPrefix + "k8s:node:osImage",
				Value: n.OsImage,
			},
			{
				Name:  RADPrefix + "k8s:node:arch",
				Value: n.Architecture,
			},
			{
				Name:  RADPrefix + "k8s:node:kernel",
				Value: n.KernelVersion,
			},
			{
				Name:  RADPrefix + "k8s:node:bootId",
				Value: n.BootID,
			},
			{
				Name:  RADPrefix + "k8s:node:type",
				Value: n.Type,
			},
			{
				Name:  RADPrefix + "k8s:node:operatingSystem",
				Value: n.OperatingSystem,
			},
			{
				Name:  RADPrefix + "k8s:node:machineId",
				Value: n.MachineID,
			},
			{
				Name:  RADPrefix + "k8s:node:hostname",
				Value: n.Hostname,
			},
			{
				Name:  RADPrefix + "k8s:node:containerRuntimeVersion",
				Value: n.ContainerRuntimeVersion,
			},
			{
				Name:  RADPrefix + "k8s:node:kubeletVersion",
				Value: n.KubeletVersion,
			},
			{
				Name:  RADPrefix + "k8s:node:kubeProxyVersion",
				Value: n.KubeProxyVersion,
			},
		}
		nodeProperties = nodeCapacityProperties(nodeProperties, "capacity", n.Capacity)
		nodeProperties = nodeCapacityProperties(nodeProperties, "allocatable", n.Allocatable)

		components = append(components, cyclonedx.Component{
			BOMRef:     bomRef,
			Type:       cyclonedx.ComponentTypePlatform,
			Name:       n.Name,
			Properties: &nodeProperties,
		})
		clusterDependencies[bomRef] = bomRef
	}

	imageRefs := make(map[string]string, len(kbom.Cluster.Components.Images))
	for _, img := range kbom.Cluster.Components.Images {
		bomRef := img.PkgID()
		container := cyclonedx.Component{
			BOMRef:     bomRef,
			Type:       cyclonedx.ComponentTypeContainer,
			Name:       img.Name,
			Version:    img.Digest,
			PackageURL: bomRef,
			Properties: &[]cyclonedx.Property{
				{
					Name:  CdxPrefix + K8sComponentType,
					Value: ContainerType,
				},
				{
					Name:  CdxPrefix + K8sComponentName,
					Value: img.Name,
				},
				{
					Name:  RADPrefix + "pkg:type",
					Value: "oci",
				},
				{
					Name:  RADPrefix + "pkg:name",
					Value: img.Name,
				},
				{
					Name:  RADPrefix + "pkg:version",
					Value: img.Version,
				},
				{
					Name:  RADPrefix + "pkg:digest",
					Value: img.Digest,
				},
			},
		}

		components = append(components, container)
		imageRefs[img.FullName] = bomRef

		if img.ControlPlane {
			clusterDependencies[bomRef] = bomRef
		}
	}

	for _, addon := range kbom.Cluster.Components.Addons {
		bomRef := id(addon)
		components = append(components, cyclonedx.Component{
			BOMRef:  bomRef,
			Type:    cyclonedx.ComponentTypeApplication,
			Name:    addon.Name,
			Version: addon.Version,
			CPE:     addon.CPE,
			Properties: &[]cyclonedx.Property{
				{
					Name:  RADPrefix + "k8s:addon:category",
					Value: addon.Category,
				},
			},
		})
		clusterDependencies[bomRef] = bomRef

		addonImages := make([]string, 0, len(addon.Images))
		for _, img := range addon.Images {
			if ref, ok := imageRefs[img]; ok {
				addonImages = append(addonImages, ref)
			}
		}
		slices.Sort(addonImages)
		if len(addonImages) > 0 {
			dependencies = append(dependencies, cyclonedx.Dependency{
				Ref:          bomRef,
				Dependencies: &addonImages,
			})
		}
	}

	for _, resList := range kbom.Cluster.Components.Resources {
		for _, res := range resList.Resources {
			properties := []cyclonedx.Property{
				{
					Name:  CdxPrefix + K8sComponentType,
					Value: resList.Kind,
				},
				{
					Name:  CdxPrefix + K8sComponentName,
					Value: res.Name,
				},
				{
					Name:  RADPrefix + "k8s:component:apiVersion",
					Value: resList.APIVersion,
				},
			}

			if version, ok := res.AdditionalProperties["version"]; ok {
				properties = append(properties, cyclonedx.Property{
					Name:  RADPrefix + K8sComponentVersion,
					Value: version,
				})
			}

			if resList.Namespaced {
				properties = append(properties, cyclonedx.Property{
					Name:  RADPrefix + "k8s:component:namespace",
					Value: res.Namespace,
				})
			}

			// resource items don't carry kind and API version, include them so
			// objects with the same name in different kinds get unique refs
			ref := id(model.Resource{
				Kind:       resList.Kind,
				APIVersion: resList.APIVersion,
				Name:       res.Name,
				Namespace:  res.Namespace,
			})

			resource := cyclonedx.Component{
				BOMRef:     ref,
				Type:       cyclonedx.ComponentTypeApplication, // TODO: this is not perfect but we don't have a better option
				Name:       res.Name,
				Version:    res.APIVersion,
				Properties: &properties,
			}

			components = append(components, resource)
		}
	}

	slices.SortFunc(components, func(a, b cyclonedx.Component) int {
		return lessComponent(a, b)
	})

	clusterDependenciesArr := make([]string, 0)
	for _, dep := range clusterDependencies {
		clusterDependenciesArr = append(clusterDependenciesArr, dep)
	}
	slices.Sort(clusterDependenciesArr)

	dependencies = append(dependencies,
		cyclonedx.Dependency{
			Ref:          clusterComponent.BOMRef,
			Dependencies: &clusterDependenciesArr,
		},
	)
	slices.SortFunc(dependencies, func(a, b cyclonedx.Dependency) int {
		return strings.Compare(a.Ref, b.Ref)
	})

	cdxBOM.Components = &components
	cdxBOM.Dependencies = &dependencies
	cdxBOM.SerialNumber = deterministicSerialNumber(cdxBOM)

	return cdxBOM
}

func id(obj interface{}) string {
	f, err := hashstructure.Hash(obj, hashstructure.FormatV2, &hashstructure.HashOptions{
		ZeroNil:      true,
		SlicesAsSets: true,
		Hasher:       fnv.New64(),
	})

	// this should never happen, but if it does, we don't want to crash - use empty string
	if err != nil {
		fmt.Printf("failed to hash object: %v", err)
		return ""
	}

	return fmt.Sprintf("%016x", f)
}
