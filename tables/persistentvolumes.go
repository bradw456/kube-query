package tables

import (
	"context"
	"encoding/json"
	"log"

	// "github.com/aquasecurity/kube-query/utils"
	"github.com/kolide/osquery-go/plugin/table"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	metrics "k8s.io/metrics/pkg/client/clientset/versioned"
)

// PersistentVolumesTable implements the Table interface,
// Uses kubeclient to extract information about pods
type PersistentVolumesTable struct {
	columns       []table.ColumnDefinition
	name          string
	client        kubernetes.Interface
	metricsClient metrics.Interface
}

// NewPersistentVolumesTable creates a new PersistentVolumesTable
// saves given initialized kubernetes client
func NewPersistentVolumesTable(kubeclient kubernetes.Interface) *PersistentVolumesTable {
	columns := []table.ColumnDefinition{
		table.TextColumn("name"),
		table.TextColumn("status"),
		table.TextColumn("capacity"),
		table.TextColumn("path"),
		table.TextColumn("storageclass_name"),
		table.TextColumn("nodeaffinity"),
	}
	return &PersistentVolumesTable{
		name:    "kubernetes_persistentvolumes",
		columns: columns,
		client:  kubeclient,
	}
}

// Name Returns name of table
func (t *PersistentVolumesTable) Name() string {
	return t.name
}

// Columns Retrieves the initialized columns
func (t *PersistentVolumesTable) Columns() []table.ColumnDefinition {
	return t.columns
}

// getNodeAffinity as a json string
func (t *PersistentVolumesTable) getNodeAffinity(nodeaffinity *corev1.VolumeNodeAffinity) string {
	var source string
	// Because the NodeAffinity struct contains alot of optional fields,
	// We use the marshal unmarshal to filter the zero values, and get the
	// json name representation of the only non zero type in the struct
	if bytes, err := json.Marshal(*nodeaffinity); err == nil {
		source = string(bytes)
	}
	return source
}

// Generate uses the api to retrieve information on all pods
func (t *PersistentVolumesTable) Generate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	pvs, err := t.client.CoreV1().PersistentVolumes().List(metav1.ListOptions{})
	if err != nil {
		log.Println("could not list pvs from k8s api")
		return nil, err
	}

	rows := make([]map[string]string, len(pvs.Items))
	for i, pv := range pvs.Items {
		currRow := map[string]string{
			"name":              pv.ObjectMeta.Name,
			"status":            string(pv.Status.Phase),
			"storageclass_name": pv.Spec.StorageClassName,
		}

		if _, ok := pv.Spec.Capacity["storage"]; ok {
			quantity := pv.Spec.Capacity["storage"]
			currRow["capacity"] = (&quantity).String()
		}

		if pv.Spec.Local != nil {
			currRow["path"] = pv.Spec.Local.Path
		}

		// if the volume source is not with zero value
		if pv.Spec.NodeAffinity != nil {
			currRow["nodeaffinity"] = t.getNodeAffinity(pv.Spec.NodeAffinity)
		}

		//pv.Spec.NodeAffinity.Required.NodeSelectorTerms[0].MatchExpressions[0].Values[0],

		rows[i] = currRow
	}
	return rows, nil
}
