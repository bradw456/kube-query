package tables

import (
	"context"
	"log"

	// "github.com/aquasecurity/kube-query/utils"
	"github.com/kolide/osquery-go/plugin/table"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	metrics "k8s.io/metrics/pkg/client/clientset/versioned"
)

// PersistentVolumeClaimsTable implements the Table interface,
// Uses kubeclient to extract information about pods
type PersistentVolumeClaimsTable struct {
	columns       []table.ColumnDefinition
	name          string
	client        kubernetes.Interface
	metricsClient metrics.Interface
}

// NewPersistentVolumesClaimsTable creates a new PersistentVolumesClaimsTable
// saves given initialized kubernetes client
func NewPersistentVolumeClaimsTable(kubeclient kubernetes.Interface) *PersistentVolumeClaimsTable {
	columns := []table.ColumnDefinition{
		table.TextColumn("name"),
		table.TextColumn("status"),
		table.TextColumn("storageclass_name"),
		table.TextColumn("capacity"),
		table.TextColumn("requested"),
		table.TextColumn("volumename"),
		table.TextColumn("volumemode"),
	}
	return &PersistentVolumeClaimsTable{
		name:    "kubernetes_persistentvolumeclaims",
		columns: columns,
		client:  kubeclient,
	}
}

// Name Returns name of table
func (t *PersistentVolumeClaimsTable) Name() string {
	return t.name
}

// Columns Retrieves the initialized columns
func (t *PersistentVolumeClaimsTable) Columns() []table.ColumnDefinition {
	return t.columns
}

// Generate uses the api to retrieve information on all pods
func (t *PersistentVolumeClaimsTable) Generate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {

	pvcs, err := t.client.CoreV1().PersistentVolumeClaims(metav1.NamespaceAll).List(metav1.ListOptions{})
	if err != nil {
		log.Println("could not list pvcs from k8s api")
		return nil, err
	}

	rows := make([]map[string]string, len(pvcs.Items))

	for i, pvc := range pvcs.Items {
		currRow := map[string]string{
			"name":       pvc.ObjectMeta.Name,
			"status":     string(pvc.Status.Phase),
			"volumename": pvc.Spec.VolumeName,
		}
		if pvc.Spec.VolumeMode != nil {
			currRow["volumemode"] = string(*pvc.Spec.VolumeMode)
		}

		if pvc.Spec.StorageClassName != nil {
			currRow["storageclass_name"] = string(*pvc.Spec.StorageClassName)
		}

		if _, ok := pvc.Status.Capacity["storage"]; ok {
			quantity := pvc.Status.Capacity["storage"]
			currRow["capacity"] = (&quantity).String()
		}

		if _, ok := pvc.Spec.Resources.Requests["storage"]; ok {
			quantity := pvc.Spec.Resources.Requests["storage"]
			currRow["requested"] = (&quantity).String()
		}

		rows[i] = currRow
	}

	return rows, nil
}
