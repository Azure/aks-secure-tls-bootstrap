package consts

const (
	// SystemNodeSubjectNamePrefix is expected to always prefix the subject name of valid kubelet client certificates.
	SystemNodeSubjectNamePrefix = "system:node:"

	// SystemNodesSubjectOrganizationName is the expected subject organization name of valid kubelet client certificates.
	// This organization name corresponds to the "system:nodes" k8s RBAC group which gives the kubelet the permissions
	// it needs to function as a k8s node.
	SystemNodesSubjectOrganizationName = "system:nodes"
)
