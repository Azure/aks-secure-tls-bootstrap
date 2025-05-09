package imds

// ComputeData encapsulates the compute-related fields we need from VM instance data.
type ComputeData struct {
	ResourceID string `json:"resourceId,omitempty"`
}

// VMInstanceData encapsulates the fields we need within VM instance data retrieved from IMDS.
type VMInstanceData struct {
	Compute ComputeData `json:"compute,omitempty"`
}

// VMAttestedData encapsulates the fields we need within VM attested data retrieved from IMDS.
type VMAttestedData struct {
	Signature string `json:"signature,omitempty"`
}
