package libvault

// Secret is the interface to fetch secrets from the secrets engine used
type Secret interface {
	Secrets() map[string]string
}

type kvSecretResp struct {
	ResponseData struct {
		Data     map[string]string `json:"data"`
		Metadata struct {
			CreatedTime  string `json:"created_time"`
			DeletionTime string `json:"deleted_time"`
			Destroyed    bool   `json:"destroyed"`
			Version      int    `json:"version"`
		} `json:"metadata"`
	} `json:"data"`
	RequestID string `json:"request_id"`
}

func (vr kvSecretResp) Secrets() map[string]string {
	return vr.ResponseData.Data
}

func (vr kvSecretResp) Version() int {
	return vr.ResponseData.Metadata.Version
}
