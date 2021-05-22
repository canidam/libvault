package libvault

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
)

/* parseJson extract json content from http.Response to a struct */
func parseJson(resp io.Reader, responseStruct interface{}) error {
	bytesData, err := ioutil.ReadAll(resp)
	if err != nil {
		return err
	}

	return json.Unmarshal(bytesData, responseStruct)
}

/* getEnv returns value from the environment, or fallback if it isn't set */
func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	} else {
		return fallback
	}
}

/* vaultErrorMsg extracts the body content of a vault error */
func vaultErrorMsg(resp io.ReadCloser) interface{} {
	var respData map[string]interface{}
	_ = parseJson(resp, &respData)
	if val, ok := respData["errors"]; ok {
		return val
	}
	return respData
}
