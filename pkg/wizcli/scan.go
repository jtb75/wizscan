// wizcli/scan.go

package wizcli

import (
	"encoding/json"
	"os/exec"
	"wizscan/pkg/logger"
)

// ScanResult represents the structure of the vulnerability scan result.
// Adjust the fields according to the actual JSON output of wizcli.
type ScanResult struct {
	// Example fields; adjust based on actual output
	Vulnerabilities []struct {
		ID          string `json:"id"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
	} `json:"vulnerabilities"`
}

// ScanDirectory invokes the wizcli tool to scan the specified directory for vulnerabilities.
func ScanDirectory(wizcliPath, mountedPath string) (*ScanResult, error) {
	cmd := exec.Command(wizcliPath, "dir", "scan", "--path", mountedPath, "-f", "json")
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Log.Errorf("Failed to scan directory %s: %v", mountedPath, err)
		return nil, err
	}

	var result ScanResult
	if err := json.Unmarshal(output, &result); err != nil {
		logger.Log.Errorf("Failed to parse scan result for directory %s: %v", mountedPath, err)
		return nil, err
	}

	return &result, nil
}
