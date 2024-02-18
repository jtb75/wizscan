// wizcli/scan.go

package wizcli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"time"
	"wizscan/pkg/logger"
)

type AggregatedScanResults struct {
	Libraries    []Library      `json:"libraries"`
	Applications []Applications `json:"applications"`
}

type ScanOutput struct {
	ID                 string             `json:"id"`
	CreatedAt          time.Time          `json:"createdAt"`
	ScanOriginResource ScanOriginResource `json:"scanOriginResource"`
	Result             Result             `json:"result"`
	ReportUrl          string             `json:"reportUrl"`
}

type ScanOriginResource struct {
	Typename string `json:"__typename"`
	Name     string `json:"name"`
}

type Result struct {
	OsPackages   interface{}    `json:"osPackages"`
	Libraries    []Library      `json:"libraries"`
	Applications []Applications `json:"applications"`
	Cpes         interface{}    `json:"cpes"`
}

type Library struct {
	Name            string          `json:"name"`
	Version         string          `json:"version"`
	Path            string          `json:"path"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	DetectionMethod string          `json:"detectionMethod"`
}

type Applications struct {
	Name            string                `json:"name"`
	Vulnerabilities []VulnerabilityDetail `json:"vulnerabilities"`
	DetectionMethod string                `json:"detectionMethod"`
}

type VulnerabilityDetail struct {
	Path          interface{}   `json:"path"`
	PathType      interface{}   `json:"pathType"`
	Version       string        `json:"version"`
	Vulnerability Vulnerability `json:"vulnerability"`
}

type Vulnerability struct {
	Name                      string      `json:"name"`
	Severity                  string      `json:"severity"`
	FixedVersion              string      `json:"fixedVersion"`
	Source                    string      `json:"source"`
	Description               interface{} `json:"description"`
	Score                     float64     `json:"score"`
	ExploitabilityScore       float64     `json:"exploitabilityScore"`
	CvssV3Metrics             interface{} `json:"cvssV3Metrics"`
	CvssV2Metrics             interface{} `json:"cvssV2Metrics"`
	HasExploit                bool        `json:"hasExploit"`
	HasCisaKevExploit         bool        `json:"hasCisaKevExploit"`
	CisaKevReleaseDate        interface{} `json:"cisaKevReleaseDate"`
	CisaKevDueDate            interface{} `json:"cisaKevDueDate"`
	EpssProbability           interface{} `json:"epssProbability"`
	EpssPercentile            interface{} `json:"epssPercentile"`
	EpssSeverity              interface{} `json:"epssSeverity"`
	PublishDate               interface{} `json:"publishDate"`
	FixPublishDate            interface{} `json:"fixPublishDate"`
	GracePeriodEnd            interface{} `json:"gracePeriodEnd"`
	GracePeriodRemainingHours interface{} `json:"gracePeriodRemainingHours"`
}

// ScanDirectory uses wizcli to scan the specified directory for vulnerabilities and parses the JSON output.
func ScanDirectory(wizcliPath, directoryPath string) (*ScanOutput, error) {

	// Get hostname to be used as scan name
	hostname, err := os.Hostname()
	if err != nil {
		logger.Log.Errorf("Error getting hostname: %v\n", err)
		return nil, fmt.Errorf("failed to get hostname - Output %s", err)
	}

	scanName := hostname + "-" + directoryPath

	// Construct the command to scan the directory, handling Windows and Unix-like systems appropriately.
	cmdStr := fmt.Sprintf("%s dir scan --path %s -f json --name %s", wizcliPath, directoryPath, scanName)
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", cmdStr)
	} else {
		cmd = exec.Command("sh", "-c", cmdStr)
	}

	// Execute the command and capture its combined output.
	logger.Log.Debugf("Initiating scan for directory: %s", directoryPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Handle the case where the command execution results in an error not related to parsing.
		errMsg := err.Error()
		if errMsg != "exit status 4" {
			return nil, fmt.Errorf("failed to scan directory %s: %v - Output: %s", directoryPath, err, string(output))
		}
	}

	// Attempt to extract the JSON portion from the mixed output.
	logger.Log.Debugf("Extracting JSON output from scan of directory: %s", directoryPath)
	jsonOutput, err := extractJSON(string(output))
	if err != nil {
		// Handle the case where JSON extraction fails.
		return nil, fmt.Errorf("failed to extract JSON from scan output: %v", err)
	}

	// Parse the extracted JSON output into the ScanOutput struct.
	logger.Log.Debugf("Unmarshalling JSON output from scan of directory: %s", directoryPath)
	var scanResult ScanOutput
	if err := json.Unmarshal([]byte(jsonOutput), &scanResult); err != nil {
		// Handle JSON parsing errors.
		return nil, fmt.Errorf("failed to parse scan output: %v", err)
	}

	// Log completion and return the parsed scan results.
	logger.Log.Debugf("Scan completed for directory: %s", directoryPath)
	return &scanResult, nil
}

// extractJSON tries to find and extract the JSON substring from the provided text.
func extractJSON(output string) (string, error) {
	// Use a regular expression to identify the JSON part of the output.
	// This regex assumes the JSON object starts with '{' and ends with '}'.
	re := regexp.MustCompile(`\{.*\}`)
	matches := re.FindStringSubmatch(output)
	if len(matches) == 0 {
		return "", fmt.Errorf("no JSON output found in command output")
	}

	return matches[0], nil
}
