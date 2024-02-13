// wizcli/scan.go

package wizcli

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"time"
	"wizscan/pkg/logger"
)

type ScanOutput struct {
	ID                 string             `json:"id"`
	Projects           interface{}        `json:"projects"`
	CreatedAt          time.Time          `json:"createdAt"`
	StartedAt          time.Time          `json:"startedAt"`
	CreatedBy          CreatedBy          `json:"createdBy"`
	Status             Status             `json:"status"`
	Policies           []Policy           `json:"policies"`
	ExtraInfo          interface{}        `json:"extraInfo"`
	Tags               interface{}        `json:"tags"`
	OutdatedPolicies   []interface{}      `json:"outdatedPolicies"`
	TaggedResource     interface{}        `json:"taggedResource"`
	ScanOriginResource ScanOriginResource `json:"scanOriginResource"`
	Result             Result             `json:"result"`
	ReportUrl          string             `json:"reportUrl"`
}

type CreatedBy struct {
	ServiceAccount ServiceAccount `json:"serviceAccount"`
}

type ServiceAccount struct {
	ID string `json:"id"`
}

type Status struct {
	State   string `json:"state"`
	Verdict string `json:"verdict"`
}

type Policy struct {
	ID                          string                       `json:"id"`
	Name                        string                       `json:"name"`
	Description                 string                       `json:"description"`
	Type                        string                       `json:"type"`
	Builtin                     bool                         `json:"builtin"`
	Projects                    interface{}                  `json:"projects"`
	PolicyLifecycleEnforcements []PolicyLifecycleEnforcement `json:"policyLifecycleEnforcements"`
	IgnoreRules                 interface{}                  `json:"ignoreRules"`
	LifecycleTargets            interface{}                  `json:"lifecycleTargets"`
	Params                      Params                       `json:"params"`
}

type PolicyLifecycleEnforcement struct {
	EnforcementMethod   string `json:"enforcementMethod"`
	DeploymentLifecycle string `json:"deploymentLifecycle"`
}

type Params struct {
	Typename                string        `json:"__typename"`
	CountThreshold          int           `json:"countThreshold"`
	PathAllowList           []interface{} `json:"pathAllowList"`
	Severity                string        `json:"severity,omitempty"`
	PackageCountThreshold   int           `json:"packageCountThreshold,omitempty"`
	IgnoreUnfixed           bool          `json:"ignoreUnfixed,omitempty"`
	PackageAllowList        []interface{} `json:"packageAllowList,omitempty"`
	DetectionMethods        interface{}   `json:"detectionMethods,omitempty"`
	FixGracePeriodHours     int           `json:"fixGracePeriodHours,omitempty"`
	PublishGracePeriodHours int           `json:"publishGracePeriodHours,omitempty"`
}

type ScanOriginResource struct {
	Typename string `json:"__typename"`
	Name     string `json:"name"`
}

type Result struct {
	Typename            string              `json:"__typename"`
	OsPackages          interface{}         `json:"osPackages"`
	Libraries           []Library           `json:"libraries"`
	Applications        interface{}         `json:"applications"`
	Cpes                interface{}         `json:"cpes"`
	Secrets             []Secret            `json:"secrets"`
	DataFindings        interface{}         `json:"dataFindings"`
	FailedPolicyMatches []FailedPolicyMatch `json:"failedPolicyMatches"`
	Analytics           Analytics           `json:"analytics"`
}

type Library struct {
	Name                string          `json:"name"`
	Version             string          `json:"version"`
	Path                string          `json:"path"`
	Vulnerabilities     []Vulnerability `json:"vulnerabilities"`
	DetectionMethod     string          `json:"detectionMethod"`
	LayerMetadata       interface{}     `json:"layerMetadata"`
	FailedPolicyMatches []interface{}   `json:"failedPolicyMatches"`
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

type Secret struct {
	Description         string              `json:"description"`
	Path                string              `json:"path"`
	LineNumber          int                 `json:"lineNumber"`
	Offset              int                 `json:"offset"`
	Type                string              `json:"type"`
	Contains            []Contains          `json:"contains"`
	Snippet             interface{}         `json:"snippet"`
	ExternalId          interface{}         `json:"externalId"`
	FailedPolicyMatches []FailedPolicyMatch `json:"failedPolicyMatches"`
	Details             Details             `json:"details"`
}

type Contains struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type FailedPolicyMatch struct {
	Policy Policy `json:"policy"`
}

type Details struct {
	Typename  string `json:"__typename"`
	Length    int    `json:"length"`
	IsComplex bool   `json:"isComplex"`
}

type Analytics struct {
	Vulnerabilities         Vulnerabilities `json:"vulnerabilities"`
	Secrets                 Secrets         `json:"secrets"`
	FilesScannedCount       int             `json:"filesScannedCount"`
	DirectoriesScannedCount int             `json:"directoriesScannedCount"`
}

type Vulnerabilities struct {
	InfoCount     int `json:"infoCount"`
	LowCount      int `json:"lowCount"`
	MediumCount   int `json:"mediumCount"`
	HighCount     int `json:"highCount"`
	CriticalCount int `json:"criticalCount"`
	UnfixedCount  int `json:"unfixedCount"`
	TotalCount    int `json:"totalCount"`
}

type Secrets struct {
	CloudKeyCount           int `json:"cloudKeyCount"`
	GitCredentialCount      int `json:"gitCredentialCount"`
	DbConnectionStringCount int `json:"dbConnectionStringCount"`
	PrivateKeyCount         int `json:"privateKeyCount"`
	PasswordCount           int `json:"passwordCount"`
	SaasAPIKeyCount         int `json:"saasAPIKeyCount"`
	TotalCount              int `json:"totalCount"`
}

// ScanDirectory uses wizcli to scan the specified directory for vulnerabilities and parses the JSON output.
func ScanDirectory(wizcliPath, directoryPath string) (*ScanOutput, error) {
	// Ensure the wizcliPath is correctly quoted to handle spaces.
	quotedWizcliPath := "\"" + wizcliPath + "\""
	quotedDirectoryPath := "\"" + directoryPath + "\""

	// Construct the command to scan the directory, handling Windows and Unix-like systems appropriately.
	cmdStr := fmt.Sprintf("%s dir scan --path %s -f json", quotedWizcliPath, quotedDirectoryPath)
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", cmdStr)
	} else {
		cmd = exec.Command("sh", "-c", cmdStr)
	}

	// Execute the command and capture its combined output.
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Handle the case where the command execution results in an error not related to parsing.
		return nil, fmt.Errorf("failed to scan directory %s: %v - Output: %s", directoryPath, err, string(output))
	}

	// Attempt to extract the JSON portion from the mixed output.
	jsonOutput, err := extractJSON(string(output))
	if err != nil {
		// Handle the case where JSON extraction fails.
		return nil, fmt.Errorf("failed to extract JSON from scan output: %v", err)
	}

	// Parse the extracted JSON output into the ScanOutput struct.
	var scanResult ScanOutput
	if err := json.Unmarshal([]byte(jsonOutput), &scanResult); err != nil {
		// Handle JSON parsing errors.
		return nil, fmt.Errorf("failed to parse scan output: %v", err)
	}

	// Log completion and return the parsed scan results.
	logger.Log.Infof("Scan completed for directory: %s", directoryPath)
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
