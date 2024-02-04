package wizcli

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"wizscan/pkg/logger" // Ensure you import your logger package
)

func ScanDirectories(directories []string, wizCliPath string) ([]string, error) {
	var jsonOutputs []string

	hostname, err := os.Hostname()
	if err != nil {
		logger.Log.Errorf("Error getting hostname: %v", err)
		return nil, err
	}

	for _, dir := range directories {
		logger.Log.Infof("Scanning directory %s", dir)
		scanName := fmt.Sprintf("%s:%s", hostname, dir)

		cmdStr := fmt.Sprintf("%s dir scan --path %s -f json --name %s", wizCliPath, dir, scanName)
		cmd := exec.Command("sh", "-c", cmdStr)
		output, err := cmd.CombinedOutput()
		if err != nil {
			errMsg := err.Error()
			if errMsg == "exit status 4" {
				err = nil
			} else {
				logger.Log.Errorf("Error scanning directory %s: %v", dir, err)
				return nil, err
			}
		}

		jsonOutput, err := extractJSON(string(output))
		if err != nil {
			logger.Log.Errorf("Error parsing scan results for directory %s: %v", dir, err)
			continue
		}

		jsonOutputs = append(jsonOutputs, jsonOutput)
	}

	return jsonOutputs, nil
}

func extractJSON(output string) (string, error) {
	startIndex := strings.Index(output, "{")
	if startIndex == -1 {
		return "", fmt.Errorf("no opening brace of JSON object found")
	}

	endIndex := strings.LastIndex(output, "}")
	if endIndex == -1 {
		return "", fmt.Errorf("no closing brace of JSON object found")
	}

	if endIndex+1 <= startIndex {
		return "", fmt.Errorf("invalid JSON boundaries found")
	}
	jsonPart := output[startIndex : endIndex+1]

	return jsonPart, nil
}
