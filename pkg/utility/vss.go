// utility/vss.go

package utility

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"wizscan/pkg/logger"
)

// CreateVSSSnapshot creates a VSS snapshot for the given drive and mounts it.
// It returns the path to the mounted snapshot and the shadow copy ID.
func CreateVSSSnapshot(drive string) (string, string, error) {
	if !isWindows() {
		return "", "", fmt.Errorf("VSS is only supported on Windows")
	}

	// Create VSS snapshot
	snapshotOutput, err := executeCommandAndGetOutput("vssadmin", "create", "shadow", "/For="+drive)
	if err != nil {
		return "", "", fmt.Errorf("failed to create VSS snapshot for %s: %v", drive, err)
	} else {
		logger.Log.Debugf("Created VSS snapshot for %s", drive)
	}

	// Extract the Shadow Copy Volume Name
	shadowCopyVolume, err := extractShadowCopyVolumeName(snapshotOutput)
	if err != nil {
		return "", "", err
	}

	// Extract the Shadow Copy ID
	shadowCopyID, err := extractShadowCopyID(snapshotOutput)
	if err != nil {
		return "", "", err
	}

	// Mount the snapshot
	mountedPath, err := mountSnapshot(drive, shadowCopyVolume)
	if err != nil {
		return "", shadowCopyID, err
	}

	return mountedPath, shadowCopyID, nil
}

// extractShadowCopyID extracts the Shadow Copy ID from the output.
func extractShadowCopyID(output string) (string, error) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Shadow Copy ID:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				// Trim spaces and return the ID part
				return strings.TrimSpace(parts[1]), nil
			}
		}
	}
	if err := scanner.Err(); err != nil {
		logger.Log.Errorf("Error reading output for Shadow Copy ID: %v", err)
		return "", err
	}
	return "", fmt.Errorf("shadow copy ID not found in output")
}

// executeCommandAndGetOutput executes a command and returns its output.
func executeCommandAndGetOutput(command string, args ...string) (string, error) {
	cmd := exec.Command(command, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Log.Errorf("Command execution failed: %s %v", command, err)
		return "", err
	}
	return string(output), nil
}

// extractShadowCopyVolumeName extracts the Shadow Copy Volume Name from the output.
func extractShadowCopyVolumeName(output string) (string, error) {
	scanner := bufio.NewScanner(bytes.NewReader([]byte(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Shadow Copy Volume Name:") {
			parts := strings.Fields(line)
			if len(parts) >= 5 {
				parts[4] += "\\"
				return parts[4], nil
			}
		}
	}
	return "", fmt.Errorf("shadow copy volume name not found in output")
}

// mountSnapshot mounts the VSS snapshot and returns the path.
func mountSnapshot(drive, shadowCopyVolume string) (string, error) {
	mountPath := fmt.Sprintf("%sShadowCopy", drive)
	mountCmd := fmt.Sprintf("mklink /D %s %s", mountPath, shadowCopyVolume)
	if _, err := executeCommandAndGetOutput("cmd", "/C", mountCmd); err != nil {
		return "", fmt.Errorf("failed to mount snapshot for %s: %v", drive, err)
	} else {
		logger.Log.Debugf("Mounted VSS Snapshot at %s", mountPath)
	}
	return mountPath, nil
}

// isWindows checks if the current OS is Windows.
func isWindows() bool {
	return runtime.GOOS == "windows"
}

// RemoveVSSSnapshot removes the VSS snapshot and the link for the given mounted path.
func RemoveVSSSnapshot(mountedPath string, shadowCopyID string) error {
	if !isWindows() {
		return fmt.Errorf("VSS is only supported on Windows")
	}

	// Command to remove the mount
	removeMountCmd := fmt.Sprintf("rd %s", mountedPath)
	if err := exec.Command("cmd", "/C", removeMountCmd).Run(); err != nil {
		logger.Log.Errorf("Failed to remove VSS mount for %s: %v", mountedPath, err)
		return err
	} else {
		logger.Log.Debugf("Removed mounted VSS snapshot at %s", mountedPath)
	}

	// Command to delete the VSS snapshot
	deleteSnapshotCmd := fmt.Sprintf("vssadmin delete shadows /Shadow=%s /quiet", shadowCopyID)
	if err := exec.Command("cmd", "/C", deleteSnapshotCmd).Run(); err != nil {
		logger.Log.Errorf("Failed to delete VSS snapshot for %s: %v", shadowCopyID, err)
		return err
	} else {
		logger.Log.Debugf("Removed VSS snapshot id: %s", shadowCopyID)
	}

	return nil
}
