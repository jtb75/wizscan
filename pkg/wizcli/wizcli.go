package wizcli

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"wizscan/pkg/logger"
)

// WizCliURLs holds the download URLs for wizcli binaries for different platforms and architectures.
var WizCliURLs = map[string]string{
	"linux/amd64":   "https://wizcli.app.wiz.io/latest/wizcli-linux-amd64",
	"linux/arm64":   "https://wizcli.app.wiz.io/latest/wizcli-linux-arm64",
	"darwin/arm64":  "https://wizcli.app.wiz.io/latest/wizcli-darwin-arm64",
	"windows/amd64": "https://wizcli.app.wiz.io/latest/wizcli-windows-amd64.exe",
	// Add other platforms and architectures as needed.
}

// GetDownloadURL returns the URL to download wizcli based on the operating system and architecture.
func GetDownloadURL() (string, error) {
	key := runtime.GOOS + "/" + runtime.GOARCH
	url, exists := WizCliURLs[key]
	if !exists {
		return "", fmt.Errorf("unsupported platform or architecture: %s", key)
	}
	return url, nil
}

// DownloadFile downloads a URL to a local file. It's efficient because it writes as it downloads and doesn't load the whole file into memory.
func DownloadFile(filepath string, url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

// SetupEnvironment creates a temporary directory, downloads wizcli, and sets up necessary permissions.
func SetupEnvironment() (string, error) {
	// Get the correct download URL for the platform
	url, err := GetDownloadURL()
	if err != nil {
		return "", fmt.Errorf("error determining download URL: %v", err)
	}

	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "wizcli")
	if err != nil {
		return "", fmt.Errorf("error creating a temporary directory: %v", err)
	}

	// Define the path for the downloaded file
	downloadPath := tmpDir + "/wizcli"
	if runtime.GOOS == "windows" {
		downloadPath += ".exe" // Adjust if Windows support is added
	}

	// Download the file
	logger.Log.Debugf("Downloading wizcli: %v", downloadPath)
	if err := DownloadFile(downloadPath, url); err != nil {
		os.RemoveAll(tmpDir) // Clean up the temporary directory
		return "", fmt.Errorf("error downloading wizcli: %v", err)
	}
	logger.Log.Debug("Download Complete")

	// Set up permissions (especially for Unix-like systems)
	if runtime.GOOS != "windows" {
		if err := os.Chmod(downloadPath, 0755); err != nil {
			os.RemoveAll(tmpDir)
			return "", fmt.Errorf("error setting execute permissions on wizcli: %v", err)
		}
	}

	return downloadPath, nil
}

func AuthenticateWizcli(wizcliPath, wizClientID, wizClientSecret string) (string, error) {
	cmd := exec.Command(wizcliPath, "auth", "--id", wizClientID, "--secret", wizClientSecret)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("wizcli authentication failed: %v - Output: %s", err, string(output))
	}

	return "wizcli authenticated successfully", nil
}

// CleanupEnvironment removes the temporary directory and its contents.
func CleanupEnvironment(downloadPath string) error {
	// Extract the directory path from the full downloadPath
	dirPath := filepath.Dir(downloadPath)

	// Remove the directory and its contents
	err := os.RemoveAll(dirPath)
	if err != nil {
		return err
	}
	return nil
}

func InitializeAndAuthenticate(clientID, clientSecret string) (cleanupFunc func(), err error) {
	wizCliPath, err := SetupEnvironment()
	if err != nil {
		logger.Log.Errorf("Failed to set up wizcli environment: %v", err)
		return nil, err
	}

	cleanupFunc = func() {
		if err := CleanupEnvironment(wizCliPath); err != nil {
			logger.Log.Errorf("Warning: Failed to clean up environment: %v", err)
		}
	}

	// Set the WIZ_DIR environment variable
	wizDir := filepath.Dir(wizCliPath)
	if err := os.Setenv("WIZ_DIR", wizDir); err != nil {
		cleanupFunc()
		logger.Log.Errorf("Failed to set WIZ_DIR environment variable: %v", err)
		return nil, err
	}

	// Authenticate wizcli
	authMessage, err := AuthenticateWizcli(wizCliPath, clientID, clientSecret)
	if err != nil {
		cleanupFunc()
		logger.Log.Errorf("Failed to authenticate wizcli: %v", err)
		return nil, err
	}
	logger.Log.Info(authMessage)

	return cleanupFunc, nil
}
