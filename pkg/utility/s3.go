package utility

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"wizscan/pkg/logger"
)

// uploads a file to the provided upload URL.
func S3Upload(uploadURL, filePath string) error {
	// Open the file that needs to be uploaded.
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("cannot open file: %v", err)
	}
	defer file.Close()

	// Read the file's contents into memory
	fileContents, err := io.ReadAll(file)
	if err != nil {
		return fmt.Errorf("cannot read file contents: %v", err)
	}

	// Create a new request with the file contents
	req, err := http.NewRequest("PUT", uploadURL, bytes.NewReader(fileContents))
	if err != nil {
		return fmt.Errorf("cannot create request: %v", err)
	}

	// Set the appropriate headers (if your server expects a specific content type, set it here)
	req.Header.Set("Content-Type", "application/octet-stream")

	// Perform the upload request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Check for a successful response
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	logger.Log.Info("Vulnerability information uploaded successfully")
	return nil
}
