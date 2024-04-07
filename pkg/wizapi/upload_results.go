package wizapi

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"wizscan/pkg/logger"
	"wizscan/pkg/utility"
)

// Query to Post for upload of new vulnerability content
const graphFileUploadRequest = `
query RequestSecurityScanUpload($filename: String!) {
	requestSecurityScanUpload(filename: $filename) {
	  upload {
		id
		url
		systemActivityId
	  }
	}
}
`

// Query to check System Activity (check upload status)
const graphSystemActivityQuery = `
query SystemActivity($id: ID!) {
	systemActivity(id: $id) {
		id
		status
		statusInfo
		result {
		  ...on SystemActivityEnrichmentIntegrationResult{
			dataSources {
			  ... IngestionStatsDetails
			}
			findings {
			  ... IngestionStatsDetails
			}
			events {
			  ... IngestionStatsDetails
			}
			tags {
			  ... IngestionStatsDetails
			}
			unresolvedAssets {
			  ... UnresolvedAssetsDetails
			}
		  }
		}
		context {
		  ... on SystemActivityEnrichmentIntegrationContext{
			fileUploadId
		  }
		}
	}
  }
fragment IngestionStatsDetails on EnrichmentIntegrationStats {
	incoming
	handled
}

fragment UnresolvedAssetsDetails on EnrichmentIntegrationUnresolvedAssets {
	count
	ids
}
`

// RequestSecurityScanUploadResponse represents the response structure for the RequestSecurityScanUpload query
type RequestSecurityScanUploadResponse struct {
	Data struct {
		RequestSecurityScanUpload struct {
			Upload struct {
				ID               string `json:"id"`
				URL              string `json:"url"`
				SystemActivityId string `json:"systemActivityId"`
			} `json:"upload"`
		} `json:"requestSecurityScanUpload"`
	} `json:"data"`
	Errors []GraphQLResourceError `json:"errors"` // Reuse the existing error struct
}

// SystemActivityResponse is the expected response from the SystemActivity GraphQL query
type SystemActivityResponse struct {
	Data struct {
		SystemActivity struct {
			ID         string `json:"id"`
			Status     string `json:"status"`
			StatusInfo string `json:"statusInfo"`
			Result     struct {
				DataSources      IngestionStatsDetails `json:"dataSources"`
				Findings         IngestionStatsDetails `json:"findings"`
				Events           IngestionStatsDetails `json:"events"`
				Tags             IngestionStatsDetails `json:"tags"`
				UnresolvedAssets struct {
					Count int      `json:"count"`
					IDs   []string `json:"ids"`
				} `json:"unresolvedAssets"`
			} `json:"result"`
			Context struct {
				FileUploadId string `json:"fileUploadId"`
			} `json:"context"`
		} `json:"systemActivity"`
	} `json:"data"`
	Errors []GraphQLResourceError `json:"errors"`
}

type IngestionStatsDetails struct {
	Incoming int `json:"incoming"`
	Handled  int `json:"handled"`
}

// GraphQLRequest represents a request to a GraphQL API.
type GraphQLRequest struct {
	Query     string                 `json:"query"`     // The GraphQL query string
	Variables map[string]interface{} `json:"variables"` // Any variables used in the query
}

// RequestSecurityScanUpload sends a query to request a security scan upload URL and ID for a file
func (w *WizAPI) requestSecurityScanUpload(filename string) (*RequestSecurityScanUploadResponse, error) {
	// Prepare the variables for the query
	variables := map[string]interface{}{
		"filename": filename,
	}

	// Execute the query using the constant graphFileUploadRequest
	response, err := w.QueryWithRetry(graphFileUploadRequest, variables)
	if err != nil {
		return nil, fmt.Errorf("error querying with retry: %w", err)
	}

	// Process the HTTP response and unmarshal the JSON into RequestSecurityScanUploadResponse
	var uploadResponse RequestSecurityScanUploadResponse
	if err := json.NewDecoder(response.Body).Decode(&uploadResponse); err != nil {
		return nil, fmt.Errorf("error unmarshaling response: %w", err)
	}

	// Handle any errors in the response
	if len(uploadResponse.Errors) > 0 {
		return nil, fmt.Errorf("graphql errors: %v", uploadResponse.Errors)
	}

	return &uploadResponse, nil
}

// querySystemActivity performs the SystemActivity GraphQL query with the given ID.
func (w *WizAPI) querySystemActivity(systemActivityID string) (*SystemActivityResponse, error) {
	// Prepare the variables for the query
	variables := map[string]interface{}{
		"id": systemActivityID,
	}

	// Use QueryWithRetry to perform the query with built-in retry logic
	response, err := w.QueryWithRetry(graphSystemActivityQuery, variables)
	if err != nil {
		return nil, fmt.Errorf("error querying system activity with retry: %w", err)
	}
	defer response.Body.Close()

	// Decode the response into the SystemActivityResponse struct
	var systemActivityResponse SystemActivityResponse
	if err := json.NewDecoder(response.Body).Decode(&systemActivityResponse); err != nil {
		return nil, fmt.Errorf("error unmarshaling response: %w", err)
	}

	// Check for GraphQL errors
	if len(systemActivityResponse.Errors) > 0 {
		return nil, fmt.Errorf("graphql errors: %v", systemActivityResponse.Errors)
	}

	// Return the parsed response
	return &systemActivityResponse, nil
}

// PublishVulns handles the publication of vulnerability findings by uploading them to an S3 bucket.
func (w *WizAPI) PublishVulns(tempFilePath string) error {
	uploadResponse, err := w.requestSecurityScanUpload(tempFilePath)
	if err != nil {
		return fmt.Errorf("failed to request upload URL: %w", err)
	}

	uploadURL := uploadResponse.Data.RequestSecurityScanUpload.Upload.URL
	if uploadURL == "" {
		return fmt.Errorf("received empty upload URL")
	}

	if err := utility.S3Upload(uploadURL, tempFilePath); err != nil {
		return fmt.Errorf("failed to upload file to S3: %w", err)
	}

	logger.Log.Debugln("File successfully uploaded to S3:", uploadURL)

	const maxRetries = 5
	const retryDelay = 10 // in seconds

	var systemActivityResponse *SystemActivityResponse
	for attempt := 0; attempt < maxRetries; attempt++ {
		systemActivityResponse, err = w.querySystemActivity(uploadResponse.Data.RequestSecurityScanUpload.Upload.SystemActivityId)
		if err != nil {
			if strings.Contains(err.Error(), "Resource not found") && attempt < maxRetries-1 {
				logger.Log.Infof("Resource not found, retrying in %d seconds...", retryDelay)
				time.Sleep(time.Duration(retryDelay) * time.Second)
				continue
			} else {
				logger.Log.Errorf("Error querying system activity: %v", err)
				break
			}
		}

		if systemActivityResponse.Data.SystemActivity.Status == "IN_PROGRESS" && attempt < maxRetries-1 {
			logger.Log.Infof("Processing upload, retrying in %d seconds...", retryDelay)
			time.Sleep(time.Duration(retryDelay) * time.Second)
			continue
		}
		break
	}

	if err == nil {
		logger.Log.Infof("System Activity Status: %s", systemActivityResponse.Data.SystemActivity.Status)
	} else {
		logger.Log.Error("Failed to query system activity after retries.")
	}

	return err // Return the final state of 'err', whether it's nil or contains an error
}
