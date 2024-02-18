package wizapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
	"wizscan/pkg/logger"
)

// WizAPI represents the client for interacting with the Wiz API.
type WizAPI struct {
	Session        *http.Client
	WizAPI         map[string]string
	ClientID       string
	ClientSecret   string
	ClientAuthURL  string
	ClientQueryURL string
	AuthToken      string // Added field to store the auth token
}

// NewWizAPI creates a new instance of WizAPI.
func NewWizAPI(clientID, clientSecret, clientAuthURL, clientQueryURL string) *WizAPI {
	api := &WizAPI{
		Session: &http.Client{Timeout: 60 * time.Second},
		WizAPI: map[string]string{
			"proxy":           "",    // Define if any proxy is used
			"wiz_req_timeout": "300", // Request timeout in seconds
		},
		ClientID:       clientID,
		ClientSecret:   clientSecret,
		ClientAuthURL:  clientAuthURL,
		ClientQueryURL: clientQueryURL,
	}

	// Authenticate the API Client
	if err := api.Authenticate(); err != nil {
		logger.Log.Errorf("Failed to authenticate: %v", err)
		return nil // Exit the program if authentication fails
	}

	return api
}

// Authenticate authenticates with the WizAPI and stores the auth token
func (w *WizAPI) Authenticate() error {
	// Construct the request data
	requestData := url.Values{}
	requestData.Set("audience", "wiz-api")
	requestData.Set("grant_type", "client_credentials")
	requestData.Set("client_id", w.ClientID)
	requestData.Set("client_secret", w.ClientSecret)

	// Send a POST request to the Wiz API authentication endpoint
	response, err := w.Session.PostForm(w.ClientAuthURL, requestData)
	if err != nil {
		return fmt.Errorf("error authenticating to the Wiz API: %w", err)
	}
	defer response.Body.Close()

	// Handle non-200 status
	if response.StatusCode != 200 {
		body, _ := io.ReadAll(response.Body)
		return fmt.Errorf("authentication failed with status: %s - %s", response.Status, string(body))
	}

	// Decode the response
	var responseData map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&responseData); err != nil {
		return fmt.Errorf("error parsing authentication response: %w", err)
	}

	// Extract the access token from the response
	token, ok := responseData["access_token"].(string)
	if !ok {
		return errors.New("no access token found in the response")
	}

	// Store the access token
	w.AuthToken = token
	return nil
}

// QueryWithRetry attempts to send a GraphQL query and retries if certain conditions are met.
func (w *WizAPI) QueryWithRetry(query string, variables map[string]interface{}) (*http.Response, error) {
	// Define how many times you want to retry and the delay between retries
	maxRetries := 3
	retryDelay := time.Second * 2

	// Prepare the request data
	data := map[string]interface{}{
		"query":     query,
		"variables": variables,
	}

	// Convert the data to JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("Error marshaling query data: %s\n", err)
		return nil, err
	}

	// Create the HTTP request
	request, err := http.NewRequest("POST", w.ClientQueryURL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Error creating request: %s\n", err)
		return nil, err
	}

	// Set necessary headers
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", w.AuthToken))
	request.Header.Add("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")

	// Initialize response variable
	var response *http.Response

	// Attempt the request with retries
	for attempt := 0; attempt < maxRetries; attempt++ {
		response, err = w.Session.Do(request)
		if err != nil {
			log.Printf("Error querying Wiz API: %s\n", err)
			time.Sleep(retryDelay) // Wait before retrying
			continue               // Proceed to the next attempt
		}

		// If the status code is not one of the retryable ones, break the loop
		if !w.RetryableResponseStatusCode(response.StatusCode) {
			break
		}

		// Close the previous response body to avoid leaks
		if response.Body != nil {
			response.Body.Close()
		}

		log.Printf("Retrying due to status code: %d, attempt: %d\n", response.StatusCode, attempt+1)
		time.Sleep(retryDelay) // Wait before retrying
	}

	// After the loop, check why the function exited the loop
	if err != nil {
		// If there was an error in the last attempt, return it
		return nil, err
	} else if response != nil && !w.RetryableResponseStatusCode(response.StatusCode) {
		// If the last response had a non-retryable status code, return the response
		return response, nil
	}

	// If none of the above conditions were met, it means all retries were exhausted
	return nil, fmt.Errorf("max retries reached with status code: %d", response.StatusCode)
}

// RetryableResponseStatusCode determines whether a given HTTP status code is retryable
func (w *WizAPI) RetryableResponseStatusCode(statusCode int) bool {
	// Define which status codes are considered retryable
	switch statusCode {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func RedactAuthToken(output string) string {
	// Define the start and end markers of the sensitive information
	startMarker := "AuthToken:"
	endMarker := `"`

	// Find the starting position of the AuthToken value
	startIndex := strings.Index(output, startMarker)
	if startIndex == -1 {
		// AuthToken not found; return original output
		return output
	}

	// Adjust startIndex to point to the start of the AuthToken value
	startIndex += len(startMarker)

	// Find the end position of the AuthToken value
	endIndex := strings.Index(output[startIndex:], endMarker)
	if endIndex == -1 {
		// End marker not found; return original output
		return output
	}

	// Adjust endIndex to be relative to the entire output string
	endIndex += startIndex + len(endMarker)

	// Replace the AuthToken with "REDACTED"
	redactedOutput := output[:startIndex] + " \"REDACTED\"" + output[endIndex:]

	return redactedOutput
}
