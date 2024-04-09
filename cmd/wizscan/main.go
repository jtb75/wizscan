package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
	"wizscan/pkg/logger"
	"wizscan/pkg/utility"
	"wizscan/pkg/vulnerability"
	"wizscan/pkg/wizapi"
	"wizscan/pkg/wizcli"

	"github.com/sirupsen/logrus"
)

func main() {
	logger.Init(logrus.InfoLevel)

	args := utility.ArgParse() // Updated call to ArgParse
	logger.Log.Debugf("Arguments: %+v\n", args)

	apiClient := wizapi.NewWizAPI(args.WizClientID, args.WizClientSecret, args.WizAuthURL, args.WizQueryURL)
	if apiClient == nil {
		logger.Log.Error("Failed to initialize API client")
		return
	} else {
		logger.Log.Debugf("API Client: %+v\n", apiClient)
	}

	// Retrieve the resource ID
	resourceId, err := apiClient.GetResourceID(args.ScanCloudType, args.ScanProviderID)
	if err != nil {
		logger.Log.Error(err)
		return
	}

	logger.Log.Debugf("Matched Resource ID: %s", resourceId)

	response, err := wizapi.FetchAllVulnerabilities(apiClient, resourceId)
	if err != nil {
		logger.Log.Errorf("Error fetching vulnerabilities: %v", err)
		logger.Log.Debug("Vulnerability Query Response: ", response)
	}

	var assetVulns vulnerability.Asset

	// Set test to 0 to run, set to 1 to use sample data
	test := 0
	if test == 0 {

		jsonResponseBytes, err := json.MarshalIndent(response, "", "    ")
		if err != nil {
			fmt.Println("Error marshalling JSON:", err)
			return
		}
		// Writing the indented JSON output to a file
		err = os.WriteFile("sample_data/known_vulns.json", jsonResponseBytes, 0644)
		if err != nil {
			fmt.Println("Error writing to file:", err)
			logger.Log.Exit(1)
			return
		}

		// Initialize and authenticate wizcli
		cleanup, wizCliPath, err := wizcli.InitializeAndAuthenticate(args.WizClientID, args.WizClientSecret)
		if err != nil {
			logger.Log.Errorf("Initialization and authentication failed: %v", err)
			return
		}
		defer cleanup()

		// Retrieve top-level directories
		directories, err := utility.GetTopLevelDirectories()
		if err != nil {
			logger.Log.Errorf("Error listing directories: %v", err)
			return
		} else {
			logger.Log.Debug("Directories to scan: ", directories)
		}

		aggregatedResults := wizcli.AggregatedScanResults{}

		// Used for testing
		//directories = []string{"/boot", "/usr"}
		//directories = []string{"E:\\"}

		logger.Log.Info("Initiating directory scan")
		for _, drive := range directories {
			mountedPath := ""
			shadowCopyID := ""
			if runtime.GOOS == "windows" {
				mountedPath, shadowCopyID, err = utility.CreateVSSSnapshot(drive)
				if err != nil {
					logger.Log.Errorf("Error creating VSS snapshot for drive %s: %v", drive, err)
					continue
				}
			}

			// Do operations on the mounted snapshot...
			if mountedPath == "" {
				mountedPath = drive
			}
			scanResult, err := wizcli.ScanDirectory(wizCliPath, mountedPath)
			if err != nil {
				logger.Log.Errorf("Failed to scan %s: %v", mountedPath, err)
				continue
			}

			// Prepend the Drive to the Library path to represent actual full path
			for i, lib := range scanResult.Result.Libraries {
				if runtime.GOOS == "windows" {
					lib.Path = strings.ReplaceAll(lib.Path, "/", "\\")
					lib.Path = strings.TrimPrefix(lib.Path, "\\")
				}
				scanResult.Result.Libraries[i].Path = drive + lib.Path
			}

			// Aggregate results
			aggregatedResults.Libraries = append(aggregatedResults.Libraries, scanResult.Result.Libraries...)
			aggregatedResults.Applications = append(aggregatedResults.Applications, scanResult.Result.Applications...)
			// Remove the VSS snapshot and link
			if runtime.GOOS == "windows" {

				if err := utility.RemoveVSSSnapshot(mountedPath, shadowCopyID); err != nil {
					logger.Log.Errorf("Failed to remove mount and VSS snapshot for drive %s: %v", drive, err)
				}
			}

		}
		jsonBytes, err := json.MarshalIndent(aggregatedResults, "", "    ")
		if err != nil {
			fmt.Println("Error marshalling JSON:", err)
			return
		}

		err = os.WriteFile("sample_data/scan.json", jsonBytes, 0644)
		if err != nil {
			fmt.Println("Error writing to file:", err)
			return
		}

		assetVulns, err = vulnerability.CompareVulnerabilities(aggregatedResults, response, args.ScanProviderID)
		if err != nil {
			fmt.Printf("Error in CompareVulnerabilities: %s\n", err)
			return
		}

	} else {

		// Load the scan results into aggregatedResults using LoadScanResults
		// which returns a pointer to AggregatedScanResults
		filePath := "sample_data/scan.json" // Adjust the file path as necessary
		loadedResults, err := wizcli.LoadScanResults(filePath)
		if err != nil {
			fmt.Printf("Error loading scan results: %s\n", err)
			return
		}

		// Ensure loadedResults is not nil before dereferencing
		if loadedResults == nil {
			fmt.Println("No scan results loaded, loadedResults is nil")
			return
		}
		assetVulns, err = vulnerability.CompareVulnerabilities(*loadedResults, response, args.ScanProviderID)
		if err != nil {
			fmt.Printf("Error in CompareVulnerabilities: %s\n", err)
			return
		}

	}

	var vulnPayloadJSON []byte // Use a byte slice to hold JSON data

	if len(assetVulns.VulnerabilityFindings) > 0 {
		assetVulns.AssetIdentifier.CloudPlatform = args.ScanCloudType
		assetVulns.AssetIdentifier.ProviderId = args.ScanProviderID
		vulnPayload := vulnerability.IntegrationData{
			IntegrationId: "e7ddcf48-a2f3-fd39-89f4-b27c4efca17c", // Set an integration ID
			DataSources:   []vulnerability.DataSource{},           // Initialize an empty slice of DataSources
		}
		// Create a DataSource and add assetVulns to it
		dataSource := vulnerability.DataSource{
			Id:           args.ScanSubscriptionID,
			AnalysisDate: time.Now(),                        // Set current time as the analysis date
			Assets:       []vulnerability.Asset{assetVulns}, // Add assetVulns here
		}

		vulnPayload.DataSources = append(vulnPayload.DataSources, dataSource)

		vulnPayloadJSON, err = json.MarshalIndent(vulnPayload, "", "\t")
		if err != nil {
			fmt.Println("Error marshaling assetVulns to JSON:", err)
			return
		}
	} else {
		logger.Log.Infof("No new vulnerabilities found")
		return // Exit the program gracefully
	}

	file, err := utility.CreateTempFile()
	if err != nil {
		logger.Log.Errorln("Error creating temp file:", err)
		return
	}

	defer func() {
		// Ensure the temporary file is deleted upon exiting the function
		if err := file.Close(); err != nil {
			logger.Log.Errorf("Error closing file: %v", err)
		}
		if err := os.Remove(file.Name()); err != nil {
			logger.Log.Errorf("Error removing temporary file: %v", err)
		}
	}()

	logger.Log.Debugln("Temporary file created:", file.Name())

	_, err = file.Write(vulnPayloadJSON)
	if err != nil {
		logger.Log.Errorln("Error writing JSON to temp file:", err)
		return
	}

	if err := apiClient.PublishVulns(file.Name()); err != nil {
		logger.Log.Errorln("Error publishing vulnerabilities:", err)
	}

}
