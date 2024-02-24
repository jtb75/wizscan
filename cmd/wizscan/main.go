package main

import (
	"runtime"
	"strings"
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
	/*
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
	*/
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
		logger.Log.Info("Directories to scan: ", directories)
	}

	aggregatedResults := wizcli.AggregatedScanResults{}

	// Used for testing
	//directories = []string{"/boot", "/usr"}
	//directories = []string{"E:\\"}

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

		// Process the scanResult as needed
		logger.Log.Infof("Scan completed for %s", mountedPath)
		// Example: Log the number of vulnerabilities found
		logger.Log.Infof("Found %d libraries with vulnerabilities in %s", len(scanResult.Result.Libraries), mountedPath)
		logger.Log.Infof("Found %d applications with vulnerabilities in %s", len(scanResult.Result.Applications), mountedPath)

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
	/*
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

		fmt.Println("Results saved to output.json")
	*/

	vulnerability.CompareVulnerabilities(aggregatedResults, response)
}
