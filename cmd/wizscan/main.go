package main

import (
	"runtime"
	"wizscan/pkg/logger"
	"wizscan/pkg/utility"
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

		// Process the scanResult as needed
		logger.Log.Infof("Scan completed for %s", mountedPath)
		// Example: Log the number of vulnerabilities found
		logger.Log.Infof("Found %d vulnerabilities in %s", len(scanResult.Vulnerabilities), mountedPath)

		// Remove the VSS snapshot and link
		if runtime.GOOS == "windows" {

			if err := utility.RemoveVSSSnapshot(mountedPath, shadowCopyID); err != nil {
				logger.Log.Errorf("Failed to remove mount and VSS snapshot for drive %s: %v", drive, err)
			}
		}
	}

}
