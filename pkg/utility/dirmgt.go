package utility

import (
	"os"
	"path/filepath"
	"runtime"
	"wizscan/pkg/logger"
)

// Exclusion map
var exclusions = map[string]bool{
	"/lost+found": true,
	"/media":      true,
	"/mnt":        true,
	"/proc":       true,
	"/tmp":        true,
	"/sys":        true,
	"/cores":      true,
	"D:\\":        true, // For Windows
}

// listDirectoriesInDrive lists all top-level directories in the given drive.
func listDirectoriesInDrive(drive string) ([]string, error) {
	var directories []string
	entries, err := os.ReadDir(drive)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			dirPath := filepath.Join(drive, entry.Name())
			if !exclusions[dirPath] {
				directories = append(directories, dirPath)
			}
		}
	}
	return directories, nil
}

// ListTopLevelDirectories lists all top-level directories excluding specified ones.
func listTopLevelDirectories(rootPath string) ([]string, error) {
	var directories []string

	// Check the OS and handle Windows separately
	if runtime.GOOS == "windows" {
		for _, drive := range "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
			drive := string(drive) + ":\\"
			if _, err := os.Stat(drive); err == nil {
				directories = append(directories, drive)
			}
		}
	} else {
		// Unix-like system: Read all items in the root directory
		items, err := os.ReadDir(rootPath)
		if err != nil {
			return nil, err
		}

		// Iterate through the items
		for _, item := range items {
			if item.IsDir() {
				fullPath := filepath.Join(rootPath, item.Name())
				if !exclusions[fullPath] {
					directories = append(directories, fullPath)
				}
			}
		}
	}

	return directories, nil
}

func GetTopLevelDirectories() ([]string, error) {
	var allDirectories []string

	if runtime.GOOS == "windows" {
		for _, drive := range "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
			drive := string(drive) + ":\\"
			if _, err := os.Stat(drive); err == nil {
				driveDirectories, err := listDirectoriesInDrive(drive)
				if err != nil {
					logger.Log.Errorf("Error listing directories in drive %s: %v", drive, err)
				} else {
					allDirectories = append(allDirectories, driveDirectories...)
				}
			}
		}
	} else {
		// Unix-like systems code remains the same
		directories, err := listTopLevelDirectories("/")
		if err != nil {
			logger.Log.Errorf("Error listing directories: %v", err)
			return nil, err
		}
		allDirectories = append(allDirectories, directories...)
	}

	return allDirectories, nil
}
