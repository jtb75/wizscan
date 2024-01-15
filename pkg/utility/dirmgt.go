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
	// Determine the root path based on the operating system
	rootPath := "/"
	if runtime.GOOS == "windows" {
		rootPath = ""
	}

	// Get top level directories
	directories, err := listTopLevelDirectories(rootPath)
	if err != nil {
		logger.Log.Errorf("Error listing directories: %v", err)
		return nil, err
	}

	return directories, nil
}
