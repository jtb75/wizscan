package utility

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
	"wizscan/pkg/logger"
)

func ensureConfigDirExists() (string, error) {
	var dirPath string

	if runtime.GOOS == "windows" {
		// Get the local app data directory
		localAppData, err := os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("failed to get local app data directory: %w", err)
		}
		dirPath = localAppData + "\\wizscan"
	} else {
		// For Linux and potentially other Unix-like systems, use /etc
		dirPath = "/etc/wizscan"
	}

	// Check if the directory exists
	if _, err := os.Stat(dirPath); os.IsNotExist(err) {
		// Create the directory with appropriate permissions
		// Permissions set to 0700 to ensure that only the owner can access it on Unix.
		// Windows will generally ignore these permissions but will follow ACLs.
		err := os.MkdirAll(dirPath, 0700)
		if err != nil {
			return "", fmt.Errorf("failed to create directory '%s': %w", dirPath, err)
		}
	} else if err != nil {
		return "", fmt.Errorf("error checking directory '%s': %w", dirPath, err)
	}

	if runtime.GOOS == "windows" {
		// Get the local app data directory
		return dirPath + "\\config", nil
	} else {
		// For Linux and potentially other Unix-like systems, use /etc
		return dirPath + "/config", nil
	}
}

func InstallApp(args *Arguments) error {
	configPath, err := ensureConfigDirExists()
	if err != nil {
		logger.Log.Errorf("Setup failed. See log for details: %v", err)
		return fmt.Errorf("setup failed. See log for details: %v", err)
	}
	if err := saveConfig(args, configPath); err != nil {
		logger.Log.Errorf("Error saving config: %v", err)
		return fmt.Errorf("error saving config: %v", err)
	}
	logger.Log.Infof("Config successfully saved to: %s", configPath)

	binaryPath, err := copyBinaryToPath() // Ensure this function now returns the path of the copied binary
	if err != nil {
		logger.Log.Errorf("Installation failed: %v", err)
		return fmt.Errorf("installation failed: %v", err)
	}
	logger.Log.Infof("Binary successfully copied to: %s", binaryPath)

	// Schedule the binary to run daily between 8pm and 11:30pm
	if err := scheduleDailyRun(binaryPath); err != nil {
		logger.Log.Errorf("Failed to schedule daily run: %v", err)
		return fmt.Errorf("failed to schedule daily run: %v", err)
	}
	logger.Log.Info("Scheduled daily run successfully.")

	return nil
}

func copyBinaryToPath() (string, error) {
	// Determine the path of the currently running executable
	src, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to determine path of the current executable: %w", err)
	}

	// Determine the destination path based on the operating system
	var dstPath string
	if runtime.GOOS == "windows" {
		dstPath = filepath.Join(os.Getenv("PROGRAMFILES"), filepath.Base(src)) // Typically C:\Program Files\
	} else {
		dstPath = filepath.Join("/usr/local/bin", filepath.Base(src))
	}

	// Read the binary data from the current executable
	input, err := os.ReadFile(src)
	if err != nil {
		return "", fmt.Errorf("failed to read source binary '%s': %w", src, err)
	}

	// Write the binary data to the destination path with appropriate permissions
	if err := os.WriteFile(dstPath, input, 0755); err != nil { // Setting execute permissions for Unix
		return "", fmt.Errorf("failed to copy binary to %s: %w", dstPath, err)
	}

	return dstPath, nil
}

func UninstallApp() error {
	// First, remove any scheduled tasks to prevent them from attempting to execute non-existent binaries
	if err := removeScheduledDailyRun(); err != nil {
		logger.Log.Errorf("Failed to remove scheduled tasks: %v", err)
		return fmt.Errorf("failed to remove scheduled tasks: %w", err)
	}
	logger.Log.Info("Scheduled tasks removed successfully.")

	var binDir, configDir string
	if runtime.GOOS == "windows" {
		binDir = filepath.Join(os.Getenv("PROGRAMFILES"), "wizscan")
		configDir = filepath.Join(os.Getenv("PROGRAMFILES"), "wizscan")
	} else {
		binDir = "/usr/local/bin"
		configDir = "/etc/wizscan"
	}

	// Find and remove any binaries that start with "wizscan"
	binaries, err := filepath.Glob(filepath.Join(binDir, "wizscan*"))
	if err != nil {
		return fmt.Errorf("failed to search for binaries: %w", err)
	}
	for _, binPath := range binaries {
		if err := os.Remove(binPath); err != nil {
			return fmt.Errorf("failed to remove binary '%s': %w", binPath, err)
		}
		logger.Log.Debugf("Binary removed: '%s'", binPath)
	}

	// Remove the configuration file
	configFilePath := filepath.Join(configDir, "config")
	if err := os.Remove(configFilePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove configuration file '%s': %w", configFilePath, err)
	}
	logger.Log.Debugf("Config file removed: '%s'", configFilePath)

	// Remove the configuration directory if empty
	if err := os.Remove(configDir); err != nil && !os.IsNotExist(err) {
		// If the directory is not empty, you might want to list contents or force remove
		return fmt.Errorf("failed to remove configuration directory '%s': %w", configDir, err)
	}
	logger.Log.Debugf("Config file directory: '%s'", configDir)

	return nil
}

// ScheduleDailyRun schedules the binary to run daily between 8 PM and 11:30 PM.
func scheduleDailyRun(binaryPath string) error {
	if runtime.GOOS == "windows" {
		return scheduleOnWindows(binaryPath)
	}
	// First, remove any scheduled tasks to make sure we are not duplicating
	if err := removeScheduledDailyRun(); err != nil {
		logger.Log.Errorf("Failed to remove scheduled tasks: %v", err)
		return fmt.Errorf("failed to remove scheduled tasks: %w", err)
	}
	return scheduleOnLinux(binaryPath)
}

// scheduleOnLinux uses crontab to schedule the binary execution.
func scheduleOnLinux(binaryPath string) error {
	minute := rand.Intn(31)   // Random minute between 0 and 30
	hour := rand.Intn(4) + 20 // Random hour between 20 (8 PM) and 23 (11 PM)

	// Setting up the cron job command with log redirection and configuration option
	cronJob := fmt.Sprintf("%d %d * * * %s -config /etc/wizscan/config >> /var/log/wizscan.log 2>&1\n", minute, hour, binaryPath)

	// Adding the cron job to the user's crontab
	cmd := exec.Command("bash", "-c", fmt.Sprintf("(crontab -l 2>/dev/null; echo '%s') | crontab -", cronJob))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to schedule cron job: %w", err)
	}
	return nil
}

// scheduleOnWindows uses Task Scheduler via PowerShell to schedule the binary execution.
func scheduleOnWindows(binaryPath string) error {
	minute := rand.Intn(31)   // Random minute between 0 and 30
	hour := rand.Intn(4) + 20 // Random hour between 20 (8 PM) and 23 (11 PM)

	// PowerShell command to create a scheduled task
	psCommand := fmt.Sprintf(`$action = New-ScheduledTaskAction -Execute '%s';`+
		`$trigger = New-ScheduledTaskTrigger -Daily -At %d:%02d PM;`+
		`Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "RunWizScanDaily" -Description "Runs WizScan daily between 8PM and 11:30PM"`,
		binaryPath, hour, minute)

	cmd := exec.Command("powershell", "-Command", psCommand)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create scheduled task on Windows: %w", err)
	}
	return nil
}

func init() {
	rand.Seed(time.Now().UnixNano()) // Seed random number generator
}

// removeScheduledDailyRun removes a scheduled daily run from either cron (Linux) or Task Scheduler (Windows).
func removeScheduledDailyRun() error {
	if runtime.GOOS == "windows" {
		return removeScheduledTaskWindows()
	}
	return removeScheduledTaskLinux()
}

// removeScheduledTaskLinux removes the scheduled cron job for the wizscan application.
func removeScheduledTaskLinux() error {
	// This command filters out 'wizscan' and any empty lines left behind.
	cmd := exec.Command("bash", "-c", "crontab -l | grep -v 'wizscan' | grep -v '^$' | crontab -")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to remove scheduled cron job: %w", err)
	}
	return nil
}

// removeScheduledTaskWindows removes the scheduled task created for the wizscan application.
func removeScheduledTaskWindows() error {
	cmd := exec.Command("powershell", "-Command", "Unregister-ScheduledTask -TaskName 'RunWizScanDaily' -Confirm:$false")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to remove scheduled task on Windows: %w", err)
	}
	return nil
}
