package utility

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"wizscan/pkg/logger"

	"github.com/sirupsen/logrus"
)

type Arguments struct {
	WizClientID        string `json:"wizClientId"`
	WizClientSecret    string `json:"wizClientSecret"`
	WizQueryURL        string `json:"wizQueryUrl"`
	WizAuthURL         string `json:"wizAuthUrl"`
	ScanSubscriptionID string `json:"scanSubscriptionId"`
	ScanCloudType      string `json:"scanCloudType"`
	ScanProviderID     string `json:"scanProviderId"`
	Save               bool   `json:"save"`
}

func saveConfig(config *Arguments, filePath string) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	err = os.WriteFile(filePath, data, 0644)
	if err != nil {
		return err
	}
	return nil
}

// ArgParse parses command-line arguments and returns an Arguments struct and config file path.
func ArgParse() *Arguments {
	args := &Arguments{}
	var configFilePath string
	var logLevel string

	flag.StringVar(&logLevel, "logLevel", "info", "Set log level (info, error, etc.)")
	flag.StringVar(&args.WizClientID, "wizClientId", "", "Wiz Client ID")
	flag.StringVar(&args.WizClientSecret, "wizClientSecret", "", "Wiz Client Secret")
	flag.StringVar(&args.WizQueryURL, "wizQueryUrl", "", "Wiz Query URL")
	flag.StringVar(&args.WizAuthURL, "wizAuthUrl", "", "Wiz Auth URL")
	flag.StringVar(&args.ScanSubscriptionID, "scanSubscriptionId", "", "Scan Subscription ID")
	flag.StringVar(&args.ScanCloudType, "scanCloudType", "", "Scan Cloud Type")
	flag.StringVar(&args.ScanProviderID, "scanProviderId", "", "Scan Provider ID")
	flag.BoolVar(&args.Save, "save", false, "Set to true to save the configuration")
	flag.StringVar(&configFilePath, "config", "config.json", "Path to the configuration file")

	flag.Parse()

	// Set log level
	parsedLevel, err := logrus.ParseLevel(logLevel)
	if err != nil {
		logger.Log.Errorf("Invalid log level: %s", logLevel)
	} else {
		logger.Init(parsedLevel)
	}

	// Check if config file path is provided and attempt to read it
	if configFilePath != "" {
		if err := readConfig(configFilePath, args); err != nil {
			fmt.Println("Error reading config file:", err)
		}
	}

	// Check and save configuration if Save flag is set
	if args.Save {
		if err := saveConfig(args, configFilePath); err != nil {
			fmt.Println("Error saving config:", err)
		}
	}

	// Validate arguments before returning
	if err := validateArguments(args); err != nil {
		fmt.Println("Error validating arguments:", err)
		os.Exit(1) // Exit the program if validation fails
	}

	return args
}

// readConfig reads the configuration from a file into a Arguments struct
func readConfig(filePath string, config *Arguments) error {
	file, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	err = json.Unmarshal(file, config)
	if err != nil {
		return err
	}

	return nil
}

// validateArguments checks if all mandatory fields in Arguments are set.
func validateArguments(args *Arguments) error {
	if args.WizClientID == "" {
		return errors.New("WizClientID is required")
	}
	if args.WizClientSecret == "" {
		return errors.New("WizClientSecret is required")
	}
	if args.WizQueryURL == "" {
		return errors.New("WizQueryURL is required")
	}
	if args.WizAuthURL == "" {
		return errors.New("WizAuthURL is required")
	}
	if args.ScanSubscriptionID == "" {
		return errors.New("ScanSubscriptionID is required")
	}
	if args.ScanCloudType == "" {
		return errors.New("ScanCloudType is required")
	}
	if args.ScanProviderID == "" {
		return errors.New("ScanProviderID is required")
	}

	return nil
}
