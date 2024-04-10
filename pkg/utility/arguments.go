package utility

import (
	"encoding/base64"
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
	Install            bool   `json:"install"`
	Uninstall          bool   `json:"uninstall"`
}

func saveConfig(config *Arguments, filePath string) error {
	config.Install = false // Ensure Install is always false when saving config

	// Marshal the config struct to JSON
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Encode the JSON data using base64
	encodedData := base64.StdEncoding.EncodeToString(data)

	// Convert encoded data to byte slice for writing to file
	byteData := []byte(encodedData)

	// Write the base64 encoded data to the file with 0600 permissions to ensure the file is only accessible to the user
	err = os.WriteFile(filePath, byteData, 0600)
	if err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

func ArgParse() (*Arguments, error) {
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
	flag.BoolVar(&args.Save, "save", false, "Set to true to save the configuration (ignored if install flag is set)")
	flag.StringVar(&configFilePath, "config", "config.json", "Path to the configuration file (ignored if install flag is set)")
	flag.BoolVar(&args.Install, "install", false, "Install the application")
	flag.BoolVar(&args.Uninstall, "uninstall", false, "Uninstall the application")

	flag.Parse()

	// Set log level
	parsedLevel, err := logrus.ParseLevel(logLevel)
	if err != nil {
		logger.Log.Errorf("Invalid log level: %s", logLevel)
	} else {
		logger.Init(parsedLevel)
	}

	// Enforce mutual exclusivity
	if args.Install && args.Uninstall {
		return nil, errors.New("'-install' and '-uninstall' cannot be used together")
	}

	// If uninstall is requested, we can immediately return since no other flags are needed
	if args.Uninstall {
		return args, nil
	}

	if args.Install {
		if err := validateArguments(args); err != nil {
			return nil, fmt.Errorf("error validating arguments: %v", err)
		}
		return args, nil
	}

	if configFilePath != "" {
		if err := readConfig(configFilePath, args); err != nil {
			return nil, fmt.Errorf("error reading config file: %v", err)
		}
	}

	if args.Save {
		if err := saveConfig(args, configFilePath); err != nil {
			return nil, fmt.Errorf("error saving config: %v", err)
		}
	}

	if err := validateArguments(args); err != nil {
		return nil, fmt.Errorf("error validating arguments: %v", err)
	}

	return args, nil
}

func readConfig(filePath string, config *Arguments) error {
	encodedData, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Decode the base64-encoded data
	decodedData, err := base64.StdEncoding.DecodeString(string(encodedData))
	if err != nil {
		return fmt.Errorf("failed to decode base64 data: %w", err)
	}

	// Unmarshal the JSON data into the Arguments struct
	if err = json.Unmarshal(decodedData, config); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return nil
}

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
