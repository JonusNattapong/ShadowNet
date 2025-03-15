package config

import (
	"errors"
	"io/ioutil"
	"os"

	"gopkg.in/yaml.v2"
)

// Config represents the application configuration
type Config struct {
	Honeypots struct {
		SSHPort    int `yaml:"ssh_port"`
		HTTPPort   int `yaml:"http_port"`
		FTPPort    int `yaml:"ftp_port"`
		RDPPort    int `yaml:"rdp_port"`
		SMBPort    int `yaml:"smb_port"`
		ModbusPort int `yaml:"modbus_port"`
		MQTTPort   int `yaml:"mqtt_port"`
	} `yaml:"honeypots"`

	Database struct {
		Host     string `yaml:"host"`
		Port     int    `yaml:"port"`
		User     string `yaml:"user"`
		Password string `yaml:"password"`
		DBName   string `yaml:"dbname"`
		TestDB   string `yaml:"test_db"`
	} `yaml:"database"`

	AI struct {
		ModelPath string `yaml:"model_path"`
	} `yaml:"ai"`

	Countermeasures struct {
		EnableExploits bool `yaml:"enable_exploits"`
	} `yaml:"countermeasures"`

	API struct {
		Port int `yaml:"port"`
	} `yaml:"api"`
}

// LoadConfig reads the configuration file and returns a Config struct
func LoadConfig() (*Config, error) {
	// First check if we have an environment-specific config
	env := os.Getenv("SHADOWNET_ENV")
	if env == "" {
		env = "development"
	}

	configFile := "config/config." + env + ".yaml"
	if _, err := os.Stat(configFile); errors.Is(err, os.ErrNotExist) {
		// Fall back to the default config file
		configFile = "config/config.yaml"
	}

	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	// Set default values for any missing configuration
	if config.API.Port == 0 {
		config.API.Port = 8000
	}

	return &config, nil
}
