// cert.go
package main

import (
	"fmt"
	"github.com/pelletier/go-toml/v2"
	"os"
)

// configuration file config.toml
type Configuration struct {
	CertsRepo string
	CsrRepo   string
}

/*
loadConfig(filename string)

Loads the configuration file filename in the same path
The configuration file should be TOML

Parameters:

	filename (string) - the filename of the configuration to import

Returns:

	*Configuration -  configuration struct
	error - if the file cannot be read or deserialized

Example:

	c, err = loadConfig("config.toml")
	fmt.Println(c.Pathroot)
*/
func loadConfig(filename string) (*Configuration, error) {
	body, err := os.ReadFile(filename)
	if err != nil {
		return &Configuration{}, fmt.Errorf("loadConfig: failed to read file %q\n%w\n", filename, err)
	}
	var c Configuration
	err = toml.Unmarshal(body, &c)
	if err != nil {
		return &Configuration{}, fmt.Errorf("loadConfig: failed to parse file %q\n%w\n", filename, err)
	}

	return &c, nil
}

// representation of either a csr or cert file
type Cert struct {
	Host, Type string
	Body       []byte
}

/*
Cert.get(config)

# Determines the certificate filepath given the pathRoot in the configuration file

Parameters:

	config (string) - local or full path to the configuration file

Returns:

	string - The full filepath corresponding to the certificate
	error - If the config input cannot be read

Example:

	c, err := myCert.get("conf.json")
	fmt.Println(c)
*/
func (c *Cert) get(config *Configuration) (string, error) {
	if c.Type == "csr" {
		return (config.CsrRepo + c.Host + ".csr.pem"), nil
	} else if c.Type == "cert" {
		return (config.CertsRepo + c.Host + ".cert.pem"), nil
	} else {
		return "", fmt.Errorf("Cert.get: invalid type %q; must be csr or cert", c.Type)
	}
}

/*
Cert.save(config)

# Saves the certificate content to the appropriate filepath based on the config

Parameters:

	config (string) - Local or full path to the config file

Returns:

	error - if the config file cannot be read or if the file content cannot be written
*/
func (c *Cert) save(config *Configuration) error {
	certPath, err := c.get(config)
	if err != nil {
		return fmt.Errorf("Cert.save: failed to get filepath\n%w\n", err)
	}

	var pathRoot string
	if c.Type == "csr" {
		pathRoot = config.CsrRepo
	} else {
		pathRoot = config.CertsRepo
	}

	_, err = os.Stat(pathRoot)
	if os.IsNotExist(err) {
		err = os.MkdirAll(pathRoot, os.ModePerm)
		if err != nil {
			return fmt.Errorf("Cert.save: failed to create path %q\n%w\n", pathRoot, err)
		}
	}
	err = os.WriteFile(certPath, c.Body, 0444)
	if err != nil {
		return fmt.Errorf("Cert.save: failed to save file %q\n%w\n", certPath, err)
	}
	return nil
}
