// cert.go
package main

import (
	"fmt"
	"os"
	//    "os/exec"

	"github.com/pelletier/go-toml/v2"
)

// configuration file config.toml
type Configuration struct {
	CertsRepo string
	CsrRepo   string
	CertChain string
}

// loadConfig(filename string)
// Loads the configuration file filename in the same path
// The configuration file should be TOML
func loadConfig(filename string) (*Configuration, error) {
	body, err := os.ReadFile(filename)
	if err != nil {
		return &Configuration{}, fmt.Errorf("loadConfig: failed to read file %q\n%w\n", filename, err)
	}

	// Generate Configuration from the read file
	var c Configuration
	err = toml.Unmarshal(body, &c)
	if err != nil {
		return &Configuration{}, fmt.Errorf("loadConfig: failed to parse file %q\n%w\n", filename, err)
	}

	return &c, nil
}

// representation of either a csr or cert file
type Cert struct {
	Host, CertType string
	Body           []byte
}

// Cert.Get(config)
// Returns the certificate filepath given the pathRoot in the configuration file
func (c *Cert) Get(config *Configuration) (string, error) {
	if c.CertType == "csr" {
		return (config.CsrRepo + c.Host + ".csr.pem"), nil
	} else if c.CertType == "cert" {
		return (config.CertsRepo + c.Host + ".cert.pem"), nil
	} else {
		return "", fmt.Errorf("Cert.get: invalid type %q; must be csr or cert", c.CertType)
	}
}

// Cert.Save(config)
// Saves the certificate content to the appropriate filepath based on the config
func (csr *Cert) Save(config *Configuration) error {
	certPath, err := csr.Get(config)
	if err != nil {
		return fmt.Errorf("Cert.Save: failed to get filepath\n%w\n", err)
	}

	var pathRoot string
	if csr.CertType == "csr" {
		pathRoot = config.CsrRepo
	} else {
		pathRoot = config.CertsRepo
	}

	// Create certificate repo path if it does not already exist
	_, err = os.Stat(pathRoot)
	if os.IsNotExist(err) {
		err = os.MkdirAll(pathRoot, os.ModePerm)
		if err != nil {
			return fmt.Errorf("Cert.Save: failed to create path %q\n%w\n", pathRoot, err)
		}
	}

	err = os.WriteFile(certPath, csr.Body, 0o444)
	if err != nil {
		return fmt.Errorf("Cert.Save: failed to save file %q\n%w\n", certPath, err)
	}
	return nil
}

// Cert.Verify()
// Will return error if certificate cannot be verified
/*
func (cer *Cert) Verify(config *Configuration) (int, error) {
    if cer.CertType != "cert" {
        return 1, fmt.Errorf("Cert.Verify: Invalid cert type %q", cer.CertType)
    }

    certPath, err := cer.Get(config)
    if err != nil {
        return 1, fmt.Errorf("Cert.Verify: Failed to get filepath\n%w\n", err)
    }

    _, err = os.Stat(certPath)
    if os.IsNotExist(err) {
        return 1, fmt.Errorf("Cert.Verify: file %q does not exist", certPath)
    }

    cmd := exec.Command("openssl", "verify", "-CAfile", config.CertChain, certPath)
    out, err := cmd.Output()
    if err != nil {
        if exitError, ok := err.(*exec.ExitError); ok {
            return exitError.ExitCode(), fmt.Errorf("Cert.Verify: openssl verify failed with exit code %d: %s", exitError.ExitCode(), out)
        }
        return 1, fmt.Errorf("Cert.Verify: openssl verify failed with unknown error: %w", err)
    }

    return 0, nil
}
*/
