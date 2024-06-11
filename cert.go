// cert.go
package main

import (
	"fmt"
	"os"
    "encoding/json"
)

// configuration file conf.json
type Configuration struct {
    PathRoot string `json:"pathRoot"`
}

/*
    loadConfig(filename string)

    Loads the configuration file filename in the same path
    The configuration file should be JSON

    Parameters:
        filename (string) - the filename of the configuration to import

    Returns:
        *Configuration -  configuration struct
        error - if the file cannot be read or deserialized

    Example:
        c, err = loadConfig("conf.json")
        fmt.Println(c.Pathroot)
*/
func loadConfig(filename string) (*Configuration, error) {
    body, err := os.ReadFile(filename)
    if err != nil {
        return &Configuration{}, fmt.Errorf("loadConfig: failed to read file %q\n%w\n", filename, err)
    }
    var c Configuration
    err = json.Unmarshal(body, &c)
    if err != nil {
        return &Configuration{}, fmt.Errorf("loadConfig: failed to parse file %q\n%w\n", filename, err)
    }

    return &c, nil
}

// representation of either a csr or cert file 
type Cert struct {
    Host, Type string
    Body []byte
}

/*
    Cert.get(config)

    Determines the certificate filepath given the pathRoot in the configuration file
    
    Parameters:
        config (string) - local or full path to the configuration file
    
    Returns:
        string - The full filepath corresponding to the certificate
        error - If the config input cannot be read

    Example:
        c, err := myCert.get("conf.json")
        fmt.Println(c)
*/
func (c *Cert) get(config string) (string, error) {
    conf, err := loadConfig(config)
    if err != nil {
        return "", fmt.Errorf("Cert.get: failed to read config file %q\n%w\n", config, err)
    }
    var pathRoot string = conf.PathRoot
    if c.Type == "csr" {
        return (pathRoot + "/csr/" + c.Host + ".csr.pem"), nil
    } else if c.Type == "cert" {
        return (pathRoot + "/certs/" + c.Host + ".cert.pem"), nil
    } else {
        return "", fmt.Errorf("Cert.get: invalid type %q; must be csr or cert", c.Type)
    }
}

/*
    Cert.save(config)

    Saves the certificate content to the appropriate filepath based on the config

    Parameters:
        config (string) - Local or full path to the config file

    Returns:
        error - if the config file cannot be read or if the file content cannot be written
*/
func (c *Cert) save(config string) error {
    certPath, err := c.get(config)
    if err != nil {
        return fmt.Errorf("Cert.save: failed to get filepath\n%w\n", err)
    }
    err = os.WriteFile(certPath, c.Body, 0600)
    if err != nil {
        return fmt.Errorf("Cert.save: failed to save file %q\n%w\n", certPath, err)
    }
    return nil
}

