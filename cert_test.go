package main

import (
	"bytes"
	"os"
	"testing"
)

var testCerts = []*Cert {
    {Host: "webserver.domain", Body: []byte("Testing ABC"), Type: "csr"},
    {Host: "appserver.domain", Body: []byte("Testing 123"), Type: "cert"},
    {Host: "dbserver.domain", Body: []byte("Testing xyz"), Type: "bogus"},
    {Host: "authserver.domain", Body: []byte("Testing 987"), Type: ""},
}

type getTest struct {
    cert *Cert
    expected string
}

var getTests = []getTest {
    {testCerts[0], "./root/ca/intermediate/csr/webserver.domain.csr.pem"},
    {testCerts[1], "./root/ca/intermediate/certs/appserver.domain.cert.pem"},
    {testCerts[2], ""},
    {testCerts[3], ""},
}

// loadConfig() should output a configuration for the test config
func TestLoadConfig(t *testing.T) {
    config, err := loadConfig("test.toml")
    if err != nil {
        t.Errorf("loadConfig failed due to error %q", err)
    }
    
    var certsExpected string = "./root/ca/intermediate/certs/"
    var csrExpected string = "./root/ca/intermediate/csr/"

    if config.CertsRepo != certsExpected {
        t.Errorf("Output %q not equal to expected %q", config.CertsRepo, certsExpected)
    }

    if config.CsrRepo != csrExpected {
        t.Errorf("Output %q not equal to expected %q", config.CsrRepo, csrExpected)
    }
}

// Cert.get() should output a string containing the filepath
// /root/ca/intermediate/${Cert.Type}s/${Cert.Host}.${Cert.Type}.pem
func TestGet(t *testing.T) {
    config, _ := loadConfig("test.toml")
    for _, test := range getTests {
        output, _ := test.cert.get(config)
        if output != test.expected {
            t.Errorf("Output %q not equal to expected %q", output, test.expected)
        }
    }
}


// Cert.save() should create a file with the certificate name and file
func TestSave(t *testing.T) {
    config, _ := loadConfig("test.toml")
    for _, test := range testCerts {
        certPath, err := test.get(config)
        if err != nil {
            continue
        }

        err = test.save(config)
        if err != nil {
            t.Errorf("Cert.save produced error: %q", err)
        }

        // Check that the file exists
        body, err := os.ReadFile(certPath)
        if err != nil {
            t.Errorf("File %q not saved to system", certPath)
        }

        // Check that the body matches that of the cert struct
        if !(bytes.Equal(body, test.Body)) {
            t.Errorf("Body '%q' doesn't match expected body '%q'", body, test.Body)
        }

        // Cleanup the files
        os.Remove(certPath)
    }
}
