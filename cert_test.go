package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

const TEST_CONFIG string = "test.toml"

var getTestCerts = [4]*Cert{
	{Host: "webserver.domain", Body: []byte("Testing ABC"), CertType: "csr"},
	{Host: "appserver.domain", Body: []byte("Testing 123"), CertType: "cert"},
	{Host: "dbserver.domain", Body: []byte("Testing xyz"), CertType: "bogus"},
	{Host: "authserver.domain", Body: []byte("Testing 987"), CertType: ""},
}

type certTest struct {
	cert     *Cert
	expected string
}

var getTests = [4]*certTest{
	{getTestCerts[0], "./root/ca/intermediate/csr/webserver.domain.csr.pem"},
	{getTestCerts[1], "./root/ca/intermediate/certs/appserver.domain.cert.pem"},
	{getTestCerts[2], ""},
	{getTestCerts[3], ""},
}

// loadConfig() should output a configuration for the test config
func TestLoadConfig(t *testing.T) {
	config, err := loadConfig(TEST_CONFIG)
	if err != nil {
		t.Errorf("loadConfig failed due to error %q", err)
	}

	const CERTS_EXPECTED string = "./root/ca/intermediate/certs/"
	const CSR_EXPECTED string = "./root/ca/intermediate/csr/"

	if config.CertsRepo != CERTS_EXPECTED {
		t.Errorf("Output %q not equal to expected %q", config.CertsRepo, CERTS_EXPECTED)
	}

	if config.CsrRepo != CSR_EXPECTED {
		t.Errorf("Output %q not equal to expected %q", config.CsrRepo, CSR_EXPECTED)
	}
}

// Cert.get() should output a string containing the filepath
// /root/ca/intermediate/${Cert.Type}s/${Cert.Host}.${Cert.Type}.pem
func TestGet(t *testing.T) {
	config, err := loadConfig(TEST_CONFIG)
	if err != nil {
		t.Errorf("loadConfig failed due to error %q", err)
		return
	}
	for _, test := range getTests {
		output, _ := test.cert.Get(config)
		if output != test.expected {
			t.Errorf("Output %q not equal to expected %q", output, test.expected)
		}
	}
}

// Cert.save() should create a file with the certificate name and file
func TestSave(t *testing.T) {
	config, err := loadConfig(TEST_CONFIG)
	if err != nil {
		t.Errorf("loadConfig failed due to error %q", err)
		return
	}

	for _, test := range getTestCerts {
		certPath, err := test.Get(config)
		if err != nil {
			continue
		}

		err = test.Save(config)
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

var loadTestCerts = map[string]*Cert{
	"valid.domain.cert.pem":   {Host: "valid.domain", Body: []byte("Testing ABC\n"), CertType: "cert"},
	"invalid.domain.cert.pem": {Host: "invalid.domain", Body: []byte("Testing 123\n"), CertType: "cert"},
	"revoked.domain.cert.pem": {Host: "revoked.domain", Body: []byte("Testing XYZ\n"), CertType: "cert"},
}

// LoadCert() should load a certificate file into a Cert struct
func TestLoadCert(t *testing.T) {
	for file, expected := range loadTestCerts {
		fullPath := filepath.Join("./loadTestFiles", file)
		loaded, err := LoadCert(fullPath)
		if err != nil {
			t.Errorf("LoadCert failed due to error %q", err)
		}
		if loaded.Host != expected.Host {
			t.Errorf("Host value %q does not match expected %q", loaded.Host, expected.Host)
		}
		if !(bytes.Equal(loaded.Body, expected.Body)) {
			t.Errorf("Body %q does not match expected %q", loaded.Body, expected.Body)
		}
	}
}
