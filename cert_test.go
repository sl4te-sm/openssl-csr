package main

import "testing"

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
    {testCerts[0], "/root/ca/intermediate/csr/webserver.domain.csr.pem"},
    {testCerts[1], "/root/ca/intermediate/certs/appserver.domain.cert.pem"},
    {testCerts[2], ""},
    {testCerts[3], ""},
}

// Cert.get() should output a string containing the filepath
// /root/ca/intermediate/${Cert.Type}s/${Cert.Host}.${Cert.Type}.pem
func TestGet(t *testing.T) {
    for _, test := range getTests {
        output, _ := test.cert.get()
        if output != test.expected {
            t.Errorf("Output %q not equal to expected %q", output, test.expected)
        }
    }
}
