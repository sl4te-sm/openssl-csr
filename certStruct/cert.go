// cert.go
package main

import "errors"

type CertFile string

func NewCertFile(t string) (CertFile, error) {
    if !(t == "csr" || t == "cert") {
        return "", errors.New("Must be either a csr or a cert")
    }
    return CertFile(t), nil
}

type Cert struct {
    Host string
    Body []byte
    Type CertFile
}

func (c *Cert) get() string {
    var pathRoot string = "/root/ca/intermediate"
    if c.Type == "csr" {
        return (pathRoot + "/csr/" + c.Host + ".csr.pem")
    } else {
        return (pathRoot + "/certs/" + c.Host + ".cert.pem") 
    }
}
