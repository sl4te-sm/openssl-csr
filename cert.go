// cert.go
package main

import (
	"fmt"
)

type Cert struct {
    Host, Type string
    Body []byte
}

func (c *Cert) get() (string, error) {
    var pathRoot string = "/root/ca/intermediate"
    if c.Type == "csr" {
        return (pathRoot + "/csr/" + c.Host + ".csr.pem"), nil
    } else if c.Type == "cert" {
        return (pathRoot + "/certs/" + c.Host + ".cert.pem"), nil
    } else {
        return "", fmt.Errorf("cert: invalid type '%q'; must be csr or cert", c.Type)
    }
}
