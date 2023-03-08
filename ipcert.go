package ipcert

import (
	"fmt"
	"net"
)

const (
	VerifyURLPrefix string = "/.well-known/pki-validation/"
)

// https://help.zerossl.com/hc/en-us/articles/360060119973-Is-It-Possible-To-Generate-a-SSL-Certificate-for-an-IP-Address-
//
// need ZeroSSL api key (paid subscription)
//
// ipv4 cert only
//
// ! please use mutex to prevent from conflict on port 80
func GetIpCert(ip string, key string) (*CertPack, error) {
	listener80, err := net.Listen("tcp", ":80")
	if err != nil {
		return nil, err
	}
	defer listener80.Close()

	ipbyte := net.ParseIP(ip)
	if ipbyte == nil || ipbyte.To4() == nil {
		return nil, fmt.Errorf("%s is not a valid IPv4 address", ip)
	}
	if isReversed(ipbyte) {
		return nil, fmt.Errorf("%s is a reversed IP", ip)
	}

	c, err := newCertPack(ip)
	if err != nil {
		return nil, err
	}

	qid, fname, fcontent, err := createReq(key, ip, c.CertificateRequest)
	if err != nil {
		return nil, err
	}
	openVerifyServer(fname, fcontent, listener80)
	err = verifyReq(key, qid, fname, fcontent)
	if err != nil {
		return nil, err
	}
	cert, cab, err := downloadReq(key, qid)
	if err != nil {
		return nil, err
	}
	c.Certificate = cert
	c.CABundle = cab

	return c, nil
}
