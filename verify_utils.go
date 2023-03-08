package ipcert

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// create a request of issueing a IP certificate.
// return: requested issue id, file name and content for the verify, or error.
// ref: https://zerossl.com/documentation/api/create-certificate/
func createReq(key, ip, csrPem string) (string, string, string, error) {
	client := &http.Client{}

	data := url.Values{}
	data.Set("certificate_domains", ip)
	data.Set("certificate_csr", csrPem)

	req, err := http.NewRequest("POST",
		"https://api.zerossl.com/certificates?access_key="+key,
		strings.NewReader(data.Encode()))
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer resp.Body.Close()

	var res map[string]any
	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return "", "", "", err
	}

	if res["success"] == false {
		return "", "", "", outputErr(res["error"].(map[string]any))
	}

	var fname, fcontent string
	if fnameStr, ok := getValue(res, "validation", "other_methods", ip, "file_validation_url_http").(string); !ok {
		return "", "", "", fmt.Errorf("cannot parse response")
	} else if len(fnameStr) < (len(VerifyURLPrefix) + 4) {
		return "", "", "", fmt.Errorf("cannot parse response")
	} else {
		fname = fnameStr
	}
	if u, err := url.Parse(fname); err != nil {
		return "", "", "", fmt.Errorf("cannot parse response")
	} else {
		if len(u.Path) < (len(VerifyURLPrefix) + 4) {
			return "", "", "", fmt.Errorf("cannot parse response")
		}
		fname = u.Path[len(VerifyURLPrefix):]
	}
	if fcontentArr, ok := getValue(res, "validation", "other_methods", ip, "file_validation_content").([]any); !ok {
		return "", "", "", fmt.Errorf("cannot parse response")
	} else {
		for _, v := range fcontentArr {
			fcontent += fmt.Sprintf("%s\n", v)
		}
		fcontent = strings.TrimRight(fcontent, "\n")
	}
	return res["id"].(string), fname, fcontent, err
}

// ref: https://zerossl.com/documentation/api/verify-domains/
func verifyReq(key, qid, fname, fcontent string) error {
	data := url.Values{}
	data.Set("validation_method", "HTTP_CSR_HASH")

	resp, err := http.Post(
		fmt.Sprintf("https://api.zerossl.com/certificates/%s/challenges?access_key=%s", qid, key),
		"application/x-www-form-urlencoded",
		strings.NewReader(data.Encode()),
	)
	if err != nil {
		return err
	}

	var res map[string]any
	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return err
	}

	if res["success"] == false {
		return outputErr(res["error"].(map[string]any))
	}
	return nil
}

// return: the certificate and ca bundle in pem format, or error.
// return ZeroSSLError for waiting without ready cert after 600 seconds,
// which indicates zerossl's service disruption.
// ref: https://zerossl.com/documentation/api/download-certificate-inline/
func downloadReq(key, qid string) (string, string, error) {
	// wait and check if the certificate issued
	certOk := false
	for i := 0; i < 30; i++ {
		ok, err := checkReq(key, qid)
		if err != nil {
			return "", "", err
		}
		if ok {
			certOk = true
			break
		}
		time.Sleep(20 * time.Second)
	}

	if !certOk {
		return "", "", &ZeroSSLError{}
	}
	resp, err := http.Get(fmt.Sprintf("https://api.zerossl.com/certificates/%s/download/return?access_key=%s", qid, key))
	if err != nil {
		return "", "", err
	}
	var res map[string]any
	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return "", "", err
	}

	if res["success"] == false {
		return "", "", outputErr(res["error"].(map[string]any))
	}

	return res["certificate.crt"].(string), res["ca_bundle.crt"].(string), nil
}

// ref: https://zerossl.com/documentation/api/get-certificate/
func checkReq(key, qid string) (bool, error) {
	resp, err := http.Get(fmt.Sprintf("https://api.zerossl.com/certificates/%s?access_key=%s", qid, key))
	if err != nil {
		return false, err
	}
	var res map[string]any
	err = json.NewDecoder(resp.Body).Decode(&res)
	if err != nil {
		return false, err
	}

	if res["success"] == false {
		return false, outputErr(res["error"].(map[string]any))
	}
	if res["status"] == "issued" {
		return true, nil
	}
	return false, nil
}

// format and output ZeroSSL's error info in json
func outputErr(errinfo map[string]any) error {
	return fmt.Errorf("[ZeroSSL ERR %v] %v: %v%v", errinfo["code"], errinfo["type"], errinfo["info"], errinfo["details"])
}

// get string for a map[string]any chain.
// args are the map with a chain of keys in order.
// return nil if the target value does not exist.
func getValue(m map[string]any, keys ...string) any {
	var value any
	var ok bool
	value = m
	for _, key := range keys {
		if _, ok = value.(map[string]any); !ok {
			return nil
		}
		if value, ok = value.(map[string]any)[key]; !ok {
			return nil
		}
	}
	return value
}
