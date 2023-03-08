package main

import (
	"flag"
	"fmt"
	"sync"

	ipcert "github.com/lingkaix/zero-ip-cert"
)

func main() {
	ip := flag.String("ip", "", "IP which requires a TLS certificate")
	key := flag.String("key", "", "ZeroSSL api key")
	flag.Parse()
	if *ip == "" || *key == "" {
		fmt.Println("Please specify ip and/or key.")
		return
	}

	var mu sync.Mutex
	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		mu.Lock()
		fmt.Println("Generating the FIRST cert ...")
		c, err := ipcert.GetIpCert(*ip, *key)
		if err != nil {
			fmt.Println("Error when generating FIRST cert:")
			fmt.Println(err.Error())
		} else {
			fmt.Println("FIRST cert is:")
			fmt.Println(c.Certificate)
		}
		wg.Done()
		mu.Unlock()
	}()

	go func() {
		mu.Lock()
		fmt.Println("Generating the SECOND cert ...")
		c, err := ipcert.GetIpCert(*ip, *key)
		if err != nil {
			fmt.Println("Error when generating SECOND cert:")
			fmt.Println(err.Error())
		} else {
			fmt.Println("SECOND cert is:")
			fmt.Println(c.Certificate)
		}
		wg.Done()
		mu.Unlock()
	}()

	fmt.Println("Waiting while doing sth else...")

	wg.Wait()
}
