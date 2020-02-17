package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/go-ntlmssp"

	"github.com/micrictor/mdns"
)

func main() {
	var queryName string
	var userName string
	var authMethod string
	var interval int
	var intervalDeviation int

	flag.StringVar(&queryName, "query-target", "wpad", "The hostname to query with the .local TLD.")
	flag.StringVar(&userName, "username", "LocalAdmin", "The username for the fed credential.")
	flag.StringVar(&authMethod, "auth-method", "basic", "Web authentication method to send the credential with. Supported: NTLMSSP, Basic")
	flag.IntVar(&interval, "interval", 5, "Interval between requests, in minutes.")
	flag.IntVar(&intervalDeviation, "interval-deviation", 45, "Tolerable deviation from the specified interval, in seconds.")

	flag.Parse()

	fmt.Printf("Querying for %s every %d minutes +- %d seconds, feeding a false credential for %s.\n", queryName, interval, intervalDeviation, userName)

	for {
		resultChan := make(chan *mdns.ServiceEntry, 1)

		defer close(resultChan)
		mdns.Lookup(queryName, resultChan)

		go func() {
			for entry := range resultChan {
				if entry.AddrV4 != nil {
					doAuth(strings.ToLower(authMethod), userName, entry.AddrV4, queryName)
				}
			}
		}()

		deviation := rand.Intn(intervalDeviation)
		time.Sleep(time.Duration(interval)*time.Minute + time.Duration(deviation)*time.Second)
	}
}

func generateRandomString(length int) string {
	var randString string
	rand.Seed(time.Now().Unix())

	for i := 0; i < length; i++ {
		randInt := rand.Intn(92)
		randString = randString + string(rune(33+randInt))
	}
	return randString
}

func doAuth(authMethod string, userName string, ipAddr net.IP, hostName string) {

	// Generate a password that meets the minimum reccommended requirements
	password := generateRandomString(8)
	fmt.Printf("Trying to send credential %s:%s to IP %s via %s authentication\n",
		userName, password, ipAddr.String(), authMethod)

	switch authMethod {
	case "basic":
		client := &http.Client{}

		req, _ := http.NewRequest("GET", "http://"+ipAddr.String(), nil)
		req.SetBasicAuth(userName, password)
		req.Header.Set("UserAgent", "WinHttp-Autoproxy-Service/5.1")
		req.Host = hostName + ".local"

		_, err := client.Do(req)
		if err == nil {
			fmt.Println("Successfully sent credential!")
		} else {
			fmt.Printf("Send failed: %v\n", err)
		}
	case "ntlmssp":
		client := &http.Client{
			Transport: ntlmssp.Negotiator{
				RoundTripper: &http.Transport{},
			},
		}

		req, _ := http.NewRequest("GET", "http://"+ipAddr.String(), nil)
		req.SetBasicAuth(userName, password)
		req.Header.Set("UserAgent", "WinHttp-Autoproxy-Service/5.1")
		req.Host = hostName + ".local"

		_, err := client.Do(req)
		if err == nil {
			fmt.Println("Successfully sent credential!")
		} else {
			fmt.Printf("Send failed: %v\n", err)
		}
	default:
		log.Fatalf("Invalid authentication method specified! %s", authMethod)
	}
}
