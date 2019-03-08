package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/antchfx/htmlquery"
)

var wg sync.WaitGroup

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func crtsh(domain string, c chan []string) {
	wg.Add(1)
	defer wg.Done()

	subdomainsList := make([]string, 0)
	doc, err := htmlquery.LoadURL("https://crt.sh/?q=%25." + domain)
	checkErr(err)
	list := htmlquery.Find(doc, "/html/body/table[2]/tbody/tr/td/table/tbody/tr[*]/td[5]")
	for _, n := range list {
		subdomain := htmlquery.InnerText(n)
		subdomain = strings.Replace(subdomain, "*.", "", -1)
		subdomainsList = append(subdomainsList, subdomain)
	}
	c <- subdomainsList
}

func virustotal(domain string, c chan []string) {
	wg.Add(1)
	defer wg.Done()

	// Define a multi-layer struct to extract subdomain info from JSON
	type Info struct {
		Subdomain []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	var info Info
	subdomains := make([]string, 0)

	resp, err := http.Get("https://www.virustotal.com/ui/domains/" + domain + "/subdomains?limit=40")
	checkErr(err)

	err = json.NewDecoder(resp.Body).Decode(&info)
	checkErr(err)

	for _, subdomain := range info.Subdomain {
		subdomains = append(subdomains, subdomain.ID)
	}
	c <- subdomains
}

func main() {
	c := make(chan []string)
	subdomainsMap := make(map[string]int, 0)

	if len(os.Args) != 2 {
		fmt.Println("Usage: subscan.go [domain]")
		return
	}
	domain := os.Args[1]

	go virustotal(domain, c)
	go crtsh(domain, c)

	wg.Wait()

	// As channel has more than one subdomain arrays, iterate over all of them and extract each

	for _, subdomain := range <-c {
		subdomainsMap[subdomain] = 1
	}
	for _, subdomain := range <-c {
		subdomainsMap[subdomain] = 1
	}

	for subdomain := range subdomainsMap {
		fmt.Println(subdomain)
	}
}
