package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"ssl_scan/certificateutils"
	"sync"
	"time"
)

type flags struct {
	notificationThreshold int
	connectionTimeout     int
	remoteSite            string
	remoteSiteFile        string
}

func readFile(fileName string) []byte {
	hostnamesFileBytes, err := ioutil.ReadFile(fileName)

	if err != nil {
		log.Fatalf("Error reading file: %s, err: %v", fileName, err)
	}

	return hostnamesFileBytes
}

func setupArgumentParsing() flags {
	var cliArgs flags

	flag.IntVar(&cliArgs.notificationThreshold, "days", 60, "threshold for SSL certificate 'Not After' date to alert on")
	flag.IntVar(&cliArgs.connectionTimeout, "timeout", 10, "number of seconds to wait for tcp connection to hostname")
	flag.StringVar(&cliArgs.remoteSite, "hostname", "", "specify hostname:port you would like to test")
	flag.StringVar(&cliArgs.remoteSiteFile, "file", "", "specify filename with hostnames to scan")
	flag.Parse()

	return cliArgs
}

func main() {
	// Will hold our arguments that can be passed in via cli
	flags := setupArgumentParsing()
	var certDetailsChannel chan certificateutils.CertificateDetails
	var errorsChannel chan error
	var numberOfHostnames int

	expiringSoonCount := make(map[string]int)
	expiredCount := make(map[string]int)
	okCount := make(map[string]int)

	var wg sync.WaitGroup

	startTime := time.Now()

	fmt.Println("Configured Options...")
	fmt.Printf("SSL expiration notification threshold set at: %d days\n", flags.notificationThreshold)
	fmt.Printf("Connection timeout set to: %d seconds\n\n", flags.connectionTimeout)

	if flags.remoteSiteFile != "" {
		hostnamesFileBytes := readFile(flags.remoteSiteFile)
		hostnames := bytes.Split(hostnamesFileBytes, []byte("\n"))
		numberOfHostnames = len(hostnames) - 1
		certDetailsChannel = make(chan certificateutils.CertificateDetails, numberOfHostnames)
		errorsChannel = make(chan error, numberOfHostnames)

		for _, hostname := range hostnames {
			hostname := string(hostname)
			if hostname != "" {
				wg.Add(1)
				go func() {
					defer wg.Done()
					res, err := certificateutils.GetCertificateDetails(hostname, flags.connectionTimeout)
					if err != nil {
						errorsChannel <- err
					} else {
						certDetailsChannel <- res
					}
				}()
			}
		}
		wg.Wait()

	} else {
		certDetailsChannel = make(chan certificateutils.CertificateDetails, 1)
		errorsChannel = make(chan error, 1)
		res, err := certificateutils.GetCertificateDetails(flags.remoteSite, flags.connectionTimeout)
		if err != nil {
			errorsChannel <- err
		} else {
			certDetailsChannel <- res
		}
	}

	if len(errorsChannel) > 0 {
		fmt.Printf("\n** %d error(s) occurred\n", len(errorsChannel))
		for i, errorsInChannel := 0, len(errorsChannel); i < errorsInChannel; i++ {
			fmt.Printf("%s\n", <-errorsChannel)
		}
		fmt.Printf("\n")
	}

	for i, certDetailsInQueue := 0, len(certDetailsChannel); i < certDetailsInQueue; i++ {
		certDetails := <-certDetailsChannel
		certificateutils.CheckExpirationStatus(&certDetails, flags.notificationThreshold)

		if certDetails.Expired {
			fmt.Printf("* Certificate status: expired\n%s\n", certDetails)
			if _, ok := expiredCount[certDetails.SubjectName]; !ok {
				expiredCount[certDetails.SubjectName] = 1
			} else {
				expiredCount[certDetails.SubjectName]++
			}

		} else if certDetails.ExpiringSoon {
			fmt.Printf(
				"* %s certificate expiring in %d days\n%s\n",
				certDetails.Hostname,
				certDetails.DaysUntilExpiration,
				certDetails)
			if _, ok := expiringSoonCount[certDetails.SubjectName]; !ok {
				expiringSoonCount[certDetails.SubjectName] = 1
			} else {
				expiringSoonCount[certDetails.SubjectName]++
			}
		} else {
			fmt.Printf("* Certificate status: OK!\n%s\n", certDetails)
			if _, ok := okCount[certDetails.SubjectName]; !ok {
				okCount[certDetails.SubjectName] = 1
			} else {
				okCount[certDetails.SubjectName]++
			}
		}
	}

	fmt.Println("------------------")
	fmt.Printf("Certificate summary\n\n")

	if len(expiringSoonCount) > 0 {
		fmt.Printf("There are %d certificates expiring soon\n", len(expiringSoonCount))
		for cert, count := range expiringSoonCount {
			fmt.Printf("Subject name: %s -- Instances found: %d\n", cert, count)
		}
		fmt.Println("")
	}

	if len(expiredCount) > 0 {
		fmt.Printf("There are %d certificates already expired\n", len(expiredCount))
		for cert, count := range expiredCount {
			fmt.Printf("Subject name: %s -- Instances found: %d\n", cert, count)
		}
		fmt.Println("")
	}

	if len(okCount) > 0 {
		fmt.Printf("There are %d OK certificates\n", len(okCount))
		for cert, count := range okCount {
			fmt.Printf("Subject name: %s -- Instances found: %d\n", cert, count)
		}
	}

	fmt.Printf("Time taken to complete all certificate scans: %v\n", time.Since(startTime))

}
