package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"ssl_scan/certificateutils"
	"sync"
	"time"
)

type flags struct {
	notificationThreshold int
	connectionTimeout     int
	remoteSite            string
	remoteSiteFile        string
	publicCertificate     string
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
	flag.StringVar(&cliArgs.remoteSiteFile, "listfile", "", "specify filename with hostnames to scan")
	flag.StringVar(&cliArgs.publicCertificate, "certfile", "", "specify public certificate file to scan")
	flag.Parse()

	return cliArgs
}

func scanSitesFile(flags flags,
	certDetailsChannel chan certificateutils.CertificateDetails,
	errorsChannel chan error) (chan certificateutils.CertificateDetails, chan error) {

	var wg sync.WaitGroup

	hostnamesFileBytes := readFile(flags.remoteSiteFile)
	hostnames := bytes.Split(hostnamesFileBytes, []byte("\n"))
	numberOfHostnames := len(hostnames) - 1
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
					errorsChannel <- fmt.Errorf("> %s: %s", hostname, err)
				} else {
					certDetailsChannel <- res
				}
			}()
		}
	}
	wg.Wait()

	return certDetailsChannel, errorsChannel
}

func readCertificateFile(flags flags) {
	certsDetails, err := certificateutils.ReadCertificateDetailsFromFile(flags.publicCertificate, "")
	if err != nil {
		log.Fatalf(err.Error())
	}

	fmt.Printf("Found %d certificate(s) inside file: %s:\n\n", len(certsDetails), flags.publicCertificate)
	for _, certDetails := range certsDetails {
		fmt.Printf("%v\n", certDetails)
	}

	os.Exit(0)
}

func scanHost(flags flags,
	certDetailsChannel chan certificateutils.CertificateDetails,
	errorsChannel chan error) {

	res, err := certificateutils.GetCertificateDetails(flags.remoteSite, flags.connectionTimeout)
	if err != nil {
		errorsChannel <- err
	} else {
		certDetailsChannel <- res
	}
}

func updateSitesAndCounts(count map[string]int, sites map[string]bool, certDetails certificateutils.CertificateDetails) {
	if _, ok := count[certDetails.SubjectName]; !ok {
		count[certDetails.SubjectName] = 1
	} else {
		count[certDetails.SubjectName]++
	}

	if !sites[certDetails.Hostname] {
		sites[certDetails.Hostname] = true
	}
}

func printCertificateStats(count map[string]int, sites map[string]bool) {
	for cert, instanceCount := range count {
		fmt.Printf("Subject name: %s -- Instances found: %d\n", cert, instanceCount)
	}

	for hostname := range sites {
		fmt.Printf("> %s\n", hostname)
	}
	fmt.Println("")
}

func main() {
	// Will hold our arguments that can be passed in via cli
	flags := setupArgumentParsing()
	var certDetailsChannel chan certificateutils.CertificateDetails
	var errorsChannel chan error

	expiringSoonCount := make(map[string]int)
	expiringSoonSites := make(map[string]bool)
	expiredCount := make(map[string]int)
	expiredSites := make(map[string]bool)

	okCount := make(map[string]int)
	okSites := make(map[string]bool)

	certDetailsChannel = make(chan certificateutils.CertificateDetails, 1)
	errorsChannel = make(chan error, 1)

	startTime := time.Now()

	fmt.Println("Configured Options...")
	fmt.Printf("SSL expiration notification threshold set at: %d days\n", flags.notificationThreshold)
	fmt.Printf("Connection timeout set to: %d seconds\n\n", flags.connectionTimeout)

	if flags.remoteSiteFile != "" {
		certDetailsChannel, errorsChannel = scanSitesFile(flags, certDetailsChannel, errorsChannel)
	} else if flags.publicCertificate != "" {
		readCertificateFile(flags)
	} else {
		scanHost(flags, certDetailsChannel, errorsChannel)
	}

	for i, certDetailsInQueue := 0, len(certDetailsChannel); i < certDetailsInQueue; i++ {
		certDetails := <-certDetailsChannel
		certificateutils.CheckExpirationStatus(&certDetails, flags.notificationThreshold)

		if certDetails.Expired {
			fmt.Printf("* Certificate status: expired\n%s\n", certDetails)
			updateSitesAndCounts(expiredCount, expiredSites, certDetails)
		} else if certDetails.ExpiringSoon {
			fmt.Printf(
				"* %s: certificate expiring in %d days\n%s\n",
				certDetails.Hostname,
				certDetails.DaysUntilExpiration,
				certDetails)
			updateSitesAndCounts(expiringSoonCount, expiringSoonSites, certDetails)

		} else {
			fmt.Printf("* %s: Certificate status: OK!\n%s\n",
				certDetails.Hostname,
				certDetails)
			updateSitesAndCounts(okCount, okSites, certDetails)
		}
	}

	fmt.Println("------------------")
	fmt.Printf("Certificate summary\n\n")

	if len(errorsChannel) > 0 {
		fmt.Printf("There were %d error(s):\n", len(errorsChannel))
		for i, errorsInChannel := 0, len(errorsChannel); i < errorsInChannel; i++ {
			fmt.Printf("%s\n", <-errorsChannel)
		}
		fmt.Printf("\n")
	}

	if len(expiredCount) > 0 {
		fmt.Printf("There are %d certificates already expired:\n", len(expiredCount))
		printCertificateStats(expiredCount, expiredSites)
	}

	if len(expiringSoonCount) > 0 {
		fmt.Printf("There are %d certificates expiring soon:\n", len(expiringSoonCount))
		printCertificateStats(expiringSoonCount, expiringSoonSites)
	}

	if len(okCount) > 0 {
		fmt.Printf("There are %d OK certificates\n", len(okCount))
		printCertificateStats(okCount, okSites)
	}

	fmt.Printf("Time taken to complete all certificate scans: %v\n", time.Since(startTime))

}
