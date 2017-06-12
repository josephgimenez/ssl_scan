package certificateutils

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
	"errors"
)

var (
	hostnameEmptyError = errors.New("hostname empty")
)

type ResultError struct {
	Res CertificateDetails
	Err error
}

type CertificateDetails struct {
	DaysUntilExpiration int
	IssuerName          string
	SubjectName         string
	SerialNumber        string
	ExpiringSoon        bool
	Expired             bool
	Hostname            string
	TimeTaken           time.Duration
	ExpirationDate      string
}

func (cd CertificateDetails) String() string {
	return fmt.Sprintf(
		"Subject Name: %s\nIssuer: %s\nExpiration date: %s\nRequest Time: %v\n",
		cd.SubjectName,
		cd.IssuerName,
		cd.ExpirationDate,
		cd.TimeTaken,
	)
}

func GetCertificateDetails(hostname string, connectionTimeout int) (CertificateDetails, error) {
	currentTime := time.Now()
	var certDetails CertificateDetails

	if hostname == "" {
		return CertificateDetails{}, hostnameEmptyError
	}

	if !strings.Contains(hostname, ":") {
		hostname = fmt.Sprintf("%s:443", hostname)
	}

	// Establish a new TCP connection to hostname
	// Ignore invalid certificates, so we can scan via IP addresses or hostnames
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second * time.Duration(connectionTimeout)},
		"tcp",
		hostname,
		&tls.Config{InsecureSkipVerify: true})

	if err != nil {
		return CertificateDetails{}, fmt.Errorf("Connection error: %v", err)
	}

	if handshakeCompleted := conn.ConnectionState().HandshakeComplete; !handshakeCompleted {
		return CertificateDetails{}, fmt.Errorf("TLS Handshake failed to hostname %s.", hostname)
	}

	defer conn.Close()

	// Loop through each certificate peer and determine certificate details for non-CA certificate
	for _, cert := range conn.ConnectionState().PeerCertificates {

		if cert.IsCA {
			continue
		}

		daysUntilExpiration := int(cert.NotAfter.Sub(currentTime).Hours() / 24)
		subjectName := cert.Subject.Names[len(cert.Subject.Names)-1].Value.(string)
		issuerName := cert.Issuer.Names[len(cert.Issuer.Names)-1].Value.(string)
		serialNumber := cert.SerialNumber.String()
		elapsed := time.Since(currentTime)

		certDetails = CertificateDetails{
			DaysUntilExpiration: daysUntilExpiration,
			SubjectName:         subjectName,
			IssuerName:          issuerName,
			SerialNumber:        serialNumber,
			Hostname:            hostname,
			TimeTaken:           elapsed,
			ExpirationDate:      cert.NotAfter.Format(time.UnixDate),
		}
		break
	}

	return certDetails, nil
}

func CheckExpirationStatus(cd *CertificateDetails, expirationDaysThreshold int) {
	if cd.DaysUntilExpiration < 0 {
		cd.Expired = true
	} else if cd.DaysUntilExpiration < expirationDaysThreshold {
		cd.ExpiringSoon = true
	}
}
