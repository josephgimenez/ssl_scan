# ssl_scan

Scan https sites to determine when an SSL certificate is set to expire.  

## Building
```
go build
```

## Running

### Scan individual host:
`./ssl_scan -hostname yahoo.com`

```
╰─ ./ssl_scan -hostname yahoo.com                                              
Configured Options...
SSL expiration notification threshold set at: 60 days
Connection timeout set to: 10 seconds

* Certificate status: OK!
Subject Name: www.yahoo.com
Issuer: Symantec Class 3 Secure Server CA - G4
Expiration date: Mon Oct 30 23:59:59 UTC 2017
Request Time: 375.783575ms

------------------
Certificate summary

There are 1 OK certificates
Subject name: www.yahoo.com -- Instances found: 1
Time taken to complete all certificate scans: 376.108547ms
```

### Scanning a list of URLs within a file:

`./ssl_scan -file urls.txt`

```
Configured Options...
SSL expiration notification threshold set at: 60 days
Connection timeout set to: 10 seconds

* site.domain.com:443 certificate expiring in 29 days
Subject Name: *.domain.com
Issuer: Starfield Secure Certificate Authority - G2
Expiration date: Wed Jul 12 16:12:34 UTC 2017
Request Time: 1.401266882s

[...]

Certificate summary

There are 1 certificates expiring soon
Subject name: *.domain.com -- Instances found: 13

Time taken to complete all certificate scans: 10.05354835s
```
