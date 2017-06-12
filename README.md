# ssl_scan

Scan https sites to determine when an SSL certificate is set to expire.  

## Running

Scanning a list of URLs within a file:

`./ssl_scan -file urls.txt`

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

--------
