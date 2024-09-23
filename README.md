# VulnerabilityScan

VulnerabilityScan is a Java based port scanner that identifies open ports on a machine and, using a local vulnerability database, checks for potential vulnerabilities by matching service banners with these known vulnerabilities. The program is designed to educate people on the need for securing open network ports against malicious users who can exploit these ports.

PortScanner.java is the Java file that contains the methods for scanning ports, grabbing service banners, and matching vulnerabilities.
scan_results.txt contains the output from scanning the machine, including open ports, service banners, and identified vulnerabilities.
vulnerabilities.csv is the local database file that contains the service names, versions, CVE IDs and descriptions of known vulnerabilities. This file must be manually updated, unless I import an external library.
