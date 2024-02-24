# QR-code-scanner-API-services-
*Before using the QR code scanner, please download all of the files (confirmed_malicious_urls.txt, high_risk_url.txt, legit_urls.txt, malicious_urls.txt, phishing_url_openphish.txt, suspicious_urls.txt, QR_Scanner (IPQualityScore).py, and QR-scanner(VirusTotal).py) before using it. To execute them please locate them in the same folder then install the latest python version into your device to execute them.
There are 2 QR code scanners, each using different API services which are IPQualityScore and VirusTotal to detect malicious URL.

The QR code scanner using the API for:
IPQualityScore -> QR_Scanner (IPQualityScore).py
VirusTotal -> QR-scanner(VirusTotal).py

QR-scanner(VirusTotal).py requires phishing_url_openphish.txt as phishing_url_openphish.txt acts as the dataset where it stores all phishing websites from openphish.

QR-scanner (IPQualityScore).py provides risk score on the scanned QR code. The higher the risk score the higher the confirmation of malware existing within the QR code. 

This project is just the beginning, improvements will be made in the future.
