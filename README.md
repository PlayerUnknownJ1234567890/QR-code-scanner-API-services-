# QR-code-scanners detecting malicious QR code
*Before using the QR code scanner, please download all of the files (confirmed_malicious_urls.txt, high_risk_url.txt, legit_urls.txt, malicious_urls.txt, phishing_url_openphish.txt, suspicious_urls.txt, QR_Scanner (IPQualityScore).py, and QR-scanner(VirusTotal).py) before using it. To execute them please locate them in the same folder then install the latest python version into your device to execute them.
There are 2 QR code scanners, each using different API services which are IPQualityScore and VirusTotal to detect malicious URL.

The QR code scanner using the API for:
IPQualityScore -> QR_Scanner (IPQualityScore).py
VirusTotal -> QR-scanner(VirusTotal).py

QR-scanner(VirusTotal).py requires phishing_url_openphish.txt as phishing_url_openphish.txt acts as the dataset where it stores all phishing websites from openphish.

QR-scanner (IPQualityScore).py provides risk score on the scanned QR code. The higher the risk score the higher the confirmation of malware existing within the QR code. 

Currently both scanners are without their API keys, in order to retrieve your own API key:
1) VirusTotal
Create a VirusTotal account by going to this URL (https://www.virustotal.com/gui/join-us) and after your account has been created, proceed to login and navigate to the API documentation page (https://docs.virustotal.com/docs/api-overview). Follow this instrcution to get your own API key.
   
2) IPQualityScore
Create a IPQualityScore account by going this URL (https://www.ipqualityscore.com/create-account) follow by verifying your email when completing the registration. Once your email address is verified, log in to your IPQualityScore account using the credentials you provided during sign-up. After logging in, navigate to the dashboard or API settings section of your account. This is typically where you can manage your API keys and settings. In the API settings section, you should find an option to generate a new API key. Click on this option, and a new API key will be generated for you. Once the API key is generated, it will typically be displayed on the screen. Copy the API key to your clipboard or save it in a secure location.   

This project is just in the beginning phase, improvements will be made in the future.
