import cv2
from pyzbar.pyzbar import decode
import numpy as np
import requests
import json

# Phishing URL dataset from openphish
PHISHING_URLS_FILE = 'phishing_url_openphish.txt'

# Create txt file to store secure URL and malicious URL
LEGIT_URLS_FILE = 'legit_urls.txt'
MALICIOUS_URLS_FILE = 'malicious_urls.txt'

# Using VirusTotal API and URL
VIRUSTOTAL_API_KEY = '499cdc7e26e065576569604857149f86e92653792abb76587f8bf07814f86858'  # VirusTotal API key
VIRUSTOTAL_API_URL = 'https://www.virustotal.com/vtapi/v2/url/report'

# Load openphish dataset
def load_phishing_urls(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file]
    
# Check if the URL matches any known phishing URLs
def is_phishing_url(url, phishing_urls):
    return any(url.startswith(phishing_url) for phishing_url in phishing_urls)

# This function checks the reputation of the URL by using VirusTotal API
def check_url_virustotal(url, api_key):
    params = {'apikey': api_key, 'resource': url}
    response = requests.get(VIRUSTOTAL_API_URL, params=params)
    result = response.json()

    try:
        response.raise_for_status()  # Check for HTTP errors
        result = response.json()
    except requests.exceptions.HTTPError as errh:
        print("HTTP Error:", errh)
        return False
    except requests.exceptions.RequestException as err:
        print("Error:", err)
        return False
    except json.decoder.JSONDecodeError:
        print("Error decoding JSON response from VirusTotal.")
        return False

    if 'response_code' in result and result['response_code'] == 1:
        # URL is in the VirusTotal database
        return result['positives'] > 0
    else:
        # URL not found in the database or other error
        return False

# Continuously capture video frames from the webcam and to detect QR code within each frame
def scan_qr_code():
    
    cap = cv2.VideoCapture(0)  # Open the default camera (0)
    
    # Load phishing URLs from the specified file
    phishing_urls = load_phishing_urls(PHISHING_URLS_FILE)

    while True:
        ret, frame = cap.read()

        # Decode QR codes
        decoded_objects = decode(frame)

        for obj in decoded_objects:
            # Extract QR code data
            data = obj.data.decode('utf-8')

            # Draw a rectangle around the QR code
            points = obj.polygon
            if len(points) == 4:
                pts = np.array([(points[j].x, points[j].y) for j in range(4)], dtype=int)

                # Change rectangle color based on the secureness of the URL
                rectangle_color = (0, 255, 0)  # Green for safe or legit URL
                if (is_phishing_url(data, phishing_urls) or
                    check_url_virustotal(data, VIRUSTOTAL_API_KEY)):
                    rectangle_color = (0, 0, 255)  # Red for phishing URLs
                    
                    with open(MALICIOUS_URLS_FILE, 'a') as malicious_file:
                        malicious_file.write(data + '\n')
                
                else:
                    # Write the legit URL to a file
                    with open(LEGIT_URLS_FILE, 'a') as legit_file:
                        legit_file.write(data + '\n')

                 # Actually draws the rectangle based on the number of points, closing the gap of the polylines, colour of the rectangle, and the thickness level of the recetangle
                cv2.polylines(frame, [pts], isClosed=True, color=rectangle_color, thickness=2)

                # Display the QR code data
                cv2.putText(frame, data, (pts[0][0], pts[0][1] - 10),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.5, rectangle_color, 2)

                # Save the entire frame as a screenshot
                cv2.imwrite('screenshot.png', frame)

                # Display results of the safetiness of the URL
                if is_phishing_url(data, phishing_urls):
                    print("Warning: Malicious URL detected!")
                    print(data)
                elif check_url_virustotal(data, VIRUSTOTAL_API_KEY):
                    print("Warning: Malicious URL detected (VirusTotal)!")
                    print(data)
                else:
                    print("This is a safe URL.")
                    print(data)

        # Display the frame
        cv2.imshow('QR Code Scanner', frame)

        # Break the loop if 'q' key is pressed
        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    # Release the camera and close the window
    cap.release()
    cv2.destroyAllWindows()

if __name__ == "__main__":
    scan_qr_code()
