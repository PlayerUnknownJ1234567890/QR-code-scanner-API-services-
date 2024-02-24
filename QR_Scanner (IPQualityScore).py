import cv2
from pyzbar.pyzbar import decode
import numpy as np
import requests

IPQS_API_KEY = 'pQzygEVMvcoPW8R2uP4Hl3B70MMTU9HB'
MALICIOUS_URLS_FILE = 'malicious_urls.txt'
LEGIT_URLS_FILE = 'legit_urls.txt'
SUSPICIOUS_URLS_FILE = 'suspicious_urls.txt'
HIGH_RISK_URLS_FILE = 'high_risk_urls.txt'
CONFIRMED_MALICIOUS_URLS_FILE = 'confirmed_malicious_urls.txt'

# This is to use IPQualityScore API to obtain information from the URL and use try catch function to check for any HTTP errors
def check_url_ipqualityscore(url, api_key):
    params = {'url': url, 'strictness': 1, 'user_agent': 'curl/7.64.1', 'api_key': api_key}
    response = requests.get('https://www.ipqualityscore.com/api/json/url/' + api_key, params=params)

    try:
        response.raise_for_status()  # Check for HTTP errors
        result = response.json()
    except requests.exceptions.HTTPError as errh:
        print("HTTP Error:", errh)
        return False
    except requests.exceptions.RequestException as err:
        print("Error:", err)
        return False
    except ValueError:
        print("Error decoding JSON response from IPQualityScore.")
        return False

    return result

def print_risk_score_table():
    print("Risk Score Interpretation:")
    print("  ---------------------------------------------------------------------------------------------- ")
    print("| Risk Score Range  | Interpretation                                                            |")
    print("|-------------------|---------------------------------------------------------------------------|")
    print("| 0 - 30            | Clean (Green Box)                                                         |")
    print("| 30 - 75           | Suspicious  (Yellow Box)                                                  |")
    print("| 75 - 90           | High Risk URL     (Orange Box)                                            |")
    print("| 90 - 100          | Confirmed malware or phishing activity in the past 24-48 hours  (Red Box) |")
    print("  ---------------------------------------------------------------------------------------------- ")

    print("\n")

# Adding information to a file
def write_to_file(file_path, data):
    with open(file_path, 'a') as file:
        file.write(data + '\n')

# This function checks whether the URL has flagged it as a phishing URL
def is_phishing_url(ipqs_result):
    return ipqs_result.get('phishing', False)

def scan_qr_code():
    cap = cv2.VideoCapture(0)  # Open the default camera (0)

    while True:
        ret, frame = cap.read()

        # Decode QR codes
        decoded_objects = decode(frame)

        # Check if there are QR codes found
        if decoded_objects is not None:
            for obj in decoded_objects:
                data = obj.data.decode('utf-8')

                points = obj.polygon
                if len(points) == 4:
                    pts = np.array([(points[j].x, points[j].y) for j in range(4)], dtype=int)

                    rectangle_color = (0, 255, 0)  # Green for safe/Legit/clean
                    ipqs_result = check_url_ipqualityscore(data, IPQS_API_KEY)

                    risk_score = ipqs_result.get('risk_score', 0)  # Set a default value

                    if risk_score >= 30 and risk_score < 75:
                        rectangle_color = (0, 255, 255)  # Yellow for suspicious URLs
                        write_to_file(SUSPICIOUS_URLS_FILE, data)
                    if risk_score >= 75 and risk_score < 90:
                        rectangle_color = (0, 165, 255)  # Orange for high-risk URLs
                        write_to_file(HIGH_RISK_URLS_FILE, data)
                    if risk_score >= 90 or risk_score == 100 and ('phishing' in ipqs_result and ipqs_result['phishing'] == 'true') or \
                            ('malware' in ipqs_result and ipqs_result['malware'] == 'true'):
                        rectangle_color = (0, 0, 255)  # Red for confirmed malware or phishing activity
                        write_to_file(CONFIRMED_MALICIOUS_URLS_FILE, data)

                    # Log the result to specific files
                    if is_phishing_url(ipqs_result):
                        # Log malicious URL
                        write_to_file(MALICIOUS_URLS_FILE, data)
                    else:
                        # Log legit URL
                        write_to_file(LEGIT_URLS_FILE, data)

                    # Display results
                    print("URL:", data)
                    print("Risk Score:", risk_score)
                    print("Is Potential Threat:", ipqs_result.get('is_potential_threat', False))
                    print("Phishing:", ipqs_result.get('phishing', False))
                    print("Malware:", ipqs_result.get('malware', False))
                    print("")

                    cv2.polylines(frame, [pts], isClosed=True, color=rectangle_color, thickness=2)
                    cv2.putText(frame, data, (pts[0][0], pts[0][1] - 10),
                                cv2.FONT_HERSHEY_SIMPLEX, 0.5, rectangle_color, 2)
                    
                    # Save the entire frame as a screenshot
                    cv2.imwrite('screenshot.png', frame)

            cv2.imshow('QR Code Scanner', frame)

        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

    cap.release()
    cv2.destroyAllWindows()

if __name__ == "__main__":
    print_risk_score_table()
    scan_qr_code()