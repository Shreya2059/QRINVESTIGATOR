import cv2
import urllib.parse
import requests
import sys
import os

print("=== QR Investigator Started ===")


def decode_qr(image_path):
    print(f"[+] Loading image: {image_path}")
    img = cv2.imread(image_path)

    if img is None:
        print(f"[-] Error: Could not open or find the image '{image_path}'.")
        return None

    detector = cv2.QRCodeDetector()

    # Attempt 1: Original
    qr_data, bbox, _ = detector.detectAndDecode(img)
    if qr_data:
        print(f"[+] Decoded (original): {qr_data}")
        return qr_data
    print("[*] Attempt 1 failed, trying grayscale...")

    # Attempt 2: Grayscale
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    qr_data, bbox, _ = detector.detectAndDecode(gray)
    if qr_data:
        print(f"[+] Decoded (grayscale): {qr_data}")
        return qr_data
    print("[*] Attempt 2 failed, trying threshold...")

    # Attempt 3: Binary Threshold
    _, thresh = cv2.threshold(gray, 127, 255, cv2.THRESH_BINARY)
    qr_data, bbox, _ = detector.detectAndDecode(thresh)
    if qr_data:
        print(f"[+] Decoded (threshold): {qr_data}")
        return qr_data
    print("[*] Attempt 3 failed, trying upscale...")

    # Attempt 4: Upscale 2x
    upscaled = cv2.resize(gray, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
    qr_data, bbox, _ = detector.detectAndDecode(upscaled)
    if qr_data:
        print(f"[+] Decoded (upscaled): {qr_data}")
        return qr_data
    print("[*] Attempt 4 failed, trying adaptive threshold...")

    # Attempt 5: Adaptive Threshold
    adaptive = cv2.adaptiveThreshold(
        gray, 255,
        cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY, 11, 2
    )
    qr_data, bbox, _ = detector.detectAndDecode(adaptive)
    if qr_data:
        print(f"[+] Decoded (adaptive): {qr_data}")
        return qr_data

    print("[-] All attempts failed. QR could not be decoded.")
    return None


def analyze_url(url):
    print("\n--- URL Analysis ---")
    try:
        parsed_url = urllib.parse.urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            print("[-] Not a valid URL.")
            return None
        print(f"[*] Protocol: {parsed_url.scheme.upper()}")
        print(f"[*] Domain:   {parsed_url.netloc}")
        if parsed_url.path:
            print(f"[*] Path:     {parsed_url.path}")
        if parsed_url.query:
            print(f"[*] Query:    {parsed_url.query}")
        if parsed_url.scheme == 'http':
            print("[⚠️  WARNING] Insecure HTTP connection!")
        else:
            print("[✓] Secure HTTPS connection.")
        return parsed_url.netloc
    except Exception as e:
        print(f"[-] Parsing Error: {e}")
        return None


def check_reputation(domain):
    print("\n--- Reputation Check ---")
    API_KEY = "d7aff659693e0549d1082677c6f2ae332ad0448298e559975003d70b09af3504"
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"accept": "application/json", "x-api-key": API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            print(f"[*] Malicious:  {stats['malicious']}")
            print(f"[*] Suspicious: {stats['suspicious']}")
            print(f"[*] Clean:      {stats['harmless']}")
            print(f"[*] Undetected: {stats['undetected']}")
            if stats['malicious'] > 0:
                print("🚨 DANGER: Domain flagged as MALICIOUS!")
            elif stats['suspicious'] > 0:
                print("⚠️  CAUTION: Domain flagged as SUSPICIOUS.")
            else:
                print("[✓] Domain appears clean.")
        elif response.status_code == 404:
            print("[-] Domain not found in VirusTotal database.")
        elif response.status_code == 403:
            print("[-] API key invalid or quota exceeded.")
        else:
            print(f"[-] API Error: HTTP {response.status_code}")
    except requests.exceptions.ConnectionError:
        print("[-] Connection Error: Could not reach VirusTotal. Check your internet connection.")
    except requests.exceptions.Timeout:
        print("[-] Timeout: VirusTotal did not respond in time.")
    except Exception as e:
        print(f"[-] Unexpected Error: {e}")


if __name__ == "__main__":
    # Accept image path from command-line argument or prompt the user
    if len(sys.argv) > 1:
        image_file = sys.argv[1]
    else:
        image_file = input("[?] Enter the path to your QR code image: ").strip()

    # Normalize path (handles Windows backslashes, quotes, etc.)
    image_file = os.path.normpath(image_file.strip('"').strip("'"))

    if not os.path.exists(image_file):
        print(f"[-] File not found: {image_file}")
        print("    Make sure the path is correct and the file exists.")
        sys.exit(1)

    extracted_data = decode_qr(image_file)

    if extracted_data:
        print(f"\n[✓] QR Content: {extracted_data}")
        target_domain = analyze_url(extracted_data)
        if target_domain:
            check_reputation(target_domain)
    else:
        print("\n[-] Could not extract data from QR code.")
        print("    Tips: Ensure the image is clear, well-lit, and the QR code is not damaged.")

    print("\n=== Script Finished ===")
