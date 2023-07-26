import requests
import re
from bs4 import BeautifulSoup

def xss_scan(url):
    payload = "<script>alert('XSS Vulnerability')</script>"
    response = requests.get(url)
    
    if payload in response.text:
        return "XSS-Schwachstelle gefunden: " + url
    return None

def sql_injection_scan(url):
    payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' UNION SELECT 1, user(), database() --",
        "' AND 1=CONVERT(int, (SELECT @@version)) --",
        "' OR 1=1; DROP TABLE users --",
        "' OR 1=1; UPDATE users SET password='hacked' --",
    ]
    
    vulnerabilities = []
    
    for payload in payloads:
        response = requests.get(url + "?id=" + payload)
        if "error" not in response.text:
            vulnerabilities.append("SQL Injection-Schwachstelle gefunden (Payload: " + payload + "): " + url)
    
    return vulnerabilities

def csrf_scan(url):
    response = requests.get(url)
    if response.status_code != 200:
        return "Fehler beim Zugriff auf die Webseite: " + url

    # Suchen Sie nach CSRF-Tokens in Formularen
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')
    for form in forms:
        csrf_token_input = form.find('input', {'name': 'csrf_token'})
        if csrf_token_input:
            csrf_token_value = csrf_token_input.get('value')
            if not csrf_token_value:
                return "CSRF-Schwachstelle gefunden (Token fehlt): " + url
             # Überprüfen Sie, ob das CSRF-Token in HTTPS-Anfragen verwendet wird
            if not url.startswith('https'):
                return "CSRF-Schwachstelle gefunden (unsichere Verwendung des Tokens): " + url    
 
    return None

def sensitive_data_scan(url):
    response = requests.get(url)
    if response.status_code != 200:
        return "Fehler beim Zugriff auf die Webseite: " + url

    # Suchen Sie nach sensiblen Daten in der Antwort der Webseite
    sensitive_data_keywords = ['Passwort', 'Kreditkarte', 'SSN', 'Sozialversicherungsnummer', 'geheim', 'vertraulich']
    for keyword in sensitive_data_keywords:
        if keyword in response.text:
            return "Potenzielle sensible Daten gefunden: " + url

    return None

def header_security_scan(url):
    response = requests.head(url)
    if response.status_code != 200:
        return "Fehler beim Zugriff auf die Webseite: " + url

    # Überprüfen Sie, ob wichtige Sicherheits-Header korrekt gesetzt sind
    headers = response.headers
    if "Content-Security-Policy" not in headers or "Strict-Transport-Security" not in headers:
        return "Sicherheits-Header nicht korrekt konfiguriert: " + url

    # Hier können weitere spezifische Tests für die Sicherheits-Header durchgeführt werden
    # Zum Beispiel könnten Sie die Werte der Header überprüfen, um sicherzustellen, dass sie den Best Practices entsprechen

    return None

def custom_scan(url):
    # Führen Sie hier Ihre benutzerdefinierten Tests und Regeln durch, die für Ihre Webanwendung relevant sind
    # Zum Beispiel könnten Sie spezifische URLs, Formularparameter oder Code-Patterns überprüfen
    return None

def scan_website(url):
    vulnerabilities = []

    vulnerabilities.append(xss_scan(url))
    vulnerabilities.append(sql_injection_scan(url))
    vulnerabilities.append(csrf_scan(url))
    vulnerabilities.append(sensitive_data_scan(url))
    vulnerabilities.append(header_security_scan(url))
    vulnerabilities.append(custom_scan(url))

    vulnerabilities = list(filter(None, vulnerabilities))
    return vulnerabilities

def main():
    url = input("Geben Sie die URL der zu scannenden Webseite ein: ")
    vulnerabilities = scan_website(url)
    if vulnerabilities:
        print("\n".join(vulnerabilities))
    else:
        print("Keine Schwachstellen gefunden.")

if __name__ == "__main__":
    main()
