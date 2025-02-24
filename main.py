import ssl
import socket
import datetime

def check_ssl_expiry(hostname: str, port: int = 443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expiry_date = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
                remaining_days = (expiry_date - datetime.datetime.now(datetime.UTC)).days

                print(f"Zertifikat für {hostname}:{port} gültig bis: {expiry_date}")
                if remaining_days < 0:
                    print(f"WARNUNG: Das Zertifikat ist seit {-remaining_days} Tagen abgelaufen!")
                else:
                    print(f"Das Zertifikat ist noch {remaining_days} Tage gültig.")

    except Exception as e:
        print(f"Fehler beim Überprüfen des SSL-Zertifikats für {hostname}:{port}: {e}")

def read_domains_from_file(file_path: str):
    try:
        with open(file_path, 'r') as file:
            domains = []
            for line in file.readlines():
                parts = line.strip().split(':')
                if len(parts) == 2:
                    hostname, port = parts[0], int(parts[1])
                    domains.append((hostname, port))
                else:
                    print(f"Ungültiges Format in Zeile: {line.strip()} (erwartet: hostname:port)")
        return domains
    except Exception as e:
        print(f"Fehler beim Lesen der Datei: {e}")
        return []

if __name__ == "__main__":
    file_path = "domainlist.txt"
    domains = read_domains_from_file(file_path)

    for hostname, port in domains:
        print(f"\nÜberprüfung von {hostname}:{port}...")
        check_ssl_expiry(hostname, port)
