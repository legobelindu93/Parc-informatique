import socket
import os
import platform

print("=" * 50)
print("  NETWORK INFO")
print("=" * 50)

hostname = socket.gethostname()
print(f"Hostname: {hostname}")

try:
    ip = socket.gethostbyname(hostname)
    print(f"IP locale: {ip}")
except:
    print("IP locale: impossible de résoudre")

print(f"OS: {platform.system()} {platform.release()}")
print(f"Machine: {platform.machine()}")

print("\n--- Interfaces réseau ---")
try:
    import netifaces
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            for addr in addrs[netifaces.AF_INET]:
                print(f"  {iface}: {addr.get('addr', '?')}/{addr.get('netmask', '?')}")
except ImportError:
    # Fallback sans netifaces
    try:
        results = socket.getaddrinfo(hostname, None, socket.AF_INET)
        for res in results:
            print(f"  -> {res[4][0]}")
    except:
        pass

print("\n--- Passerelle par défaut ---")
try:
    with open("/proc/net/route") as f:
        for line in f.readlines()[1:]:
            parts = line.strip().split()
            if parts[1] == "00000000":
                gw = socket.inet_ntoa(bytes.fromhex(parts[2]))
                print(f"  Gateway: {gw}")
except:
    print("  Impossible de lire la passerelle")

print("\n--- DNS ---")
try:
    with open("/etc/resolv.conf") as f:
        for line in f:
            if line.strip().startswith("nameserver"):
                print(f"  {line.strip()}")
except:
    print("  Impossible de lire les DNS")

print("\n--- Test connectivité ---")
targets = [("Google DNS", "8.8.8.8"), ("Cloudflare", "1.1.1.1")]
for name, target in targets:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((target, 53))
        print(f"  {name} ({target}): OK")
        s.close()
    except:
        print(f"  {name} ({target}): FAIL")

print("=" * 50)
