import ipaddress
import json

def check_ip_in_aws(ip_to_check, json_file_path="ip-ranges.json"):
    try:
        # Convert input IP to ip_address object
        ip = ipaddress.ip_address(ip_to_check)

        # Load JSON data from local file
        with open(json_file_path, 'r') as f:
            data = json.load(f)

        # Check each IPv4 prefix
        for prefix in data.get("prefixes", []):
            network = ipaddress.ip_network(prefix["ip_prefix"])
            if ip in network:
                print(f"✅ {ip} belongs to AWS")
                print(f"  → Region: {prefix['region']}")
                print(f"  → Service: {prefix['service']}")
                print(f"  → Network Border Group: {prefix['network_border_group']}")
                return

        print(f"❌ {ip} does NOT belong to AWS")

    except FileNotFoundError:
        print(f"❌ JSON file '{json_file_path}' not found.")
    except ValueError:
        print("❌ Invalid IP address format.")

# === Example usage ===
if __name__ == "__main__":
    user_ip = input("Enter an IP address to check: ")
    check_ip_in_aws(user_ip.strip())
