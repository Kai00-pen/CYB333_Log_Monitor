
# CYB333 Automated Log Monitoring and Alerting System


# Function to read the log file
def read_logs(filename):
    logs = []

    try:
        with open(filename, "r") as file:
            for line in file:
                line = line.strip()

                # Skip empty lines
                if line:
                    logs.append(line)

    except FileNotFoundError:
        print(f"Error: {filename} was not found.")

    return logs


# Function to process each log entry
def parse_logs(logs):
    parsed_logs = []

    for log in logs:
        # Split each log entry into sections
        parts = log.split(" | ")

        # Make sure the log has all expected fields
        if len(parts) == 5:
            log_entry = {
                "timestamp": parts[0],
                "event": parts[1],
                "username": parts[2],
                "ip_address": parts[3],
                "status": parts[4]
            }

            parsed_logs.append(log_entry)

    return parsed_logs


# Function to display processed logs
def display_logs(parsed_logs):
    print("=== Processed Security Logs ===")

    for log in parsed_logs:
        print(f"Time: {log['timestamp']}")
        print(f"Event: {log['event']}")
        print(f"Username: {log['username']}")
        print(f"IP Address: {log['ip_address']}")
        print(f"Status: {log['status']}")
        print("-" * 40)


# Function to detect failed login attempts
def detect_failed_logins(parsed_logs):
    print("\n=== Failed Login Detection ===")

    failed_count = 0

    for log in parsed_logs:
        if (
            log["event"].strip().upper() == "LOGIN"
            and log["status"].strip().upper() == "FAILED"
        ):
            failed_count += 1

            print("[ALERT] Failed login detected!")
            print(f"Username: {log['username']}")
            print(f"IP Address: {log['ip_address']}")
            print(f"Time: {log['timestamp']}")
            print("-" * 40)

    print(f"Total failed logins: {failed_count}")


# Function to detect suspicious IP addresses
def detect_suspicious_ips(parsed_logs):
    print("\n=== Suspicious IP Detection ===")

    ip_counts = {}

    # Count failed login attempts from each IP
    for log in parsed_logs:
        if (
            log["event"].strip().upper() == "LOGIN"
            and log["status"].strip().upper() == "FAILED"
        ):
            ip = log["ip_address"]

            if ip in ip_counts:
                ip_counts[ip] += 1
            else:
                ip_counts[ip] = 1

    suspicious_found = False

    # TEST THRESHOLD: 5 failed login attempts
    for ip, count in ip_counts.items():
        if count >= 3:
            suspicious_found = True

            print(f"[WARNING] Suspicious IP detected: {ip}")
            print(f"Failed login attempts: {count}")
            print("Possible brute-force activity.")
            print("-" * 40)

    if not suspicious_found:
        print("No suspicious IP addresses detected.")


# Main program
def main():
    filename = "sample_logs.txt"

    logs = read_logs(filename)
    parsed_logs = parse_logs(logs)

    display_logs(parsed_logs)
    detect_failed_logins(parsed_logs)
    detect_suspicious_ips(parsed_logs)

    return parsed_logs


if __name__ == "__main__":
    main()
