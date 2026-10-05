# CYB333 Security Automation Project
# Automated Log Monitoring and Alerting System
# Core Log Parsing

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


# Main program
def main():
    filename = "sample_logs.txt"

    logs = read_logs(filename)
    parsed_logs = parse_logs(logs)

    display_logs(parsed_logs)

    # Return parsed data so other project components
    # can use it for detection and alerting
    return parsed_logs


if __name__ == "__main__":
    main()