import re
import csv
from collections import defaultdict, Counter

# Configurable failed login threshold i have set it to 5, if cout>thrshhols it detects as suspicious activity
FAILED_LOGIN_THRESHOLD = 5

def parse_log_file(log_file):
    #parse the file
    ip_requests = Counter()
    endpoint_access = Counter()
    failed_logins = defaultdict(int)
    log_pattern = (
        r'(?P<ip>\d+\.\d+\.\d+\.\d+) .* "(?P<method>\w+) (?P<endpoint>/\S*) HTTP/.*" (?P<status>\d+) .*'
    )
    failed_login_pattern = r'401.*Invalid credentials'
    with open(log_file, 'r') as file:
        for line in file:
            match = re.match(log_pattern, line)
            if match:
                ip = match.group('ip')
                endpoint = match.group('endpoint')
                status = match.group('status')

                # Count requests per IP
                ip_requests[ip] += 1
                
                # Count endpoint access
                endpoint_access[endpoint] += 1
                
                # Detect failed login attempts
                if re.search(failed_login_pattern, line):
                    failed_logins[ip] += 1

    return ip_requests, endpoint_access, failed_logins

def save_to_csv(ip_requests, most_accessed, failed_logins, output_file='log_analysis_results.csv'):
    #Save analysis results to a CSV file.
    with open(output_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        
        # Write requests per IP
        writer.writerow(['Requests per IP'])
        writer.writerow(['IP Address', 'Request Count'])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])
        
        # Write most accessed endpoint
        writer.writerow([])
        writer.writerow(['Most Accessed Endpoint'])
        writer.writerow(['Endpoint', 'Access Count'])
        writer.writerow(most_accessed)
        
        # Write suspicious activity
        writer.writerow([])
        writer.writerow(['Suspicious Activity'])
        writer.writerow(['IP Address', 'Failed Login Count'])
        for ip, count in failed_logins.items():
            writer.writerow([ip, count])

def main():
    log_file = 'sample.log'
    ip_requests, endpoint_access, failed_logins = parse_log_file(log_file)

    # Sort requests per IP
    sorted_ip_requests = ip_requests.most_common()

    # Identify the most accessed endpoint
    most_accessed_endpoint = endpoint_access.most_common(1)[0]

    # Detect suspicious activity
    suspicious_ips = {
        ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD
    }

    # Display results in the terminal
    print("IP Address           Request Count")
    for ip, count in sorted_ip_requests:
        print(f"{ip:<20} {count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20} {count}")
    
    # Save results to CSV
    save_to_csv(ip_requests, most_accessed_endpoint, suspicious_ips)

if __name__ == "__main__":
    main()
