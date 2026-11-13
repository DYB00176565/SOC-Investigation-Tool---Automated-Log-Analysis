import os

# Define file paths
dataset_folder = "ProjectDataset"
auth_file = os.path.join(dataset_folder, "auth.log")
access_file = os.path.join(dataset_folder, "access.log")
ps_file = os.path.join(dataset_folder, "powershell_log.txt")
ioc_file = os.path.join(dataset_folder, "ioc.txt")

report_file = "investigation_report.txt"

def main():
    print("Investigation started...")
    
    report_data = []
    report_data.append("=== SOC INVESTIGATION FINAL REPORT ===")
    report_data.append("Task: Automated Log Analysis\n")

    # 1. Read IOCs
    bad_ips = []
    bad_paths = []
    
    with open(ioc_file, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                if "/" in line:
                    bad_paths.append(line)
                else:
                    bad_ips.append(line)

    # 2. Analyze AUTH.LOG (Brute Force Detection)
    report_data.append("--- [PART 1] Authentication Issues ---")
    failed_attempts = {} 
    
    with open(auth_file, 'r') as f:
        for line in f:
            if "Failed password" in line:
                words = line.split()
                for i in range(len(words)):
                    if words[i] == "from":
                        ip = words[i+1]
                        if ip in failed_attempts:
                            failed_attempts[ip] += 1
                        else:
                            failed_attempts[ip] = 1
    
    for ip in failed_attempts:
        if failed_attempts[ip] > 5:
            report_data.append("DETECTION: Brute force from IP " + ip + " (" + str(failed_attempts[ip]) + " failed logins)")

    # 3. Analyze ACCESS.LOG (Web Attacks)
    report_data.append("\n--- [PART 2] Web Server Analysis ---")
    with open(access_file, 'r') as f:
        for line in f:
            for b_ip in bad_ips:
                if b_ip in line:
                    report_data.append("IOC MATCH: Malicious IP " + b_ip + " detected!")
            
            if "SELECT" in line.upper() or "UNION" in line.upper() or "OR 1=1" in line:
                report_data.append("SUSPICIOUS: Possible SQL attack in line: " + line.strip()[:60] + "...")

    # 4. Analyze POWERSHELL_LOG.TXT (Malicious commands)
    report_data.append("\n--- [PART 3] PowerShell Activity ---")
    with open(ps_file, 'r') as f:
        for line in f:
            if "-EncodedCommand" in line or "Bypass" in line:
                report_data.append("ALERT: Dangerous PowerShell flag found: " + line.strip())
            if "malicious-site.com" in line:
                report_data.append("ALERT: Connection to known malware site detected.")

    # 5. Save
    with open(report_file, "w") as out:
        for line in report_data:
            out.write(line + "\n")

    print("Success! Report saved to " + report_file)

if __name__ == "__main__":
    main()