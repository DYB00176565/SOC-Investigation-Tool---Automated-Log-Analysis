# SOC Investigation Tool - Automated Log Analysis

## Project Overview
This project is an automated Security Investigation Tool developed for a Security Operations Centre (SOC) environment. The tool is designed to analyse various security logs to detect suspicious activities, identify potential threats based on Indicators of Compromise (IOCs), and generate a comprehensive investigation report.

## Directory Structure
- `ProjectDataset/` : Contains the source log files (`access.log`, `auth.log`, `powershell_log.txt`, `ioc.txt`).
- `run.py` : The main Python script that performs the automated analysis.
- `investigation_report.txt` : The output report generated after the script execution.
- `README.md` : Documentation and execution instructions.

## Prerequisites
To run this tool, you need to have **Python 3.x** installed on your system. No external libraries are required as the script uses standard Python modules.

## How to Run the Tool
Follow these steps to perform the investigation:

### Option 1: Using File Explorer

1. Go to the project folder `B00176565_Project` in Windows File Explorer.
2. Click on the address bar at the top, type `powershell` or `cmd`, and press **Enter**.
3. In the terminal window that opens, run the script:
   ```bash
   python run.py


### Option 2: Using Terminal Navigation

1. Open **PowerShell** or **Command Prompt**.
2. Use the `cd` (change directory) command to navigate to the project folder. Run the following command:
   ```powershell
   cd "Path_to_your_project"

3. Once the terminal is inside the project folder, run the script:
   ```bash
   python run.py


### View the Results:

 After the script finishes, stay in the same folder and look for a newly generated file named investigation_report.txt. You can open it with any text editor (like Notepad) to see the security findings.
