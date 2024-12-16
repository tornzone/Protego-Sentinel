Protego Sentinel
Protego Sentinel is a desktop application designed to monitor, scan, and secure your system against potentially malicious files and links. It uses advanced techniques to detect executable files, hidden scripts, and malicious behaviors, offering real-time protection and scheduled scans for comprehensive security.
________________________________________
Features
•	File Scanning:
•	Detects suspicious files, including hidden executables, malicious scripts, and tampered files.
•	Supports common file types like images, documents, and videos.
•	Quarantines files flagged as suspicious into a secure folder.
•	VirusTotal Integration:
•	Optionally checks file hashes against the VirusTotal API for deeper analysis.
•	Displays the number of antivirus engines that flagged the file as malicious.
•	Real-Time Directory Monitoring:
•	Monitors specified directories for new files and automatically scans them.
•	Immediately quarantines suspicious files detected during monitoring.
•	Scheduled Scans:
•	Allows users to schedule scans at regular intervals.
•	Provides notifications about the results of each scan.
•	Logs and Reporting:
•	Saves scan results and details about quarantined files in a JSON log file.
•	Logs can be reviewed for further investigation.
•	Customizable File Filters:
•	Configure which file types to include or exclude from scans.
•	Tailor scanning to specific user needs.
•	Dark Mode:
•	Toggle between light and dark themes for better user experience.
•	Quarantine Management:
•	Easily view, restore, or permanently delete quarantined files.
________________________________________
How It Works
1.	Scanning for Suspicious Files:
•	The app scans the selected directory for files.
•	It checks if files contain executable headers, hidden scripts, or known suspicious patterns.
•	Detected suspicious files are moved to a quarantine folder.
2.	VirusTotal Integration:
•	Files' SHA256 hashes are calculated locally and sent to VirusTotal (if an API key is provided).
•	Displays results from VirusTotal, including the number of detection engines flagging the file.
3.	Real-Time Monitoring:
•	Monitors user-selected directories for newly created or modified files.
•	Automatically scans and quarantines suspicious files upon detection.
4.	Scheduled Scans:
•	Users can set up periodic scans for a chosen directory.
•	Scans run in the background without interrupting other tasks.
5.	Log Management:
•	Results of all scans are saved in a JSON file located in the Logs folder.
•	The log includes file names, hashes, and scan results for easy reference.
________________________________________
Setup and Installation
Step 1: Prerequisites
Ensure the following are installed:
•	Python 3.8 or newer
•	Pip package manager

Step 2: Clone the Repository
git clone https://github.com/yourusername/protego-sentinel.git cd protego-sentinel 

Step 3: Install Dependencies
Run the following command to install required libraries:
python -m pip install -r requirements.txt 

Step 4: Run the Program
Launch the application:
python protego_sentinel.py 
________________________________________
Usage
Scanning a Directory
1.	Click the "Scan Directory" button.
2.	Choose a folder to scan.
3.	Review results in the quarantine folder or logs.
Real-Time Monitoring
1.	Click "Start Real-Time Monitoring."
2.	Select a directory to monitor.
3.	The app will automatically quarantine suspicious files.
Scheduling Scans
1.	Click "Schedule Scans."
2.	Set the interval (in minutes) for periodic scanning.
Log Access
•	Click "Open Logs Folder" to view scan results and quarantined files.
Restore Quarantined Files
1.	Select a file from the quarantine list.
2.	Click "Restore Selected File."
________________________________________
Customization
•	Configure Filters: Use the "Configure Filters" option to include or exclude specific file types.
•	Dark Mode: Toggle dark mode for a better visual experience.
________________________________________
Limitations
•	VirusTotal integration requires an API key (free and paid plans available).
•	Real-time monitoring may slightly impact performance on slower systems.
________________________________________
Future Enhancements
•	Add machine learning-based file behavior analysis.
•	Extend support to additional file types.
•	Provide multi-language support.

