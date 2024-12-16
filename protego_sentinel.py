import os
import subprocess
import sys
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading
import shutil
import schedule
import time
from pathlib import Path

def install_required_libraries():
    required_libraries = ["requests", "watchdog", "schedule"]
    for lib in required_libraries:
        try:
            __import__(lib)
        except ImportError:
            print(f"The library '{lib}' is not installed.")
            user_input = input(f"Do you want to install it now? (y/n): ").strip().lower()
            if user_input == 'y':
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", lib])
                except Exception as e:
                    print(f"Failed to install '{lib}'. Error: {e}")
                    sys.exit(1)
            else:
                print(f"The library '{lib}' is required. Exiting program.")
                sys.exit(1)


install_required_libraries()
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog, messagebox


# List of common non-executable file extensions
NON_EXECUTABLE_EXTENSIONS = {
    "image": [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp"],
    "document": [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt"],
    "video": [".mp4", ".avi", ".mov", ".mkv", ".flv", ".wmv", ".webm"]
}

ALL_EXTENSIONS = set(ext for group in NON_EXECUTABLE_EXTENSIONS.values() for ext in group)

def is_executable(file_path):
    """Check if a file contains an executable header or signs of tampering."""
    try:
        with open(file_path, "rb") as f:
            header = f.read(2)
            if header == b"MZ":
                return True
            file_size = os.path.getsize(file_path)
            if file_size < 100:
                return True
            f.seek(0)
            content = f.read()
            suspicious_patterns = [b"<script>", b"powershell", b"cmd.exe", b"shellcode", b"<iframe>"]
            if any(pattern in content for pattern in suspicious_patterns):
                return True
        return False
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return False

def log_results_to_json(results, directory):
    """Log the scan results to a JSON file."""
    import json
    log_path = Path(__file__).parent / "Logs"
    log_path.mkdir(exist_ok=True)
    log_file_path = log_path / "protego_results.json"
    data = [{"file": str(file), "hash": calculate_hash(file)} for file in results]
    with open(log_file_path, "w") as log_file:
        json.dump(data, log_file, indent=4)
    return log_path

def calculate_hash(file_path):
    """Calculate SHA256 hash of a file."""
    import hashlib
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error hashing file {file_path}: {e}")
        return None

class DirectoryMonitor(FileSystemEventHandler):
    """Monitor directory for changes and scan new files."""
    def __init__(self, directory):
        self.directory = directory

    def on_created(self, event):
        if not event.is_directory:
            file_path = Path(event.src_path)
            if file_path.suffix.lower() in ALL_EXTENSIONS:
                print(f"New file detected: {file_path}")
                if is_executable(file_path):
                    quarantine_folder = Path(self.directory) / "quarantine"
                    quarantine_folder.mkdir(exist_ok=True)
                    shutil.move(file_path, quarantine_folder / file_path.name)
                    print(f"Quarantined: {file_path}")

def start_monitoring(directory):
    event_handler = DirectoryMonitor(directory, file_listbox)
    observer = Observer()
    observer.schedule(event_handler, directory, recursive=True)
    observer_thread = threading.Thread(target=observer.start)
    observer_thread.daemon = True
    observer_thread.start()
    print(f"Started monitoring directory: {directory}")


    
def check_with_virustotal(file_hash):
    """Check file hash with VirusTotal API and return detailed results."""
    api_key = "### ### ADD API KEY FROM VIRUS TOTAL ### ###"
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            positives = attributes.get("last_analysis_stats", {}).get("malicious", 0)
            scan_results = attributes.get("last_analysis_results", {})
            return {"positives": positives, "scan_results": scan_results}
        else:
            print(f"VirusTotal API error: {response.status_code}")
            return None
    except Exception as e:
        print(f"Error checking VirusTotal: {e}")
        return None


def scan_and_validate(directory, progress_callback=None):
    """Scan for files, validate them, and quarantine executable files."""
    executable_files = []
    quarantine_folder = Path(__file__).parent / "quarantine"
    quarantine_folder.mkdir(exist_ok=True)

    files_to_scan = [
        Path(root) / file
        for root, _, files in os.walk(directory)
        for file in files
        if "quarantine" not in Path(root).parts
    ]

    total_files = len(files_to_scan)
    virus_total_results = []

    for index, file_path in enumerate(files_to_scan, start=1):
        if file_path.suffix.lower() in ALL_EXTENSIONS:
            if is_executable(file_path):
                executable_files.append(file_path)
                try:
                    shutil.move(file_path, quarantine_folder / file_path.name)
                except Exception as e:
                    print(f"Failed to quarantine {file_path}: {e}")

                # VirusTotal Check
                file_hash = calculate_hash(file_path)
                vt_results = check_with_virustotal(file_hash)
                if vt_results:
                    positives = vt_results["positives"]
                    virus_total_results.append(f"{file_path.name}: Detected by {positives} engines.")
                    print(f"File {file_path.name} flagged as malicious by {positives} engines.")

        # Update progress
        if progress_callback:
            progress_callback(index, total_files)

    log_path = log_results_to_json(executable_files, directory)
    print(f"Results logged to {log_path / 'protego_results.json'}")

    # Return results and VirusTotal data
    return executable_files, virus_total_results




def start_scan():
    directory = filedialog.askdirectory()
    if not directory:
        return
    progress_bar["value"] = 0
    result_label.config(text=f"Scanning: {directory}...")
    root.update()

    def update_progress(current, total):
        progress_bar["value"] = (current / total) * 100
        root.update_idletasks()

    suspicious_files, virus_total_results = scan_and_validate(directory, progress_callback=update_progress)

    if suspicious_files:
        vt_summary = "\n".join(virus_total_results) if virus_total_results else "No VirusTotal results available."
        result = f"Quarantined {len(suspicious_files)} suspicious files.\n\nVirusTotal Results:\n{vt_summary}"
        messagebox.showinfo("Scan Complete", result)
    else:
        result = "No suspicious files found."
        messagebox.showinfo("Scan Complete", result)

    result_label.config(text="")





def run_scheduled_scan(directory):
    """Run a scheduled scan."""
    print(f"Scheduled scan running for directory: {directory}")
    scan_and_validate(directory)
    print("Scheduled scan complete.")

def start_scheduler(directory, interval_minutes):
    """Start the scheduler to run scans at regular intervals."""
    schedule.every(interval_minutes).minutes.do(run_scheduled_scan, directory=directory)

    def run_scheduler():
        while True:
            schedule.run_pending()
            time.sleep(1)

    scheduler_thread = threading.Thread(target=run_scheduler)
    scheduler_thread.daemon = True
    scheduler_thread.start()
    print(f"Scheduler started for directory: {directory} every {interval_minutes} minutes.")

def start_scheduled_scan():
    """Prompt the user for scheduling options."""
    directory = filedialog.askdirectory()
    if not directory:
        return
    interval_minutes = tk.simpledialog.askinteger(
        "Schedule Scan",
        "Enter the interval in minutes for the scheduled scan:",
        minvalue=1
    )
    if interval_minutes:
        start_scheduler(directory, interval_minutes)
        messagebox.showinfo("Scheduler Started", f"Scheduled scans every {interval_minutes} minutes for directory: {directory}")

def toggle_dark_mode():
    root.config(bg="black")
    frame.config(bg="black")
    label.config(bg="black", fg="white")
    result_label.config(bg="black", fg="white")
    scan_button.config(bg="grey", fg="white")
    open_quarantine_button.config(bg="grey", fg="white")
    open_logs_button.config(bg="grey", fg="white")
    dark_mode_button.config(bg="grey", fg="white")

def restore_file():
    selected_file = file_listbox.get(tk.ACTIVE)
    if selected_file:
        quarantine_folder = Path(__file__).parent / "quarantine"
        original_file = quarantine_folder / selected_file.split(": ")[1]
        try:
            shutil.move(original_file, original_file.parent.parent / original_file.name)
            file_listbox.delete(tk.ACTIVE)
            messagebox.showinfo("Restore", f"File {original_file.name} restored successfully.")
        except Exception as e:
            messagebox.showerror("Restore Error", f"Failed to restore file: {e}")


def configure_filters():
    filter_window = tk.Toplevel(root)
    filter_window.title("Configure Filters")
    filter_window.geometry("300x400")
    tk.Label(filter_window, text="Select file types to scan:").pack(pady=10)
    for category, extensions in NON_EXECUTABLE_EXTENSIONS.items():
        var = tk.BooleanVar(value=True)
        tk.Checkbutton(filter_window, text=f"{category}: {', '.join(extensions)}", variable=var).pack(anchor="w")

def start_real_time_monitoring():
    directory = filedialog.askdirectory()
    if not directory:
        return
    start_monitoring(directory)
    result_label.config(text=f"Monitoring started for: {directory}")
    messagebox.showinfo("Real-Time Monitoring", f"Monitoring started for: {directory}")


# Create UI
root = tk.Tk()
root.title("Protego Sentinel")
root.geometry("600x400")

frame = tk.Frame(root, padx=10, pady=10)
frame.pack(fill="both", expand=True)

label = tk.Label(frame, text="Select a directory to scan for suspicious files:")
label.pack(pady=10)

scan_button = tk.Button(frame, text="Scan Directory", command=start_scan)
scan_button.pack(pady=10)

progress_bar = ttk.Progressbar(frame, orient="horizontal", length=400, mode="determinate")
progress_bar.pack(pady=10)

open_quarantine_button = tk.Button(frame, text="Open Quarantine Folder", command=lambda: os.startfile(Path(__file__).parent / "quarantine"))
open_quarantine_button.pack(pady=5)

open_logs_button = tk.Button(frame, text="Open Logs Folder", command=lambda: os.startfile(Path(__file__).parent / "Logs"))
open_logs_button.pack(pady=5)

monitor_button = tk.Button(frame, text="Start Real-Time Monitoring", command=start_real_time_monitoring)
monitor_button.pack(pady=5)

schedule_button = tk.Button(frame, text="Schedule Scans", command=start_scheduled_scan)
schedule_button.pack(pady=10)

file_listbox = tk.Listbox(frame, height=10, width=60)
file_listbox.pack(pady=10)

dark_mode_button = tk.Button(frame, text="Toggle Dark Mode", command=toggle_dark_mode)
dark_mode_button.pack(pady=5)

result_label = tk.Label(frame, text="", fg="blue")
result_label.pack(pady=10)

file_listbox = tk.Listbox(frame, height=10, width=60)
file_listbox.pack(pady=10)

class DirectoryMonitor(FileSystemEventHandler):
    """Monitor directory for changes and scan new files."""
    def __init__(self, directory, dashboard_listbox):
        self.directory = directory
        self.dashboard_listbox = dashboard_listbox

    def on_created(self, event):
        if not event.is_directory:
            file_path = Path(event.src_path)
            if file_path.suffix.lower() in ALL_EXTENSIONS:
                if is_executable(file_path):
                    quarantine_folder = Path(self.directory) / "quarantine"
                    quarantine_folder.mkdir(exist_ok=True)
                    try:
                        shutil.move(file_path, quarantine_folder / file_path.name)
                        self.dashboard_listbox.insert(tk.END, f"Quarantined: {file_path.name}")
                    except Exception as e:
                        print(f"Failed to quarantine {file_path}: {e}")


restore_button = tk.Button(frame, text="Restore Selected File", command=restore_file)
restore_button.pack(pady=5)

filter_button = tk.Button(frame, text="Configure Filters", command=configure_filters)
filter_button.pack(pady=5)



root.mainloop()
