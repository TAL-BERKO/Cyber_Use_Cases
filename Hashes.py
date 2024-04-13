import hashlib
import shodan
import requests
import tkinter as tk
from tkinter import messagebox, ttk
import os

# Function to calculate the hash of a file
def calculate_file_hash(file_path):
    try:
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while True:
                data = f.read(4096)
                if not data:
                    break
                hasher.update(data)
        return hasher.hexdigest()
    except Exception as e:
        print('Error: %s' % e)

# Function to check the file hash on VirusTotal
def check_hash_on_virustotal(api_key, file_hash):
    try:
        url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
        headers = {'x-apikey': api_key}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()
        else:
            return None
    except Exception as e:
        print('Error: %s' % e)

# Function to download the report from VirusTotal
def download_vt_report(api_key, file_hash):
    try:
        url = f'https://www.virustotal.com/api/v3/files/{file_hash}/download'
        headers = {'x-apikey': api_key}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            # Save the report to a file
            with open(f"{file_hash}_vt_report.txt", "wb") as f:
                f.write(response.content)
            messagebox.showinfo("VirusTotal Report", "Report downloaded successfully.")
        else:
            messagebox.showerror("Error", "Failed to download the report from VirusTotal.")
    except Exception as e:
        print('Error: %s' % e)

# Function to check the file hash on Shodan
def check_hash_on_shodan(api_key, file_hash):
    try:
        api = shodan.Shodan(api_key)
        result = api.search(f'hash:{file_hash}')
        return result
    except shodan.APIError as e:
        print('Error: %s' % e)

# Function to download the report from Shodan
def download_shodan_report(api_key, file_hash):
    try:
        api = shodan.Shodan(api_key)
        result = api.download(file_hash)
        # Save the report to a file
        with open(f"{file_hash}_shodan_report.json", "w") as f:
            f.write(result)
        messagebox.showinfo("Shodan Report", "Report downloaded successfully.")
    except shodan.APIError as e:
        print('Error: %s' % e)
        messagebox.showerror("Error", "Failed to download the report from Shodan.")

# Function to handle button click event for checking file hash
def check_file_hash():
    file_path = entry.get()
    if not file_path:
        messagebox.showerror("Error", "Please enter a file path.")
        return
    
    if not os.path.exists(file_path):
        messagebox.showerror("Error", "File does not exist.")
        return
    
    file_hash = calculate_file_hash(file_path)
    vt_result = check_hash_on_virustotal(vt_api_key_entry.get(), file_hash)
    shodan_result = check_hash_on_shodan(shodan_api_key_entry.get(), file_hash)

    if vt_result:
        messagebox.showinfo("VirusTotal Report", f"Detections: {vt_result['data']['attributes']['last_analysis_stats']['malicious']}")
    else:
        messagebox.showinfo("VirusTotal Report", "No report available on VirusTotal.")

    if shodan_result:
        messagebox.showinfo("Shodan Report", f"Matches Found: {shodan_result['total']}")
        for match in shodan_result['matches']:
            messagebox.showinfo("Match Found", f"IP: {match['ip_str']}, Port: {match['port']}")
    else:
        messagebox.showinfo("Shodan Report", "No matches found on Shodan.")

# Create main application window
root = tk.Tk()
root.title("File Hash Checker")

# Create entry for file path
tk.Label(root, text="File Path:").pack()
entry = tk.Entry(root, width=50)
entry.pack()

# Create entry for VirusTotal API key
tk.Label(root, text="VirusTotal API Key:").pack()
vt_api_key_entry = tk.Entry(root, width=50)
vt_api_key_entry.pack()

# Create entry for Shodan API key
tk.Label(root, text="Shodan API Key:").pack()
shodan_api_key_entry = tk.Entry(root, width=50)
shodan_api_key_entry.pack()

# Create button to check file hash
check_button = tk.Button(root, text="Check File Hash", command=check_file_hash)
check_button.pack()

# Create button to download VirusTotal report
download_vt_button = tk.Button(root, text="Download VT Report", command=lambda: download_vt_report(vt_api_key_entry.get(), calculate_file_hash(entry.get())))
download_vt_button.pack()

# Create button to download Shodan report
download_shodan_button = tk.Button(root, text="Download Shodan Report", command=lambda: download_shodan_report(shodan_api_key_entry.get(), calculate_file_hash(entry.get())))
download_shodan_button.pack()

# Run the application
root.mainloop()
