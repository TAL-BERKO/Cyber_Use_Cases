import hashlib
import re
import subprocess
import requests
import psutil
import tkinter as tk
from tkinter import messagebox, ttk
import os
import socket

# Global variable to store all processes
all_processes = []
network_info = {}

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
        url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
        headers = {'accept':'application/Json','x-apikey': api_key}
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

    if vt_result:
        messagebox.showinfo("VirusTotal Report", f"Detections: {vt_result['data']['attributes']['last_analysis_stats']['malicious']}")
    else:
        messagebox.showinfo("VirusTotal Report", "No report available on VirusTotal.")

# Function to list all running processes
def list_all_processes():
    global all_processes
    all_processes = []
    # Iterate over all running processes
    for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'connections']):
        try:
            # Get process information
            proc_info = proc.info
            # Check if the process has children
            children = list(proc.children())
            if children:
                proc_info['children'] = children
            all_processes.append(proc_info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return all_processes

# Function to get network information for processes
def get_network_info():
    global network_info
    network_info = {}
    for proc in all_processes:
        connections = proc.get('connections', [])
        for conn in connections:
            if hasattr(conn, 'status') and hasattr(conn, 'family') and conn.family == socket.AF_INET:
                remote_ip = conn.raddr[0] if hasattr(conn, 'raddr') and len(conn.raddr) > 0 else None
                if remote_ip:
                    try:
                        remote_host = socket.gethostbyaddr(remote_ip)[0]
                    except socket.herror:
                        remote_host = remote_ip
                    network_info[proc['pid']] = remote_host

# Function to search processes by name
def search_processes(search_term):
    all_processes = list_all_processes()
    search_results = []
    # Search for processes matching the search term
    for proc in all_processes:
        if search_term.lower() in proc['name'].lower():
            search_results.append(proc)
    return search_results

# Function to display processes in the text widget
def display_processes(processes):
    # Clear previous output
    text.delete(1.0, tk.END)
    # Display processes in the text widget
    for proc in processes:
        line = f"PID: {proc['pid']}, Name: {proc['name']}, Username: {proc['username']}, CPU %: {proc['cpu_percent']}, Memory %: {proc['memory_percent']}"
        if proc['pid'] in network_info:
            line += f", Network: {network_info[proc['pid']]}"
        if 'children' in proc:
            line += " (click to expand)"
            text.insert(tk.END, line + "\n", "highlight")
        else:
            text.insert(tk.END, line + "\n")

# Function to expand process and display child processes
def expand_process(event):
    index = text.index(tk.CURRENT)
    line = text.get(index + " linestart", index + " lineend")
    pid = int(line.split("PID: ")[1].split(",")[0])
    for proc in all_processes:
        if proc['pid'] == pid and 'children' in proc:
            # Clear previous output
            text.delete(1.0, tk.END)
            # Display process information
            text.insert(tk.END, f"PID: {proc['pid']}, Name: {proc['name']}, Username: {proc['username']}, CPU %: {proc['cpu_percent']}, Memory %: {proc['memory_percent']}\n")
            # Display child processes
            text.insert(tk.END, "\nChild Processes:\n")
            for child_proc in proc['children']:
                text.insert(tk.END, f"  Child PID: {child_proc.pid}, Name: {child_proc.name()}\n")
            break

# Function to return to the list of all processes
def return_to_processes_list():
    # Display all processes again
    display_processes(all_processes)

# Function to handle search and display of processes
def search_and_display():
    search_term = search_entry.get()
    search_results = search_processes(search_term)
    display_processes(search_results)

# Function to download VirusTotal report
def download_vt():
    file_path = entry.get()
    if not file_path:
        messagebox.showerror("Error", "Please enter a file path.")
        return
    
    if not os.path.exists(file_path):
        messagebox.showerror("Error", "File does not exist.")
        return
    
    file_hash = calculate_file_hash(file_path)
    download_vt_report(vt_api_key_entry.get(), file_hash)

# Function to export ipconfig displaydns
def export_ipconfig_displaydns(output_file):
    result = subprocess.run(['ipconfig', '/displaydns'], capture_output=True, text=True)
    with open(output_file, 'w') as file:
        file.write(result.stdout)

# Function to check for Suspicious domains
def check_for_suspicious_domains(output_file, suspicious_domains_file):
    with open(suspicious_domains_file, 'r') as file:
        suspicious_domains = [line.strip() for line in file]

    with open(output_file, 'r') as file:
        output = file.read()

    matches = []
    for domain in suspicious_domains:
        if re.search(domain, output):
            matches.append(domain)

    return matches

# Create main application window
root = tk.Tk()
root.title("Main Panel")

# Create a notebook (tabbed interface)
notebook = ttk.Notebook(root)
notebook.pack(fill=tk.BOTH, expand=True)

# Create File Hashes tab
hashes_tab = ttk.Frame(notebook)
notebook.add(hashes_tab, text="File Hashes")

# Create entry for file path
tk.Label(hashes_tab, text="File Path:").pack()
entry = tk.Entry(hashes_tab, width=50)
entry.pack()

# Create entry for VirusTotal API key
tk.Label(hashes_tab, text="VirusTotal API Key:").pack()
vt_api_key_entry = tk.Entry(hashes_tab, width=50)
vt_api_key_entry.pack()

# Create button to check file hash
check_button = tk.Button(hashes_tab, text="Check File Hash", command=check_file_hash)
check_button.pack()

# Create button to download VirusTotal report
download_vt_button = tk.Button(hashes_tab, text="Download VT Report", command=download_vt)
download_vt_button.pack()

# Create Processes tab
processes_tab = ttk.Frame(notebook)
notebook.add(processes_tab, text="Processes")

# Create a frame for the search bar
search_frame = tk.Frame(processes_tab)
search_frame.pack()

# Create a label and entry for the search bar
search_label = tk.Label(search_frame, text="Search:")
search_label.pack(side=tk.LEFT)
search_entry = tk.Entry(search_frame)
search_entry.pack(side=tk.LEFT)
search_button = tk.Button(search_frame, text="Search", command=search_and_display)
search_button.pack(side=tk.LEFT)

# Create a text widget to display processes
text = tk.Text(processes_tab)
text.pack()

# Add a tag for highlighting
text.tag_configure("highlight", background="yellow")

# Bind click event to expand_process function
text.bind("<Button-1>", expand_process)

# Create a "Return" button to go back to the list of all processes
return_button = tk.Button(processes_tab, text="Return to Processes List", command=return_to_processes_list)
return_button.pack()

# Bind event to list all processes when Processes tab is selected
notebook.bind("<<NotebookTabChanged>>", lambda event: display_processes(list_all_processes()))

# Create DNS tab
dns_tab = ttk.Frame(notebook)
notebook.add(dns_tab, text="DNS")

# Create widgets for DNS tab
output_file = 'dns_output.txt'
suspicious_domains_file = 'Domains_List.txt'
export_button = ttk.Button(dns_tab, text="Export DNS Data", command=lambda: export_ipconfig_displaydns(output_file))
export_button.pack(pady=10)

check_button = ttk.Button(dns_tab, text="Check for Suspicious Domains", command=lambda: check_domains())
check_button.pack(pady=10)

result_label = ttk.Label(dns_tab, text="")
result_label.pack(pady=10)

# Function to check domains
def check_domains():
    try:
        matches = check_for_suspicious_domains(output_file, suspicious_domains_file)
        if matches:
            result_label.config(text="Found matches to suspicious domains:\n" + "\n".join(matches))
        else:
            result_label.config(text="No matches found.")
    except Exception as e:
        result_label.config(text="An error occurred: " + str(e))

# Run the application
root.mainloop()
