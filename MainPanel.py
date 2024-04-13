import hashlib
import shodan
import requests
import psutil
import tkinter as tk
from tkinter import messagebox, ttk
import os

# Global variable to store all processes
all_processes = []

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
        # Download VirusTotal report
        download_vt_report(vt_api_key_entry.get(), file_hash)
    else:
        messagebox.showinfo("VirusTotal Report", "No report available on VirusTotal.")

    if shodan_result:
        messagebox.showinfo("Shodan Report", f"Matches Found: {shodan_result['total']}")
        for match in shodan_result['matches']:
            messagebox.showinfo("Match Found", f"IP: {match['ip_str']}, Port: {match['port']}")
        # Download Shodan report
        #download_shodan_report(shodan_api_key_entry.get(), file_hash)
    else:
        messagebox.showinfo("Shodan Report", "No matches found on Shodan.")

# Function to list all running processes
def list_all_processes():
    global all_processes
    all_processes = []
    # Iterate over all running processes
    for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
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
        if 'children' in proc:
            line += " (click to expand)"
            text.insert(tk.END, line + "\n", "highlight")
        else:
            text.insert(tk.END, line + "\n")

# Function to expand process and display child processes
def expand_process(event):
    global all_processes
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

# Function to list all processes when the Processes tab is selected
def on_processes_tab_selected(event):
    # List all processes and display them
    all_processes = list_all_processes()
    display_processes(all_processes)

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

# Create entry for Shodan API key
tk.Label(hashes_tab, text="Shodan API Key:").pack()
shodan_api_key_entry = tk.Entry(hashes_tab, width=50)
shodan_api_key_entry.pack()

# Create button to check file hash
check_button = tk.Button(hashes_tab, text="Check File Hash", command=check_file_hash)
check_button.pack()

# Create button to download VirusTotal report
download_vt_button = tk.Button(hashes_tab, text="Download VT Report", command=lambda: download_vt_report(vt_api_key_entry.get(), calculate_file_hash(entry.get())))
download_vt_button.pack()

# Create button to download Shodan report
download_shodan_button = tk.Button(hashes_tab, text="Download Shodan Report", command=lambda: download_shodan_report(shodan_api_key_entry.get(), calculate_file_hash(entry.get())))
download_shodan_button.pack()

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
notebook.bind("<<NotebookTabChanged>>", on_processes_tab_selected)

# Run the application
root.mainloop()
