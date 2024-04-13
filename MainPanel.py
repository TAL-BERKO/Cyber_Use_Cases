import hashlib
import shodan
import requests
import psutil
import tkinter as tk
from tkinter import ttk, messagebox
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
        url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
        headers = {"accept": "application/json",'x-apikey': api_key}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            response = requests.get(url, headers=headers)
            # Save the report to a file
            with open(f"{file_hash}_vt_report.txt", "wb") as f:
                f.write(response.content)
            return True
        else:
            return False
    except Exception as e:
        print('Error: %s' % e)

# Function to check the file hash and IP on Shodan
def check_hash_and_ip_on_shodan(api_key, file_hash):
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
        return True
    except shodan.APIError as e:
        print('Error: %s' % e)
        return False

# Function to handle file hash checking
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
    shodan_result = check_hash_and_ip_on_shodan(shodan_api_key_entry.get(), file_hash)

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
def expand_process(proc_info):
    # Clear previous output
    text.delete(1.0, tk.END)
    # Display process information
    text.insert(tk.END, f"PID: {proc_info['pid']}, Name: {proc_info['name']}, Username: {proc_info['username']}, CPU %: {proc_info['cpu_percent']}, Memory %: {proc_info['memory_percent']}\n")
    # Display child processes
    if 'children' in proc_info:
        for child_proc in proc_info['children']:
            text.insert(tk.END, f"  Child PID: {child_proc['pid']}, Name: {child_proc['name']}\n")

# Function to return to the list of all processes
def return_to_processes_list():
    # Display all processes again
    display_processes(all_processes)

# Function to handle search and display of processes
def search_and_display():
    search_term = search_entry.get()
    search_results = search_processes(search_term)
    display_processes(search_results)

# Function to handle process clicked event
def process_clicked(event):
    index = text.index(tk.CURRENT)
    line = text.get(index + " linestart", index + " lineend")
    pid = int(line.split("PID: ")[1].split(",")[0])
    for proc in all_processes:
        if proc['pid'] == pid:
            expand_process(proc)
            break

# Create main application window
root = tk.Tk()
root.title("Main Panel")

# Create a notebook (tabbed interface)
notebook = ttk.Notebook(root)
notebook.pack(fill=tk.BOTH, expand=True)

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

# Bind click event to process_clicked function
text.bind("<Button-1>", process_clicked)

# Create a "Return" button to go back to the list of all processes
return_button = tk.Button(processes_tab, text="Return to Processes List", command=return_to_processes_list)
return_button.pack()

# Display all processes initially
all_processes = list_all_processes()
display_processes(all_processes)

# Create Hashes tab
hashes_tab = ttk.Frame(notebook)
notebook.add(hashes_tab, text="Hashes")

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

# Run the application
root.mainloop()
