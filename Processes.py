import psutil
import tkinter as tk

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

def search_processes(search_term):
    all_processes = list_all_processes()
    search_results = []
    # Search for processes matching the search term
    for proc in all_processes:
        if search_term.lower() in proc['name'].lower():
            search_results.append(proc)
    return search_results

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

def expand_process(proc_info):
    # Clear previous output
    text.delete(1.0, tk.END)
    # Display process information
    text.insert(tk.END, f"PID: {proc_info['pid']}, Name: {proc_info['name']}, Username: {proc_info['username']}, CPU %: {proc_info['cpu_percent']}, Memory %: {proc_info['memory_percent']}\n")
    # Display child processes
    if 'children' in proc_info:
        for child_proc in proc_info['children']:
            text.insert(tk.END, f"  Child PID: {child_proc['pid']}, Name: {child_proc['name']}\n")

def return_to_processes_list():
    # Display all processes again
    display_processes(all_processes)

def search_and_display():
    search_term = search_entry.get()
    search_results = search_processes(search_term)
    display_processes(search_results)

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
root.title("Process Explorer")

# Create a frame for the search bar
search_frame = tk.Frame(root)
search_frame.pack()

# Create a label and entry for the search bar
search_label = tk.Label(search_frame, text="Search:")
search_label.pack(side=tk.LEFT)
search_entry = tk.Entry(search_frame)
search_entry.pack(side=tk.LEFT)
search_button = tk.Button(search_frame, text="Search", command=search_and_display)
search_button.pack(side=tk.LEFT)

# Create a text widget to display processes
text = tk.Text(root)
text.pack()

# Add a tag for highlighting
text.tag_configure("highlight", background="yellow")

# Bind click event to process_clicked function
text.bind("<Button-1>", process_clicked)

# Create a "Return" button to go back to the list of all processes
return_button = tk.Button(root, text="Return to Processes List", command=return_to_processes_list)
return_button.pack()

# Display all processes initially
all_processes = list_all_processes()
display_processes(all_processes)

# Run the application
root.mainloop()
