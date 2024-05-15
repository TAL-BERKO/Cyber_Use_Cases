import psutil
import socket
import tkinter as tk

def get_network_info():
    network_info = []
    for proc in psutil.process_iter(['pid', 'name', 'connections']):
        try:
            proc_info = proc.info
            connections = proc_info.get('connections', [])
            for conn in connections:
                if hasattr(conn, 'status') and hasattr(conn, 'family') and conn.family == socket.AF_INET:
                    remote_ip = conn.raddr[0] if hasattr(conn, 'raddr') and len(conn.raddr) > 0 else None
                    if remote_ip:
                        try:
                            remote_host = socket.gethostbyaddr(remote_ip)[0]
                        except socket.herror:
                            remote_host = remote_ip
                        process_info = {
                            "pid": proc_info['pid'],
                            "name": proc_info['name'],
                            "remote_host": remote_host
                        }
                        network_info.append(process_info)
                        break  # Break once a connection is found for the process
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return network_info

def show_network_info():
    network_info = get_network_info()
    if network_info:
        for proc_info in network_info:
            info_text.insert(tk.END, f"PID: {proc_info['pid']}, Name: {proc_info['name']}, Remote Host: {proc_info['remote_host']}\n")
    else:
        info_text.insert(tk.END, "No processes with network connections found.")

# Create the main window
root = tk.Tk()
root.title("Network Information")

# Text widget to display network info
info_text = tk.Text(root, wrap=tk.WORD)
info_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

# Button to show network info
info_button = tk.Button(root, text="Show Network Info", command=show_network_info)
info_button.pack(padx=10, pady=10)

root.mainloop()
