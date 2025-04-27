import re
import matplotlib.pyplot as plt
from datetime import datetime
import tkinter as tk
from tkinter import filedialog
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

def parse_event_log(file_path):
    event_data = []

    log_pattern = re.compile(
        r'Event ID: (?P<event_id>\d+)\s+'
        r'Source: (?P<source>.*?)\s+'
        r'Time Generated: (?P<time_generated>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+'
        r'Category: (?P<category>\d+)\s+'
        r'Description: (?P<description>\(.*?\))'
    )

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                match = log_pattern.match(line.strip())
                if match:
                    event_id = int(match.group('event_id'))
                    source = match.group('source')
                    time_generated = match.group('time_generated')
                    description = match.group('description')

                    timestamp = datetime.strptime(time_generated, f"%Y-%m-%d %H:%M:%S")
                    event_data.append((timestamp, event_id, source, description))

        event_data.sort(key=lambda x: x[0])
        return event_data

    except Exception as e:
        print(f"Error parsing log: {e}")
        return []

def plot_in_tk(event_data, parent_frame):
    # Clear previous plots
    for widget in parent_frame.winfo_children():
        widget.destroy()

    timestamps = [e[0] for e in event_data]
    event_ids = [e[1] for e in event_data]

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.plot(timestamps, event_ids, marker='o', linestyle='-', color='blue')
    ax.set_title("Event Log Timeline")
    ax.set_xlabel("Time")
    ax.set_ylabel("Event ID")
    ax.grid(True)
    fig.autofmt_xdate()

    canvas = FigureCanvasTkAgg(fig, master=parent_frame)
    canvas.draw()
    canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

def browse_file_and_plot(parent_frame):
    file_path = filedialog.askopenfilename(
        filetypes=[("Text files", "*.txt")],
        title="Select Event Log File"
    )
    if file_path:
        event_data = parse_event_log(file_path)
        if event_data:
            plot_in_tk(event_data, parent_frame)

# Tkinter UI
root = tk.Tk()
root.title("Event Log Timeline Viewer")
root.geometry("900x600")

top_frame = tk.Frame(root)
top_frame.pack(pady=10)

btn_browse = tk.Button(top_frame, text="Load Event Log", command=lambda: browse_file_and_plot(graph_frame))
btn_browse.pack()

graph_frame = tk.Frame(root)
graph_frame.pack(fill=tk.BOTH, expand=True)

root.mainloop()