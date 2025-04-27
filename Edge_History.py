import sqlite3
import os
from datetime import datetime, timedelta

# Path to Chrome's History SQLite database
history_db_path = r"C:\Users\Nimbalkar\AppData\Local\Microsoft\Edge\User Data\Default\History"
output_file = r"C:\Users\Nimbalkar\Desktop\edge_history.txt"
# Check if the file exists
if not os.path.exists(history_db_path):
    print(f"Error: The file {history_db_path} does not exist.")
else:
    # Connect to the SQLite database
    conn = sqlite3.connect(history_db_path)
    cursor = conn.cursor()

    # SQL query to retrieve URLs from the History table
    cursor.execute("SELECT url, title, visit_count, last_visit_time FROM urls")

    # Fetch and display the results
    rows = cursor.fetchall()
    with open(output_file, 'w', encoding='utf-8') as file:
        for row in rows:
            url = row[0]
            title = row[1]
            visit_count = row[2]
            last_visit_time = row[3]

            # Convert the timestamp to a human-readable format
            last_visit_time = datetime(1601, 1, 1) + timedelta(microseconds=last_visit_time)

            file.write(f"URL: {url}\n")
            file.write(f"Title: {title}\n")
            file.write(f"Visit Count: {visit_count}\n")
            file.write(f"Last Visit Time: {last_visit_time}\n")
            file.write("="*50 + "\n")

    # Close the connection
    conn.close()
    print(f"[+] History Saved to {output_file}")