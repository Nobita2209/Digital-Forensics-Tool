import sqlite3
import os
import shutil

# Path to the Chrome 'History' file
chrome_history_path = os.path.expanduser(r'C:\Users\Nimbalkar\AppData\Local\Google\Chrome\User Data\Default\History')

# Create a temporary copy of the database file because Chrome locks it during use
temp_history_path = 'chrome_history_copy'
shutil.copy(chrome_history_path, temp_history_path)

# Connect to the copied database
conn = sqlite3.connect(temp_history_path)
cursor = conn.cursor()

# Query to retrieve the download history from Chrome's 'downloads' table
cursor.execute("SELECT * FROM downloads;")

# Fetch and print the results
downloads = cursor.fetchall()

# Print the results
for download in downloads:
    print(f"Download ID: {download[0]},\nFile Path: {download[1]},\nURL: {download[2]},\nDate: {download[3]}")

# Clean up the temporary database file
conn.close()
os.remove(temp_history_path)