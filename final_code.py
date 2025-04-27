import win32evtlog
import os
import time
import sqlite3
from datetime import datetime, timedelta
import pefile
import sys
from PIL import Image
import win32file
import win32con

print("[1] If you want to disk imaging")
print("[2] If you want to recover deleted data")
print("[3] If you want to analyse disk")
input = input("")
disk_path = r'\\.\PhysicalDrive0'  # Use the correct physical drive path here
image_path = r'D2:\disk_image.img'

def image_disk(disk_path, image_path, block_size=2048):
    """
    Creates a disk image of the specified disk.

    Args:
        disk_path: The path to the disk (e.g., '\\\\.\\PhysicalDrive0').
        image_path: The path to save the image file.
        block_size: The size of each block to read (default: 512 bytes).
    """
    handle = None  # Initialize handle to ensure it's safely accessed
    try:
        # Open the disk in read-only mode
        handle = win32file.CreateFile(
            disk_path,
            win32con.GENERIC_READ,
            win32con.FILE_SHARE_READ,
            None,
            win32con.OPEN_EXISTING,
            0,
            None
        )

        # Open the image file for writing
        with open(image_path, 'wb') as image_file:
            total_bytes_read = 0
            while True:
                # Read a block of data from the disk
                data = win32file.ReadFile(handle, block_size)[1]  # Get only the data part
                
                # If no data is read, we've reached the end of the disk
                if not data:
                    break
                
                # Write the actual data to the image file
                image_file.write(data)
                total_bytes_read += len(data)

                # Optional: Print progress every 1 MB
                if total_bytes_read % (1024 * 1024) == 0:
                    print(f"Copied {total_bytes_read // (1024 * 1024)} MB...")

        print(f"Disk image created successfully at {image_path}.")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        # Close the disk handle if it was opened successfully
        if handle:
            win32file.CloseHandle(handle)
if input == 1 :
    image_disk()

SECTOR_SIZE = 512  # Sector size in bytes
FILE_START_SECTOR = 2048  # This is an arbitrary sector where file data starts

def read_sector(file, sector_number):
    """
    Reads a single sector from the disk image.
    """
    file.seek(sector_number * SECTOR_SIZE)
    return file.read(SECTOR_SIZE)

def recover_deleted_files(image_path, output_folder):
    """
    Attempts to recover deleted files from a raw disk image.
    """
    try:
        # Open the raw disk image file
        with open(image_path, 'rb') as disk_image:
            print(f"Opened disk image: {image_path}")

            # For simplicity, let's assume we know the sectors where files could be.
            # Here we're arbitrarily scanning sectors starting from a certain point.
            # This will be system-specific and need adjustments based on your file system.
            current_sector = FILE_START_SECTOR

            recovered_files = []

            while True:
                sector_data = read_sector(disk_image, current_sector)
                
                # If sector_data is all zeros, we've likely hit the end of used space
                if all(byte == 0 for byte in sector_data):
                    break

                # In a real case, we would parse the file system structures
                # (FAT, NTFS, etc.) to identify deleted files, and here
                # we'd look for data blocks marked as deleted.
                
                # For demonstration, let's pretend that any non-zero sector is a deleted file.
                # We write this sector as a file.
                file_name = f"recovered_file_{current_sector}.bin"
                output_path = os.path.join(output_folder, file_name)

                with open(output_path, 'wb') as recovered_file:
                    recovered_file.write(sector_data)

                recovered_files.append(file_name)
                print(f"[+] Recovered file: {file_name}")

                current_sector += 1  # Move to the next sector

            if recovered_files:
                print(f"[+] Recovery complete. {len(recovered_files)} files recovered.")
            else:
                print("[!] No recoverable files found.")
                
    except Exception as e:
        print(f"[!] Error accessing disk image: {e}")
def recoverdata():
    image_path = input("Enter the path to the disk image: ")
    output_folder = input("Enter the folder to save recovered files: ")

    # Create output folder if it doesn't exist
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
        recover_deleted_files(image_path, output_folder)
if input == 2:
    recoverdata()

#image_disk(disk_path, image_path)
#output_dir = r"C:\Users\Nimbalkar\Desktop\New folder\final_Digital_Forensics"
#os.makedirs(output_dir, exist_ok=True)
def save_logs_to_file(log_type, output_file):
    with open(output_file, 'w', encoding='utf-8') as file:
        log_handle = win32evtlog.OpenEventLog('localhost', log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        while True:
            events = win32evtlog.ReadEventLog(log_handle, flags, 0)
            if not events:
                break

            for event in events:
                file.write(f"Event ID: {event.EventID}\n")
                file.write(f"Source: {event.SourceName}\n")
                file.write(f"Time Generated: {event.TimeGenerated}\n")
                file.write(f"Category: {event.EventCategory}\n")
                file.write(f"Description: {event.StringInserts}\n")
                file.write("-" * 50 + "\n")

        win32evtlog.CloseEventLog(log_handle)
    print(f"Logs saved to {output_file}")
Logs_type_List =['Application', 'Security', 'System', 'Windows PowerShell', 'Microsoft-Windows-Sysmon%4Operational']
for Log_type in Logs_type_List:
    save_logs_to_file(log_type=Log_type, output_file=f'{Log_type}.txt')
root_dir = r"C:\\" #change this to your root directory
output_file = r"C:\Users\IEUser\Desktop\file_metadata.txt" #change this to your output file

with open(output_file, 'w', encoding='utf-8') as f:
    for foldername, subfolders, filenames in os.walk(root_dir):
        for filename in filenames:
            file_path = os.path.join(foldername, filename)
            try:
                file_info = os.stat(file_path)
                f.write(f"File Size: {file_info.st_size} bytes\n")
                creation_time = time.ctime(file_info.st_ctime)
                f.write(f"Creation Time: {creation_time}\n")
                # Last modified time
                modified_time = time.ctime(file_info.st_mtime)
                f.write(f"Last Modified Time: {modified_time}\n")
                # Last accessed time
                access_time = time.ctime(file_info.st_atime)
                f.write(f"Last Accessed Time: {access_time}\n")
            except Exception as e:
                f.write(f"[-] Error accessing {file_path}: {str(e)}\n")
                f.write("=" * 60 + "\n")
print(f"[+] Metadata extraction complete. Saved to {output_file}")

# Path to Chrome's History SQLite database
history_db_path = r"C:\Users\IEUser\AppData\Local\Microsoft\Edge\User Data\Default\History"
output_file = r"C:\Users\IEUser\Desktop\edge_history.txt"
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
root_dir = r"C:\\"
output_file = r"C:\Users\IEUser\Desktop\MAlware_analysis.txt"

# Define system folders to skip
system_dirs = [
    "E:\\Program Files",
    "E:\\Program Files (x86)",
    "E:\\ProgramData"
]

def is_system_path(path):
    path = os.path.abspath(path).lower()
    return any(path.startswith(sys_dir.lower()) for sys_dir in system_dirs)

def extract_strings(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
    strings = []
    current_string = []
    for byte in data:
        if 32 <= byte <= 126:
            current_string.append(chr(byte))
        else:
            if current_string:
                strings.append(''.join(current_string))
                current_string = []
    if current_string:
        strings.append(''.join(current_string))
    return strings

def analyze_pe(file_path):
    try:
        pe = pefile.PE(file_path)
        report = [
            f"  Entry Point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}",
            f"  Number of Sections: {len(pe.sections)}"
        ]
        for section in pe.sections:
            report.append(f"  Section: {section.Name.decode(errors='ignore').strip()}")
            report.append(f"    Virtual Size: {hex(section.Misc_VirtualSize)}")
            report.append(f"    Raw Size: {hex(section.SizeOfRawData)}")
        return "\n".join(report)
    except pefile.PEFormatError as e:
        return f"  Error: Not a valid PE file: {e}"

if __name__ == "__main__":
    with open(output_file, 'w', encoding='utf-8') as f:
        for foldername, subfolders, filenames in os.walk(root_dir):
            if is_system_path(foldername):
                continue
            for filename in filenames:
                if filename.lower().endswith('.exe'):
                    file_path = os.path.join(foldername, filename)
                    if not os.path.isfile(file_path):
                        print(f"[!] Skipping invalid path: {file_path}")
                        continue
                    print(f"\n[+] Processing file: {file_path}")
                    try:
                        strings = extract_strings(file_path)
                        f.write(f"\n[+] Strings from {file_path}:\n")
                        for s in strings[:50]:
                            f.write(s + '\n')
                        f.write(f"[+] Total strings found: {len(strings)}\n")

                        f.write(f"\n[+] PE Analysis for {file_path}:\n")
                        f.write(analyze_pe(file_path) + "\n")
                    except Exception as e:
                        f.write(f"\n[!] Error processing {file_path}: {str(e)}\n")
#from itertools import zip
root_dir = r"C:\\Users"
output_file = r"C:\Users\IEUser\Desktop\Extracted_Text.txt"
def get_pixel_pairs(iterable):
    a = iter(iterable)
    return zip(a, a)
def get_LSB(value):
    if value & 1 == 0:
        return '0'
    else:
        return '1'
def extract_message(carrier):
    def to_iter(pix):
        return pix if isinstance(pix, (tuple, list)) else (pix,)
    
    try:
        c_image = Image.open(carrier)
        pixel_list = list(c_image.getdata())
        message = ""
        for pix1, pix2 in get_pixel_pairs(pixel_list):
            message_byte = "0b"
            for p in to_iter(pix1):
                message_byte += get_LSB(p)
            for p in to_iter(pix2):
                message_byte += get_LSB(p)
            if message_byte == "0b00000000":
                break
            message += chr(int(message_byte, 2))
        if len(message) > 200000:
            return 'no hidden message'
        else:
            return message
    except Exception as e:
        return f"[!] Error processing {carrier}: {e}"
def has_hidden_data(image_path):
    try:
        img = Image.open(image_path).convert("RGB")
        pixels = list(img.getdata())
        lsb_bits = ""

        for pixel in pixels[:1000]:  # Sample first 1000 pixels
            for color in pixel:
                lsb_bits += str(color & 1)

        ascii_text = ''.join(
            chr(int(lsb_bits[i:i+8], 2)) for i in range(0, len(lsb_bits)-8, 8)
        )
        return any(c.isprintable() for c in ascii_text)
    except:
        return False

print (extract_message('messagehidden.png'))
with open(output_file, 'w', encoding='utf-8') as f:
    hidden_message = extract_message(file_path)
    f.write(hidden_message + '\n')
# Run on one image
'''eith open(output_file, 'w', encoding='utf-8') as f:
    for foldername, subfolders, filenames in os.walk(root_dir):
        for filename in filenames:
            image_files = ['jpg', 'png', '']
            if filename.endswith(".png"):
                file_path = os.path.join(foldername, filename)
                if has_hidden_data(file_path):
                    hidden_message = extract_message(file_path)
                    if hidden_message:
                        f.write(hidden_message + '\n')'''