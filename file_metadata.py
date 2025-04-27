import os
import time
root_dir = r"E:\\"
output_file = r"C:\Users\Nimbalkar\Desktop\file_metadata.txt"

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