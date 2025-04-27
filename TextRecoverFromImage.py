from PIL import Image
import os
#from itertools import zip
root_dir = r"E:\\"
output_file = r"C:\Users\Nimbalkar\Desktop\Extracted_Text.txt"
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
def detect_lsb_activity(image_path):
    try:
        img = Image.open(image_path).convert("RGB")
        pixels = list(img.getdata())
        lsb_bits = ""

        for pixel in pixels[:1000]:  # Sample first 1000 pixels
            for color in pixel:
                lsb_bits += str(color & 1)

        ascii_text = ''.join(chr(int(lsb_bits[i:i+8], 2)) for i in range(0, len(lsb_bits)-8, 8))
        if any(c.isprintable() for c in ascii_text):
            f.write(f"[+] Possible hidden content in: {image_path}")
            f.write(ascii_text[:200])
            return True
    except Exception as e:
        print(f"[!] Error: {e}")

# Run on one image
with open(output_file, 'w', encoding='utf-8') as f:
    for foldername, subfolders, filenames in os.walk(root_dir):
        for filename in filenames:
            image_files = ['jpg', 'png', '']
            if filename.endswith(".png"):
                file_path = os.path.join(foldername, filename)
                if detect_lsb_activity(file_path) == True:
                    f.write(extract_message(file_path))
