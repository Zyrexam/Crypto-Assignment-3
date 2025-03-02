import sys
import os
import ast
from PIL import Image
import numpy as np
import pytesseract


def decrypt_image(encrypted_image_path, output_path, perm=None):
    img = Image.open(encrypted_image_path)
    pixels = list(img.getdata())
    if perm:
        inv_perm = [0] * len(perm)
        for i, x in enumerate(perm):
            inv_perm[x] = i
        new_pixels = [pixels[x] for x in inv_perm]
    else:
        new_pixels = sorted(pixels)
    decrypted_img = Image.new(img.mode, img.size)
    decrypted_img.putdata(new_pixels)
    decrypted_img.save(output_path)
    return decrypted_img

def extract_character_from_image(img):
    img_gray = img.convert("L")
    threshold = 128
    img_binary = img_gray.point(lambda p: 255 if p > threshold else 0)

    ocr_configs = ['--psm 10', '--psm 8', '--psm 6']
    for config in ocr_configs:
        text = pytesseract.image_to_string(img_gray, config=config).strip()
        if text and len(text) == 1:
            return text
    return "?"

def process_all_images(encrypted_folder, output_folder, serial_no, perm_key_path=None):
    os.makedirs(output_folder, exist_ok=True)
    image_files = sorted([f for f in os.listdir(encrypted_folder) if f.startswith('randomstring') and f.endswith('.png')],
                         key=lambda x: int(x.replace('randomstring', '').replace('.png', '')))
    perm = None
    if perm_key_path and os.path.exists(perm_key_path):
        with open(perm_key_path, 'r') as f:
            perm = ast.literal_eval(f.read())
    random_string = ""
    for img_file in image_files:
        img_path = os.path.join(encrypted_folder, img_file)
        out_path = os.path.join(output_folder, f"decrypted_{img_file}")
        decrypted_img = decrypt_image(img_path, out_path, perm)
        random_string += extract_character_from_image(decrypted_img)
    output_filename = f"{serial_no}_randomstring2.txt"
    with open(os.path.join(output_folder, output_filename), 'w') as f:
        f.write(random_string)
    print(f"Recovered string: {random_string}")
    return random_string


if __name__ == "__main__":
    encrypted_folder = "./encrypted"
    output_folder = "./decrypted"
    serial_no = "b22cs035"
    perm_key_path = "perm.key" if os.path.exists("perm.key") else None
    if not os.path.exists(encrypted_folder):
        print(f"Error: Folder '{encrypted_folder}' not found!")
        sys.exit(1)
    process_all_images(encrypted_folder, output_folder, serial_no, perm_key_path)