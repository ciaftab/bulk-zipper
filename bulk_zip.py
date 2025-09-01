import os
import zipfile
import shutil

"""
Bulk Zipper Script
------------------
This script zips all files and folders inside a target directory.
- Each item is zipped individually with the same name + ".zip".
- The root folder structure is preserved inside each zip.
- Original files/folders are permanently deleted after successful zipping.

⚠️ Warning: This script deletes the originals. Make sure to back up before running.
"""

# Configure your main folder here
main_folder = r"D:\Development\Courses\MERN-Delta++\PART-1"

for item in os.listdir(main_folder):
    item_path = os.path.join(main_folder, item)
    zip_path = os.path.join(main_folder, f"{item}.zip")

    # Remove existing zip if present
    if os.path.exists(zip_path):
        os.remove(zip_path)

    print(f"⏳ Creating zip: {item} ...")

    with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_STORED) as zf:
        if os.path.isdir(item_path):
            for root, _, files in os.walk(item_path):
                for file in files:
                    full_path = os.path.join(root, file)
                    arcname = os.path.relpath(full_path, start=os.path.dirname(item_path))
                    zf.write(full_path, arcname)
        else:
            zf.write(item_path, arcname=item)

    print(f"✅ Created: {item}.zip")

    # Delete original after successful zip
    if os.path.isdir(item_path):
        shutil.rmtree(item_path)
        print(f"🗑️ Deleted original folder: {item}")
    elif os.path.isfile(item_path):
        os.remove(item_path)
        print(f"🗑️ Deleted original file: {item}")

print("\n🎉 All items have been zipped and originals deleted successfully.")
