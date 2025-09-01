import os
import zipfile
import shutil

"""
Bulk Zipper - Compressed Mode (Delete Originals)
------------------------------------------------
- Zips all files and folders inside target directory.
- Uses compression (ZIP_DEFLATED) → smaller size, slower.
- Originals are permanently deleted after zipping.
"""

main_folder = r"D:\Development\Courses\MERN-Delta++\PART-1"

for item in os.listdir(main_folder):
    item_path = os.path.join(main_folder, item)
    zip_path = os.path.join(main_folder, f"{item}.zip")

    if os.path.exists(zip_path):
        os.remove(zip_path)

    print(f"⏳ Creating (compressed, delete): {item} ...")

    with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        if os.path.isdir(item_path):
            for root, _, files in os.walk(item_path):
                for file in files:
                    full_path = os.path.join(root, file)
                    arcname = os.path.relpath(full_path, start=os.path.dirname(item_path))
                    zf.write(full_path, arcname)
        else:
            zf.write(item_path, arcname=item)

    print(f"✅ Created: {item}.zip")

    if os.path.isdir(item_path):
        shutil.rmtree(item_path)
        print(f"🗑️ Deleted folder: {item}")
    elif os.path.isfile(item_path):
        os.remove(item_path)
        print(f"🗑️ Deleted file: {item}")

print("\n📦 Compressed mode (delete) complete.")
