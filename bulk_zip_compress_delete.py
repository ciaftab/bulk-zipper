import os
import zipfile
import shutil

# 🔧 Change this to your target folder
main_folder = r"D:\Development\Courses\MERN-Delta++\PART-1"

skip_extensions = [
    ".zip", ".rar", ".7z", ".tar", ".gz",
    ".tar.gz", ".tgz", ".bz2", ".xz", ".iso"
]

for item in os.listdir(main_folder):
    if any(item.lower().endswith(ext) for ext in skip_extensions):
        print(f"⏭️ Skipping archive file: {item}")
        continue

    item_path = os.path.join(main_folder, item)
    zip_path = os.path.join(main_folder, f"{item}.zip")

    if os.path.exists(zip_path):
        os.remove(zip_path)

    print(f"⏳ Zipping (compressed): {item} ...")

    with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        if os.path.isdir(item_path):
            for root, _, files in os.walk(item_path):
                for file in files:
                    full_path = os.path.join(root, file)
                    arcname = os.path.relpath(full_path, start=os.path.dirname(item_path))
                    zf.write(full_path, arcname)
        else:
            zf.write(item_path, arcname=item)

    print(f"✅ Done: {item}.zip")

    # Delete original after zipping
    if os.path.isdir(item_path):
        shutil.rmtree(item_path)
        print(f"🗑️ Deleted folder: {item}")
    elif os.path.isfile(item_path):
        os.remove(item_path)
        print(f"🗑️ Deleted file: {item}")

print("\n🎉 All items zipped (compressed) & originals deleted!")
