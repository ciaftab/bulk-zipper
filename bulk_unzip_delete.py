import os
import zipfile

# 🔧 Target folder containing zip files
main_folder = r"D:\Development\Courses\Files"

for item in os.listdir(main_folder):
    if item.lower().endswith(".zip"):
        zip_path = os.path.join(main_folder, item)
        extract_folder = os.path.join(main_folder, item[:-4])  # folder with zip name

        print(f"⏳ Extracting: {item} -> {extract_folder}")

        os.makedirs(extract_folder, exist_ok=True)

        try:
            with zipfile.ZipFile(zip_path, 'r') as zf:
                zf.extractall(extract_folder)
            print(f"✅ Done: {item}")

            # Delete original zip after successful extraction
            os.remove(zip_path)
            print(f"🗑️ Deleted original zip: {item}")

        except Exception as e:
            print(f"❌ Failed to unzip {item}: {e}")

print("\n🎉 All zip files extracted & originals deleted!")
