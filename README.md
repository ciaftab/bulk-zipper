# Bulk Zipper (Fast, No Compression)

A Python utility script to **bulk-zip files and folders** inside a target directory.

## ✨ Features
- Creates a separate `.zip` file for each file/folder inside the target directory.
- Preserves the original folder structure inside each zip.
- Uses **no compression** for maximum speed (files are just wrapped).
- Automatically deletes the original after successful zipping.
- Requires **no external dependencies** (pure Python standard library).

⚠️ **Warning**: This script deletes the original files/folders after zipping.  
Always keep a backup if data is important.

---

## 🚀 Usage

1. Clone this repository or download `bulk_zip.py`.
2. Edit the script to set your target directory:
   ```python
   main_folder = r"D:\path\to\your\folder"
