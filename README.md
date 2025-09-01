# Bulk Zipper 🗜️

Bulk Zipper is a lightweight Python utility to **batch-zip multiple files and folders** inside a target directory.  
It provides **4 modes** depending on your needs: fast wrapping (no compression) or compressed zipping, with or without deleting originals.

---

## ✨ Features
- 🔄 Automatically zips **every file and folder** in a given directory.
- ⚡ **Fast mode** (no compression, just wrapping in `.zip`).
- 📦 **Compressed mode** (smaller size, slower).
- 🗑️ Option to **delete originals** after zipping.
- 🖥 Works on **Windows, macOS, and Linux**.
- 🐍 Pure Python – no external dependencies.

---

## 📂 Modes Overview

| Mode | Compression | Delete Originals | Script |
|------|-------------|------------------|--------|
| ⚡ Fast + Delete | ❌ None (ZIP_STORED) | ✅ Yes | `bulk_zip_fast_delete.py` |
| ⚡ Fast + Keep | ❌ None (ZIP_STORED) | ❌ No | `bulk_zip_fast_keep.py` |
| 📦 Compressed + Delete | ✅ ZIP_DEFLATED | ✅ Yes | `bulk_zip_compress_delete.py` |
| 📦 Compressed + Keep | ✅ ZIP_DEFLATED | ❌ No | `bulk_zip_compress_keep.py` |

---

## 🚀 Quick Start

1. **Clone the repo**
   ```bash
   git clone https://github.com/ciaftab/bulk-zipper.git
   cd bulk-zipper
