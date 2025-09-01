import sys
import os
import zipfile
import shutil
from pathlib import Path

# Check internet connection
def check_internet():
    import socket
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=2)
        return True
    except Exception:
        return False

# Try importing dependencies if online
ONLINE = check_internet()
COLOR = False
TQDM = False

if ONLINE:
    # Dependency auto-install
    import subprocess
    import importlib

    def install(package):
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        except Exception:
            pass

    for package in ["tqdm", "colorama"]:
        try:
            importlib.import_module(package)
        except ImportError:
            print(f"[INFO] '{package}' not found. Installing...")
            install(package)

    try:
        from tqdm import tqdm
        TQDM = True
    except ImportError:
        TQDM = False
    try:
        from colorama import Fore, Style, init
        init(autoreset=True, strip=False)
        COLOR = True
    except ImportError:
        COLOR = False

# Simple color functions
def ok(text): return (Fore.GREEN + text) if COLOR else text
def info(text): return (Fore.CYAN + text) if COLOR else text
def warn(text): return (Fore.YELLOW + text) if COLOR else text
def err(text): return (Fore.RED + text) if COLOR else text
def bold(text): return (Style.BRIGHT + text) if COLOR else text

def fast_zip_contents(folder_path, zip_path, delete_original=False):
    files_list = [str(Path(root) / file)
                  for root, _, files in os.walk(folder_path)
                  for file in files]
    if TQDM:
        iterator = tqdm(files_list, desc=f"Zipping {folder_path.name}", ascii=True)
    else:
        print(f"[INFO] Zipping {folder_path.name} ({len(files_list)} files)...")
        iterator = files_list
    for i, full_path in enumerate(iterator, 1):
        arcname = Path(full_path).relative_to(folder_path)
        with zipfile.ZipFile(zip_path, 'a', compression=zipfile.ZIP_STORED) as zf:
            zf.write(full_path, arcname)
        if not TQDM:
            print(f"[{i}/{len(files_list)}] Zipped: {arcname}")
    print(ok(f"[OK] Zipped: {zip_path.name}"))
    if delete_original:
        shutil.rmtree(folder_path)
        print(warn(f"[DEL] Deleted folder: {folder_path.name}"))

def slow_zip_contents(folder_path, zip_path, delete_original=False):
    files_list = [str(Path(root) / file)
                  for root, _, files in os.walk(folder_path)
                  for file in files]
    if TQDM:
        iterator = tqdm(files_list, desc=f"Zipping {folder_path.name}", ascii=True)
    else:
        print(f"[INFO] Zipping {folder_path.name} ({len(files_list)} files)...")
        iterator = files_list
    for i, full_path in enumerate(iterator, 1):
        arcname = Path(full_path).relative_to(folder_path)
        with zipfile.ZipFile(zip_path, 'a', compression=zipfile.ZIP_DEFLATED) as zf:
            zf.write(full_path, arcname)
        if not TQDM:
            print(f"[{i}/{len(files_list)}] Zipped: {arcname}")
    print(ok(f"[OK] Zipped: {zip_path.name}"))
    if delete_original:
        shutil.rmtree(folder_path)
        print(warn(f"[DEL] Deleted folder: {folder_path.name}"))

def fast_zip_file(item_path, zip_path, delete_original=False):
    with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_STORED) as zf:
        zf.write(item_path, arcname=item_path.name)
    print(ok(f"[OK] Zipped file: {zip_path.name}"))
    if delete_original:
        item_path.unlink()
        print(warn(f"[DEL] Deleted file: {item_path.name}"))

def slow_zip_file(item_path, zip_path, delete_original=False):
    with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        zf.write(item_path, arcname=item_path.name)
    print(ok(f"[OK] Zipped file: {zip_path.name}"))
    if delete_original:
        item_path.unlink()
        print(warn(f"[DEL] Deleted file: {item_path.name}"))

def unzip(zip_path, extract_to, delete_original=False):
    with zipfile.ZipFile(zip_path, 'r') as zf:
        members = zf.namelist()
        if TQDM:
            iterator = tqdm(members, desc=f"Unzipping {zip_path.name}", ascii=True)
        else:
            print(info(f"[INFO] Extracting {zip_path.name} ({len(members)} items)..."))
            iterator = members
        for i, member in enumerate(iterator, 1):
            zf.extract(member, extract_to)
            if not TQDM:
                print(f"[{i}/{len(members)}] Unzipped: {member}")
    print(ok(f"[OK] Unzipped: {zip_path.name} -> {extract_to}"))
    if delete_original:
        zip_path.unlink()
        print(warn(f"[DEL] Deleted original zip: {zip_path.name}"))

def get_items_in_folder(main_folder, skip_archives=True):
    skip_extensions = [
        ".zip", ".rar", ".7z", ".tar", ".gz", ".tar.gz", ".tgz", ".bz2", ".xz", ".iso"
    ] if skip_archives else []
    items = []
    for item in os.listdir(main_folder):
        item_path = Path(main_folder) / item
        if skip_archives and any(item.lower().endswith(ext) for ext in skip_extensions):
            continue
        items.append(item_path)
    return items

def print_banner():
    print(bold("="*50))
    print(bold("        Bulk Zipper Tool (by ciaftab)"))
    print(bold("="*50))
    print(bold("Simple | Fast | Professional | Classic CLI\n"))
    if not ONLINE:
        print(warn("No internet connection detected. Running in classic mode (no colors, no progress bar).\n"))

def main_menu():
    print(bold("Select operation:"))
    print(" 1. Fast zip folder contents [no compression]")
    print(" 2. Slow zip folder contents [with compression]")
    print(" 3. Slow zip folder contents [compression + delete original]")
    print(" 4. Fast zip folder contents [no compression + delete original]")
    print(" 5. Unzip")
    print(" 6. Unzip + delete original zip")
    print(" 0. Exit")
    choice = input(warn("\nEnter your choice [0-6]: ")).strip()
    if choice == '0':
        print(info("Bye! Thank you for using Bulk Zipper Tool."))
        exit(0)
    return choice

def get_path_input():
    path = input(warn("Enter the folder path: ")).strip()
    if path.lower() == 'exit':
        print(info("Bye! Thank you for using Bulk Zipper Tool."))
        exit(0)
    path_obj = Path(path)
    if not path_obj.exists():
        print(err("[ERR] Path does not exist."))
        return get_path_input()
    return path_obj

def main():
    print_banner()
    try:
        while True:
            choice = main_menu()
            if choice not in {'1', '2', '3', '4', '5', '6'}:
                print(err("[ERR] Invalid choice. Try again."))
                continue

            item_path = get_path_input()

            # Zipping
            if choice in {'1', '2', '3', '4'}:
                items = get_items_in_folder(item_path)
                if not items:
                    print(warn("[WARN] No files/folders to zip in this path."))
                    continue
                for item in items:
                    zip_path = item_path / f"{item.name}.zip"
                    if zip_path.exists():
                        zip_path.unlink()
                    if item.is_dir():
                        if choice == '1':
                            fast_zip_contents(item, zip_path, delete_original=False)
                        elif choice == '2':
                            slow_zip_contents(item, zip_path, delete_original=False)
                        elif choice == '3':
                            slow_zip_contents(item, zip_path, delete_original=True)
                        elif choice == '4':
                            fast_zip_contents(item, zip_path, delete_original=True)
                    else:
                        if choice == '1':
                            fast_zip_file(item, zip_path, delete_original=False)
                        elif choice == '2':
                            slow_zip_file(item, zip_path, delete_original=False)
                        elif choice == '3':
                            slow_zip_file(item, zip_path, delete_original=True)
                        elif choice == '4':
                            fast_zip_file(item, zip_path, delete_original=True)
                print(ok("\n== All items processed successfully ==\n"))

            # Unzipping
            elif choice in {'5', '6'}:
                zip_items = [p for p in item_path.iterdir() if p.is_file() and p.suffix.lower() == ".zip"]
                if not zip_items:
                    print(warn("[WARN] No zip files found in this folder."))
                    continue
                for zip_file in zip_items:
                    extract_to = item_path / zip_file.stem
                    extract_to.mkdir(exist_ok=True)
                    unzip(zip_file, extract_to, delete_original=(choice == '6'))
                print(ok("\n== All zip files extracted ==\n"))

            again = input(warn("Run again? (y/n): ")).strip().lower()
            if again == 'exit' or again != 'y':
                print(info("Bye! Thank you for using Bulk Zipper Tool."))
                break
    except KeyboardInterrupt:
        print(err("\n[ABORT] Process aborted by user (Ctrl+C). Bye!"))

if __name__ == "__main__":
    main()
