import os
import re

# --- Configuration ---
OLD_FOLDER_NAME = "resources"
NEW_FOLDER_NAME = "_resources"
FILE_EXTENSION = ".md"
SCRIPT_NAME = "fix_paths.py"  # name of this script
# ---------------------

# Regex to match:
# - ../../resources/
# - ../resources/
# - /resources/
# - resources/
SEARCH_PATTERN = re.compile(r'((\.\./)+|/?)' + re.escape(OLD_FOLDER_NAME) + r'/')

REPLACE_TEXT = '/' + NEW_FOLDER_NAME + '/'

SKIP_FOLDERS = {'.git', '.github', '.venv', '__pycache__'}  # add more if needed

def rename_folder():
    """Renames the folder using git mv or os.rename."""
    try:
        print(f"Attempting to rename '{OLD_FOLDER_NAME}' to '{NEW_FOLDER_NAME}'...")
        os.system(f"git mv {OLD_FOLDER_NAME} {NEW_FOLDER_NAME}")

        # Fallback if git fails
        if not os.path.exists(NEW_FOLDER_NAME) and os.path.exists(OLD_FOLDER_NAME):
            os.rename(OLD_FOLDER_NAME, NEW_FOLDER_NAME)

        print(f"Folder renamed to '{NEW_FOLDER_NAME}'.")
    except Exception as e:
        print(f"Error renaming folder: {e}")

def update_markdown_files():
    """Recursively updates Markdown links to point to /_resources/"""
    count = 0
    for root, dirs, files in os.walk('.'):
        # Skip hidden/system folders
        dirs[:] = [d for d in dirs if d not in SKIP_FOLDERS]

        for file_name in files:
            if not file_name.endswith(FILE_EXTENSION):
                continue
            file_path = os.path.join(root, file_name)

            # Skip the script itself
            if file_name == SCRIPT_NAME:
                continue

            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                new_content = SEARCH_PATTERN.sub(REPLACE_TEXT, content)

                if new_content != content:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(new_content)
                    print(f"Updated paths in: {file_path}")
                    count += 1

            except Exception as e:
                print(f"Error processing {file_path}: {e}")

    print("\n--- Script Complete ---")
    print(f"Total Markdown files updated: {count}")
    print("Review changes with 'git status', then commit and push.")

if __name__ == "__main__":
    rename_folder()
    update_markdown_files()
