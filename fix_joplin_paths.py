import os
import re

# --- Configuration ---
OLD_FOLDER_NAME = "_resources"
NEW_FOLDER_NAME = "resources"
FILE_EXTENSION = ".md"

# The new search pattern is more aggressive:
# It looks for any combination of (../) (e.g., ../../, ../, etc.) 
# followed by the old folder name.
# This fixes the issue of incomplete replacement.
SEARCH_PATTERN = r'(\.\./)+' + re.escape(OLD_FOLDER_NAME) + r'/'

# Replacement text: The absolute path from the website root
# It replaces with: /resources/
REPLACE_TEXT = '/' + NEW_FOLDER_NAME + '/'
# ---------------------

def rename_folder():
    """Renames the folder using os.rename and updates Git's index."""
    try:
        # Use git to rename the folder to keep the history clean
        print(f"Attempting to rename '{OLD_FOLDER_NAME}' to '{NEW_FOLDER_NAME}'...")
        os.system(f"git mv {OLD_FOLDER_NAME} {NEW_FOLDER_NAME}")

        # Fallback for if git is not configured or fails
        if not os.path.exists(NEW_FOLDER_NAME) and os.path.exists(OLD_FOLDER_NAME):
             os.rename(OLD_FOLDER_NAME, NEW_FOLDER_NAME)
        
        print(f"Folder renamed to '{NEW_FOLDER_NAME}'.")
    except Exception as e:
        print(f"Error renaming folder: {e}")


def update_markdown_files():
    """Recursively finds all MD files and performs the path replacement."""
    count = 0
    
    # os.walk is the standard Python way to walk through directories
    for root, _, files in os.walk('.'):
        for file_name in files:
            if file_name.endswith(FILE_EXTENSION):
                file_path = os.path.join(root, file_name)
                
                # Check if the file is the script itself and skip
                if file_path == './fix_paths.py':
                    continue

                try:
                    # Read content
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    # Perform the replacement using re.sub
                    new_content = re.sub(SEARCH_PATTERN, REPLACE_TEXT, content)
                    
                    if new_content != content:
                        # Write back the modified content
                        with open(file_path, 'w', encoding='utf-8') as f:
                            f.write(new_content)
                        
                        print(f"Updated path in: {file_path}")
                        count += 1
                        
                except Exception as e:
                    print(f"Error processing file {file_path}: {e}")

    print(f"\n--- Script Complete ---")
    print(f"Total files updated: {count}")
    print("Please run 'git status' to review and then commit your changes.")


if __name__ == '__main__':
    rename_folder()
    update_markdown_files()