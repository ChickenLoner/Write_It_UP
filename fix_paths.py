import os
import re
import shutil
from pathlib import Path

# --- Configuration ---
OLD_FOLDER_NAME = "_resources"
NEW_FOLDER_NAME = "resources"
FILE_EXTENSION = ".md"
SKIP_FOLDERS = {'.git', '.github', '.venv', '__pycache__', 'build', 'node_modules'}

# Image extensions to look for
IMAGE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.bmp'}

def find_and_merge_resources():
    """Find all _resources folders and merge them into the main resources folder."""
    root_resources = Path(NEW_FOLDER_NAME)
    root_resources.mkdir(exist_ok=True)
    
    moved_count = 0
    
    # Walk through all directories
    for root, dirs, files in os.walk('.'):
        # Skip certain folders
        dirs[:] = [d for d in dirs if d not in SKIP_FOLDERS]
        
        root_path = Path(root)
        
        # Check if this directory has a _resources folder
        old_resources = root_path / OLD_FOLDER_NAME
        if old_resources.exists() and old_resources.is_dir():
            print(f"\n📁 Found: {old_resources}")
            
            # Move all files from _resources to main resources folder
            for item in old_resources.iterdir():
                if item.is_file():
                    dest = root_resources / item.name
                    
                    # Handle duplicate filenames
                    if dest.exists():
                        # Add suffix if file already exists
                        stem = dest.stem
                        suffix = dest.suffix
                        counter = 1
                        while dest.exists():
                            dest = root_resources / f"{stem}_{counter}{suffix}"
                            counter += 1
                    
                    shutil.move(str(item), str(dest))
                    print(f"   ✅ Moved: {item.name} → {dest}")
                    moved_count += 1
            
            # Remove the now-empty _resources folder
            try:
                old_resources.rmdir()
                print(f"   🗑️  Removed empty folder: {old_resources}")
            except OSError:
                print(f"   ⚠️  Could not remove {old_resources} (may not be empty)")
    
    return moved_count

def update_markdown_files():
    """Update all markdown files to point to /resources/ instead of _resources."""
    
    # Patterns to match various ways _resources might be referenced
    patterns = [
        # Match: ../_resources/ or ../../_resources/ etc.
        (re.compile(r'(\.\./)+' + re.escape(OLD_FOLDER_NAME) + r'/'), f'/{NEW_FOLDER_NAME}/'),
        # Match: /_resources/
        (re.compile(r'/' + re.escape(OLD_FOLDER_NAME) + r'/'), f'/{NEW_FOLDER_NAME}/'),
        # Match: _resources/ (relative)
        (re.compile(r'(?<![/\w])' + re.escape(OLD_FOLDER_NAME) + r'/'), f'/{NEW_FOLDER_NAME}/'),
    ]
    
    updated_files = 0
    total_replacements = 0
    
    for root, dirs, files in os.walk('.'):
        # Skip certain folders
        dirs[:] = [d for d in dirs if d not in SKIP_FOLDERS]
        
        for file_name in files:
            if not file_name.endswith(FILE_EXTENSION):
                continue
            
            file_path = Path(root) / file_name
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                new_content = content
                file_changes = 0
                
                # Apply all patterns
                for pattern, replacement in patterns:
                    matches = len(pattern.findall(new_content))
                    if matches > 0:
                        new_content = pattern.sub(replacement, new_content)
                        file_changes += matches
                
                # Write back if changed
                if new_content != content:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(new_content)
                    
                    print(f"📝 Updated: {file_path.relative_to('.')} ({file_changes} replacements)")
                    updated_files += 1
                    total_replacements += file_changes
            
            except Exception as e:
                print(f"❌ Error processing {file_path}: {e}")
    
    return updated_files, total_replacements

def verify_resources():
    """Verify the resources folder and list its contents."""
    resources_path = Path(NEW_FOLDER_NAME)
    
    if not resources_path.exists():
        print("\n⚠️  Warning: 'resources' folder does not exist!")
        return 0
    
    files = list(resources_path.iterdir())
    image_files = [f for f in files if f.suffix.lower() in IMAGE_EXTENSIONS]
    
    print(f"\n📊 Resources folder summary:")
    print(f"   Total files: {len(files)}")
    print(f"   Image files: {len(image_files)}")
    
    return len(files)

def main():
    print("=" * 60)
    print("🔧 Joplin Resources Migration Tool")
    print("=" * 60)
    
    # Step 1: Find and merge all _resources folders
    print("\n📦 Step 1: Moving files from _resources to resources...")
    moved_count = find_and_merge_resources()
    print(f"\n✅ Moved {moved_count} files to '{NEW_FOLDER_NAME}' folder")
    
    # Step 2: Update markdown file paths
    print("\n📝 Step 2: Updating markdown file paths...")
    updated_files, total_replacements = update_markdown_files()
    print(f"\n✅ Updated {updated_files} markdown files ({total_replacements} total replacements)")
    
    # Step 3: Verify resources
    print("\n🔍 Step 3: Verifying resources folder...")
    verify_resources()
    
    # Final summary
    print("\n" + "=" * 60)
    print("✅ Migration Complete!")
    print("=" * 60)
    print("\n📋 Next steps:")
    print("   1. Review changes with: git status")
    print("   2. Check a few markdown files to verify paths are correct")
    print("   3. Commit changes: git add . && git commit -m 'Fix Joplin resource paths'")
    print("   4. Push to GitHub: git push origin main")
    print("\n💡 Tip: Your site will automatically rebuild with the updated paths!")

if __name__ == "__main__":
    main()