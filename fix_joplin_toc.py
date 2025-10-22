import os
import re
from pathlib import Path

# --- Configuration ---
FILE_EXTENSION = ".md"
SKIP_FOLDERS = {'.git', '.github', '.venv', '__pycache__', 'build', 'node_modules'}

# Options
GENERATE_TOC = True  # Set to False if you just want to remove [toc]
TOC_MAX_LEVEL = 3    # Include headings up to ### (level 3)

def slugify(text):
    """Convert heading text to GitHub-style anchor link."""
    # Convert to lowercase
    slug = text.lower()
    # Remove special characters except spaces and hyphens
    slug = re.sub(r'[^\w\s-]', '', slug)
    # Replace spaces with hyphens
    slug = re.sub(r'[\s]+', '-', slug)
    # Remove multiple consecutive hyphens
    slug = re.sub(r'-+', '-', slug)
    # Strip leading/trailing hyphens
    slug = slug.strip('-')
    return slug

def extract_headings(content):
    """Extract all headings from markdown content."""
    headings = []
    lines = content.split('\n')
    
    for line in lines:
        # Match markdown headings (## Heading)
        match = re.match(r'^(#{1,6})\s+(.+)$', line)
        if match:
            level = len(match.group(1))
            text = match.group(2).strip()
            
            # Skip if it's the title (# at level 1 and first heading)
            if level == 1 and not headings:
                continue
            
            # Only include up to configured level
            if level <= TOC_MAX_LEVEL:
                slug = slugify(text)
                headings.append({
                    'level': level,
                    'text': text,
                    'slug': slug
                })
    
    return headings

def generate_toc_markdown(headings):
    """Generate a markdown table of contents."""
    if not headings:
        return ""
    
    toc_lines = ["## Table of Contents", ""]
    
    # Find the minimum level to adjust indentation
    min_level = min(h['level'] for h in headings) if headings else 2
    
    for heading in headings:
        # Calculate indentation (0 for min_level, 2 spaces per level after)
        indent = "  " * (heading['level'] - min_level)
        # Create link
        link = f"{indent}- [{heading['text']}](#{heading['slug']})"
        toc_lines.append(link)
    
    toc_lines.append("")  # Empty line after TOC
    return "\n".join(toc_lines)

def process_markdown_file(file_path):
    """Process a single markdown file to fix [toc]."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check if file has [toc]
        if '[toc]' not in content.lower():
            return False
        
        # Extract headings if we're generating TOC
        toc_replacement = ""
        if GENERATE_TOC:
            headings = extract_headings(content)
            if headings:
                toc_replacement = generate_toc_markdown(headings)
        
        # Replace [toc] with generated TOC or remove it
        # Case insensitive replacement
        new_content = re.sub(
            r'^\[toc\]\s*$',
            toc_replacement,
            content,
            flags=re.IGNORECASE | re.MULTILINE
        )
        
        # Only write if content changed
        if new_content != content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            return True
        
        return False
    
    except Exception as e:
        print(f"❌ Error processing {file_path}: {e}")
        return False

def main():
    print("=" * 60)
    print("🔧 Joplin [toc] Tag Fixer")
    print("=" * 60)
    
    if GENERATE_TOC:
        print(f"\n📝 Mode: Replace [toc] with generated TOC (max level: {TOC_MAX_LEVEL})")
    else:
        print("\n🗑️  Mode: Remove [toc] tags")
    
    print("\n🔍 Scanning markdown files...")
    
    updated_files = []
    total_files = 0
    
    for root, dirs, files in os.walk('.'):
        # Skip certain folders
        dirs[:] = [d for d in dirs if d not in SKIP_FOLDERS]
        
        for file_name in files:
            if not file_name.endswith(FILE_EXTENSION):
                continue
            
            total_files += 1
            file_path = Path(root) / file_name
            
            if process_markdown_file(file_path):
                updated_files.append(file_path)
                status = "Generated TOC" if GENERATE_TOC else "Removed [toc]"
                print(f"✅ {status}: {file_path.relative_to('.')}")
    
    # Summary
    print("\n" + "=" * 60)
    print("✅ Processing Complete!")
    print("=" * 60)
    print(f"\n📊 Summary:")
    print(f"   Total markdown files scanned: {total_files}")
    print(f"   Files updated: {len(updated_files)}")
    print(f"   Files unchanged: {total_files - len(updated_files)}")
    
    if updated_files:
        print("\n📋 Next steps:")
        print("   1. Review changes with: git diff")
        print("   2. Check a few files to verify TOC looks good")
        print("   3. Commit: git add . && git commit -m 'Fix Joplin [toc] tags'")
        print("   4. Push: git push origin main")
    else:
        print("\n💡 No files needed updating!")

if __name__ == "__main__":
    main()