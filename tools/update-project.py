#!/usr/bin/env python3
"""
Lum1na Xcode Project Updater
============================
Automatically adds new source files to Lum1na.xcodeproj/project.pbxproj

Usage:
    python3 tools/update-project.py --scan          # Add all missing files
    python3 tools/update-project.py --add Exploit/CVE_2026_XXX.m --group Exploit
    python3 tools/update-project.py --scan --dry-run  # Preview changes
"""

import os
import sys
import re
import shutil
import argparse
import uuid
import hashlib
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple

# Configuration
PROJECT_NAME = "Lum1na"
SOURCE_EXTENSIONS = {'.h', '.m', '.c', '.cpp', '.cc', '.swift', '.S', '.s'}

# Directories to scan (relative to project root)
SOURCE_DIRECTORIES = [
    'Exploit',
    'KernelMap', 
    'Primitive',
    'Bootstrap',
    'Device',
    'Session',
    'UI',
    'App',
]


class PBXProject:
    """Handles parsing and modification of project.pbxproj"""
    
    def __init__(self, project_path: str):
        self.project_path = Path(project_path)
        self.content = ""
        
        if not self.project_path.exists():
            raise FileNotFoundError(f"Project not found: {project_path}")
        
        with open(self.project_path, 'r', encoding='utf-8', errors='ignore') as f:
            self.content = f.read()
    
    def generate_uuid(self) -> str:
        """Generate Xcode-compatible 24-char UUID"""
        return hashlib.md5(str(uuid.uuid4()).encode()).hexdigest().upper()[:24]
    
    def file_exists_in_project(self, filename: str) -> bool:
        """Check if file is already referenced"""
        pattern = rf'([A-F0-9]{{24}}) /\* {re.escape(filename)} \*/'
        return bool(re.search(pattern, self.content))
    
    def find_group_by_name(self, name: str) -> Optional[str]:
        """Find group ID by name"""
        pattern = rf'([A-F0-9]{{24}}) /\* {re.escape(name)} \*/ = \{{\s*isa = PBXGroup;'
        match = re.search(pattern, self.content)
        return match.group(1) if match else None
    
    def add_file_to_group(self, filepath: Path, group_name: str, dry_run: bool = False) -> Tuple[bool, str]:
        """Add a file to a specific group"""
        filename = filepath.name
        file_ext = filepath.suffix
        
        if self.file_exists_in_project(filename):
            return False, f"Already exists: {filename}"
        
        group_id = self.find_group_by_name(group_name)
        if not group_id:
            return False, f"Group not found: {group_name}"
        
        file_ref_id = self.generate_uuid()
        build_file_id = self.generate_uuid()
        
        # File type mapping
        file_types = {
            '.h': 'sourcecode.c.h',
            '.m': 'sourcecode.c.objc',
            '.c': 'sourcecode.c.c',
            '.cpp': 'sourcecode.cpp.cpp',
            '.swift': 'sourcecode.swift',
        }
        file_type = file_types.get(file_ext, 'sourcecode.c')
        
        if dry_run:
            return True, f"[DRY-RUN] Would add {filename} to {group_name}"
        
        try:
            # 1. Add PBXFileReference
            file_ref_entry = f'''\t\t{file_ref_id} /* {filename} */ = {{
\t\t\tisa = PBXFileReference;
\t\t\tlastKnownFileType = {file_type};
\t\t\tpath = {filename};
\t\t\tsourceTree = "<group>";
\t\t}};'''
            
            pattern = r'(/\* Begin PBXFileReference section \*/\n)(.*?)(/\* End PBXFileReference section \*/)'
            match = re.search(pattern, self.content, re.DOTALL)
            if match:
                insert_pos = match.end(2)
                self.content = self.content[:insert_pos] + file_ref_entry + '\n' + self.content[insert_pos:]
            
            # 2. Add PBXBuildFile (only for .m files, not headers)
            if file_ext == '.m':
                build_file_entry = f'''\t\t{build_file_id} /* {filename} in Sources */ = {{
\t\t\tisa = PBXBuildFile;
\t\t\tfileRef = {file_ref_id} /* {filename} */;
\t\t}};'''
                
                pattern = r'(/\* Begin PBXBuildFile section \*/\n)(.*?)(/\* End PBXBuildFile section \*/)'
                match = re.search(pattern, self.content, re.DOTALL)
                if match:
                    insert_pos = match.end(2)
                    self.content = self.content[:insert_pos] + build_file_entry + '\n' + self.content[insert_pos:]
                
                # 3. Add to Sources build phase
                pattern = r'(isa = PBXSourcesBuildPhase;\s*buildActionMask = \d+;\s*files = \(\s*)(.*?)(\s*\);)'
                match = re.search(pattern, self.content, re.DOTALL)
                if match:
                    new_file = f"\n\t\t\t{build_file_id} /* {filename} in Sources */,"
                    self.content = self.content[:match.end(2)] + new_file + self.content[match.start(3):]
            
            # 4. Add to group
            pattern = rf'({group_id} /\* {re.escape(group_name)} \*/ = \{{\s*isa = PBXGroup;\s*children = \(\s*)(.*?)(\s*\);)'
            match = re.search(pattern, self.content, re.DOTALL)
            if match:
                new_child = f"\n\t\t\t{file_ref_id} /* {filename} */,"
                self.content = self.content[:match.end(2)] + new_child + self.content[match.start(3):]
            
            return True, f"Added {filename} to {group_name}"
            
        except Exception as e:
            return False, f"Error: {str(e)}"
    
    def save(self, backup: bool = True):
        """Save project with optional backup"""
        if backup:
            self._create_backup()
        
        with open(self.project_path, 'w', encoding='utf-8') as f:
            f.write(self.content)
    
    def _create_backup(self):
        """Create timestamped backup"""
        backup_dir = self.project_path.parent.parent.parent / 'tools' / 'backups'
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = backup_dir / f"project.pbxproj.backup.{timestamp}"
        shutil.copy2(self.project_path, backup_path)
        print(f"📦 Backup: tools/backups/project.pbxproj.backup.{timestamp}")


def scan_directory(project_root: Path, dir_name: str) -> List[Path]:
    """Scan directory for source files"""
    dir_path = project_root / dir_name
    if not dir_path.exists():
        return []
    
    files = []
    for ext in SOURCE_EXTENSIONS:
        files.extend(dir_path.glob(f'*{ext}'))
    
    return sorted(files)


def find_missing_files(project_root: Path, project: PBXProject) -> Dict[str, List[Path]]:
    """Find source files not in project"""
    missing = {}
    
    for dir_name in SOURCE_DIRECTORIES:
        files = scan_directory(project_root, dir_name)
        missing_in_dir = [f for f in files if not project.file_exists_in_project(f.name)]
        
        if missing_in_dir:
            missing[dir_name] = missing_in_dir
    
    return missing


def main():
    parser = argparse.ArgumentParser(description='Lum1na Xcode Project Updater')
    parser.add_argument('--scan', action='store_true', help='Scan and add all missing files')
    parser.add_argument('--add', metavar='PATH', help='Add specific file')
    parser.add_argument('--group', metavar='NAME', help='Target group for --add')
    parser.add_argument('--dry-run', action='store_true', help='Preview without changes')
    parser.add_argument('--no-backup', action='store_true', help='Skip backup creation')
    
    args = parser.parse_args()
    
    # Find project root
    script_path = Path(__file__).resolve()
    project_root = script_path.parent.parent
    
    # Find project.pbxproj
    pbxproj_paths = list(project_root.glob('*.xcodeproj/project.pbxproj'))
    if not pbxproj_paths:
        print("❌ Error: No .xcodeproj found!")
        sys.exit(1)
    
    project_path = pbxproj_paths[0]
    print(f"🔍 Lum1na Project Updater")
    print(f"📁 Project: {project_path.relative_to(project_root)}")
    
    # Scan mode
    if args.scan:
        print("\n🔍 Scanning for missing files...")
        project = PBXProject(str(project_path))
        missing = find_missing_files(project_root, project)
        
        if not missing:
            print("✅ All files already in project!")
            return
        
        total = sum(len(files) for files in missing.values())
        print(f"\n📋 Found {total} missing files:")
        for dir_name, files in missing.items():
            print(f"\n  📂 {dir_name}/")
            for f in files:
                print(f"     • {f.name}")
        
        if args.dry_run:
            print("\n📝 Dry run - no changes made")
            return
        
        # Add files
        print("\n📝 Adding files...")
        added = 0
        for dir_name, files in missing.items():
            for filepath in files:
                success, msg = project.add_file_to_group(filepath, dir_name, dry_run=False)
                print(f"  {'✅' if success else '❌'} {msg}")
                if success:
                    added += 1
        
        if added > 0:
            project.save(backup=not args.no_backup)
            print(f"\n✅ Added {added} files!")
            print(f"💾 Build: xcodebuild -project {PROJECT_NAME}.xcodeproj")
        
        return
    
    # Single file mode
    if args.add:
        filepath = project_root / args.add
        if not filepath.exists():
            print(f"❌ File not found: {filepath}")
            sys.exit(1)
        
        group = args.group or next((d for d in SOURCE_DIRECTORIES if d in str(filepath)), None)
        if not group:
            print("❌ Cannot determine group. Use --group")
            sys.exit(1)
        
        project = PBXProject(str(project_path))
        success, msg = project.add_file_to_group(filepath, group, dry_run=args.dry_run)
        print(f"{'✅' if success else '❌'} {msg}")
        
        if success and not args.dry_run:
            project.save(backup=not args.no_backup)
        
        return
    
    parser.print_help()


if __name__ == '__main__':
    main()
