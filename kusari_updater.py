#!/usr/bin/env python3

import re
import json
import sys
import subprocess
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass


@dataclass
class DependencyUpdate:
    """Represents a dependency update from Kusari scan"""
    package: str
    action: str  # 'update' or 'add'
    old_version: Optional[str] = None
    new_version: str = ""


class KusariUpdater:
    """Parse Kusari scan output and apply dependency updates to package.json"""
    
    def __init__(self):
        self.dependency_updates: List[DependencyUpdate] = []
        self.security_fixes: List[str] = []
        self.dependency_relationships: Dict[str, Dict] = {}
    
    def parse_kusari_output(self, kusari_output: str) -> List[DependencyUpdate]:
        """
        Parse Kusari scan output to extract dependency updates
        
        Args:
            kusari_output: Raw output from kusari repo scan
            
        Returns:
            List of dependency updates found
        """
        lines = kusari_output.split('\n')
        in_dependency_section = False
        
        for line in lines:
            # Check for dependency changes section
            if '## Dependency Changes Introduced' in line:
                in_dependency_section = True
                continue
            
            # Stop parsing if we've reached another section
            if in_dependency_section and line.startswith('##') and 'Dependency' not in line:
                break
            
            # Parse dependency update lines
            if in_dependency_section:
                # Look for lines with package updates
                # The line format includes status indicators and additional columns
                update_match = re.search(
                    r'│\s+(?:⚠️ Flagged|✅ Safe)?\s*│?\s*([^│]+?)\s+│\s+updated\s+│\s+([^→]+)\s+→\s+([^\s│]+)',
                    line
                )
                if not update_match:
                    # Try simpler pattern for lines with different formatting
                    update_match = re.search(
                        r'([^│]+?)\s+│\s+updated\s+│\s+([^→]+)\s+→\s+([^\s│]+)',
                        line
                    )
                
                add_match = re.search(
                    r'│\s+(?:⚠️ Flagged|✅ Safe)?\s*│?\s*([^│]+?)\s+│\s+added\s+│\s+([^\s│]+)',
                    line
                )
                
                if update_match:
                    package_name = update_match.group(1).strip()
                    old_version = update_match.group(2).strip()
                    new_version = update_match.group(3).strip()
                    
                    self.dependency_updates.append(DependencyUpdate(
                        package=package_name,
                        action='update',
                        old_version=old_version,
                        new_version=new_version
                    ))
                elif add_match:
                    package_name = add_match.group(1).strip()
                    version = add_match.group(2).strip()
                    
                    self.dependency_updates.append(DependencyUpdate(
                        package=package_name,
                        action='add',
                        new_version=version
                    ))
            
            # Also look for security advisory information
            if 'CVE-' in line or 'Security Updates Applied:' in line:
                self.security_fixes.append(line.strip())
        
        return self.dependency_updates
    
    def parse_dependency_relationships(self, kusari_output: str) -> Dict[str, Dict]:
        """
        Parse dependency relationship analysis from Kusari output
        
        Args:
            kusari_output: Raw output from kusari repo scan
            
        Returns:
            Dictionary of package relationships
        """
        relationships = {}
        lines = kusari_output.split('\n')
        current_package = None
        
        for line in lines:
            # Look for dependency relationship headers
            if line.startswith('### ') and '(' in line and '→' in line:
                match = re.match(r'###\s+(.+?)\s+\(', line)
                if match:
                    current_package = match.group(1).strip()
                    relationships[current_package] = {
                        'direct_update': '→' in line,
                        'dependent_chains': []
                    }
            
            # Parse dependent chains
            if current_package and '→' in line and re.match(r'^\d+\.', line):
                chain_match = re.match(r'^\d+\.\s+(.+?)→', line)
                if chain_match:
                    parent_package = chain_match.group(1).strip().split('@')[0]
                    if parent_package not in relationships[current_package]['dependent_chains']:
                        relationships[current_package]['dependent_chains'].append(parent_package)
        
        self.dependency_relationships = relationships
        return relationships
    
    def filter_direct_dependencies(self) -> List[DependencyUpdate]:
        """
        Filter dependencies to only include direct dependencies that should be updated
        
        Returns:
            List of direct dependency updates
        """
        direct_updates = []
        
        for update in self.dependency_updates:
            rel = self.dependency_relationships.get(update.package, {})
            
            # Check if this is a direct dependency or needs to be updated through parent
            if not rel or rel.get('direct_update', False) or not rel.get('dependent_chains', []):
                # Direct dependency - update it directly
                direct_updates.append(update)
            else:
                # Transitive dependency - will be updated through parent packages
                chains = ', '.join(rel['dependent_chains'])
                print(f"  ℹ️  {update.package} will be updated transitively through: {chains}")
        
        return direct_updates
    
    def update_package_json(self, package_json_path: Path, updates: List[DependencyUpdate]) -> bool:
        """
        Update package.json with new dependency versions
        
        Args:
            package_json_path: Path to package.json file
            updates: List of dependency updates to apply
            
        Returns:
            True if package.json was modified, False otherwise
        """
        try:
            with open(package_json_path, 'r') as f:
                package_json = json.load(f)
            
            modified = False
            
            for update in updates:
                pkg_name = update.package
                new_version = update.new_version
                
                # Check in dependencies
                if 'dependencies' in package_json and pkg_name in package_json['dependencies']:
                    current_version = package_json['dependencies'][pkg_name]
                    package_json['dependencies'][pkg_name] = f"^{new_version}"
                    print(f"  ✅ Updated {pkg_name}: {current_version} → ^{new_version}")
                    modified = True
                
                # Check in devDependencies
                elif 'devDependencies' in package_json and pkg_name in package_json['devDependencies']:
                    current_version = package_json['devDependencies'][pkg_name]
                    package_json['devDependencies'][pkg_name] = f"^{new_version}"
                    print(f"  ✅ Updated {pkg_name}: {current_version} → ^{new_version}")
                    modified = True
                
                # Handle new packages
                elif update.action == 'add':
                    # Skip platform-specific packages that npm will handle automatically
                    if '@rollup/rollup-' in pkg_name or '@esbuild/' in pkg_name:
                        print(f"  ⏭️  Skipping platform-specific package: {pkg_name}")
                        continue
                    print(f"  ℹ️  New package {pkg_name} may be added as transitive dependency")
            
            if modified:
                with open(package_json_path, 'w') as f:
                    json.dump(package_json, f, indent=2)
                    f.write('\n')
                return True
            
            return False
            
        except Exception as e:
            raise Exception(f"Failed to update package.json: {str(e)}")
    
    def run_npm_install(self) -> bool:
        """
        Run npm install to update package-lock.json
        
        Returns:
            True if successful, False otherwise
        """
        print('\n🔄 Running npm install to update dependencies...')
        try:
            result = subprocess.run(
                ['npm', 'install'],
                capture_output=True,
                text=True,
                check=True
            )
            
            if result.stderr and 'npm WARN' not in result.stderr:
                print(f"  ⚠️  npm install warnings: {result.stderr}")
            
            print('  ✅ Dependencies updated successfully')
            return True
            
        except subprocess.CalledProcessError as e:
            raise Exception(f"npm install failed: {e.stderr}")
    
    def execute(self, kusari_output: str, package_json_path: Optional[Path] = None, 
                skip_install: bool = False) -> None:
        """
        Main execution function to parse Kusari output and update dependencies
        
        Args:
            kusari_output: Raw output from kusari repo scan
            package_json_path: Path to package.json (defaults to current directory)
            skip_install: If True, skip running npm install
        """
        try:
            print('🚀 Kusari Dependency Updater\n')
            
            # Parse Kusari output
            print('📋 Parsing Kusari scan output...')
            updates = self.parse_kusari_output(kusari_output)
            self.parse_dependency_relationships(kusari_output)
            
            if not updates:
                print('  ℹ️  No dependency updates found in Kusari output')
                return
            
            print(f'  📦 Found {len(updates)} dependency changes\n')
            
            # Filter to only direct dependencies
            print('🔍 Analyzing dependency relationships...')
            direct_updates = self.filter_direct_dependencies()
            print(f'  📦 {len(direct_updates)} direct dependencies to update\n')
            
            # Update package.json
            if package_json_path is None:
                package_json_path = Path.cwd() / 'package.json'
            
            print('📝 Updating package.json...')
            updated = self.update_package_json(package_json_path, direct_updates)
            
            if updated:
                # Run npm install
                if not skip_install:
                    self.run_npm_install()
                
                print('\n✨ Update complete!')
                
                # Show security fixes if any
                if self.security_fixes:
                    print('\n🔒 Security fixes applied:')
                    unique_fixes = list(set(self.security_fixes))
                    for fix in unique_fixes[:5]:
                        if 'CVE-' in fix:
                            print(f"  • {fix[:100]}...")
            else:
                print('\n  ℹ️  No updates were necessary')
                
        except Exception as e:
            print(f'\n❌ Error: {str(e)}')
            sys.exit(1)


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='Parse Kusari scan output and update npm dependencies'
    )
    parser.add_argument(
        '--file', '-f',
        type=str,
        help='Path to file containing Kusari scan output'
    )
    parser.add_argument(
        '--package-json', '-p',
        type=str,
        help='Path to package.json file (default: ./package.json)'
    )
    parser.add_argument(
        '--skip-install',
        action='store_true',
        help='Skip running npm install after updating package.json'
    )
    
    args = parser.parse_args()
    
    updater = KusariUpdater()
    
    # Get Kusari output from file or stdin
    if args.file:
        try:
            with open(args.file, 'r') as f:
                kusari_output = f.read()
        except FileNotFoundError:
            print(f"❌ Error: File not found: {args.file}")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Error reading file: {str(e)}")
            sys.exit(1)
    else:
        # Read from stdin
        if sys.stdin.isatty():
            print('No input provided. Usage:')
            print('  kusari repo scan | python kusari_updater.py')
            print('  python kusari_updater.py --file <path-to-kusari-output>')
            sys.exit(1)
        
        kusari_output = sys.stdin.read()
    
    # Execute the updater
    package_json_path = Path(args.package_json) if args.package_json else None
    updater.execute(kusari_output, package_json_path, args.skip_install)


if __name__ == '__main__':
    main()