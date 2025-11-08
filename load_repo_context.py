#!/usr/bin/env python3
"""
Helper script to load repository context for LLM code generation.
This script helps prepare code context from the authentik repository.
"""

import os
import json
from pathlib import Path
from typing import List, Dict, Set
from collections import defaultdict


class RepositoryContextLoader:
    """Load and organize repository code for LLM context."""
    
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path)
        self.code_extensions = {'.py', '.ts', '.js', '.tsx', '.go', '.jsx'}
        self.ignore_dirs = {
            '.git', 'node_modules', '__pycache__', '.venv', 'venv',
            'dist', 'build', '.next', '.cache', 'locale', 'website'
        }
        
    def get_file_stats(self) -> Dict[str, int]:
        """Get statistics about the repository."""
        stats = {
            'total_files': 0,
            'total_lines': 0,
            'files_by_ext': defaultdict(int),
            'files_by_dir': defaultdict(int)
        }
        
        for root, dirs, files in os.walk(self.repo_path):
            # Filter ignored directories
            dirs[:] = [d for d in dirs if d not in self.ignore_dirs]
            
            for file in files:
                file_path = Path(root) / file
                ext = file_path.suffix
                
                if ext in self.code_extensions:
                    stats['total_files'] += 1
                    stats['files_by_ext'][ext] += 1
                    stats['files_by_dir'][Path(root).relative_to(self.repo_path)] += 1
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            stats['total_lines'] += len(f.readlines())
                    except Exception:
                        pass
        
        return stats
    
    def load_files_by_pattern(
        self, 
        patterns: List[str] = None,
        max_files: int = 50,
        max_lines_per_file: int = 500
    ) -> str:
        """
        Load files matching patterns into context.
        
        Args:
            patterns: List of file patterns or directory names to include
            max_files: Maximum number of files to load
            max_lines_per_file: Maximum lines per file (truncate if larger)
        """
        context_parts = []
        files_loaded = 0
        
        for root, dirs, files in os.walk(self.repo_path):
            dirs[:] = [d for d in dirs if d not in self.ignore_dirs]
            
            for file in files:
                if files_loaded >= max_files:
                    break
                    
                file_path = Path(root) / file
                
                # Filter by extension
                if file_path.suffix not in self.code_extensions:
                    continue
                
                # Filter by patterns if provided
                if patterns:
                    rel_path = str(file_path.relative_to(self.repo_path))
                    if not any(p in rel_path for p in patterns):
                        continue
                
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        lines = f.readlines()
                        
                        # Truncate if too long
                        if len(lines) > max_lines_per_file:
                            content = ''.join(lines[:max_lines_per_file])
                            content += f"\n# ... ({len(lines) - max_lines_per_file} more lines truncated)\n"
                        else:
                            content = ''.join(lines)
                        
                        rel_path = file_path.relative_to(self.repo_path)
                        context_parts.append(f"# File: {rel_path}\n{content}\n")
                        files_loaded += 1
                        
                except Exception as e:
                    print(f"Error reading {file_path}: {e}")
                    continue
        
        return '\n'.join(context_parts)
    
    def load_module_context(self, module_name: str, max_files: int = 20) -> str:
        """Load all files from a specific module/directory."""
        module_path = self.repo_path / module_name
        if not module_path.exists():
            return f"# Module {module_name} not found"
        
        return self.load_files_by_pattern(
            patterns=[module_name],
            max_files=max_files
        )
    
    def create_context_summary(self) -> str:
        """Create a summary of the repository structure."""
        stats = self.get_file_stats()
        
        summary = f"""# Repository Context Summary

## Repository: authentik
## Total Files: {stats['total_files']}
## Total Lines: {stats['total_lines']:,}

## Files by Extension:
"""
        for ext, count in sorted(stats['files_by_ext'].items()):
            summary += f"- {ext}: {count} files\n"
        
        summary += "\n## Key Directories:\n"
        top_dirs = sorted(
            stats['files_by_dir'].items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:20]
        
        for dir_path, count in top_dirs:
            summary += f"- {dir_path}: {count} files\n"
        
        return summary


def main():
    """Example usage."""
    loader = RepositoryContextLoader('/workspace')
    
    # Print statistics
    print("=" * 60)
    print("Repository Statistics")
    print("=" * 60)
    stats = loader.get_file_stats()
    print(f"Total code files: {stats['total_files']}")
    print(f"Total lines of code: {stats['total_lines']:,}")
    print(f"\nFiles by extension:")
    for ext, count in sorted(stats['files_by_ext'].items()):
        print(f"  {ext}: {count}")
    
    # Example: Load specific module
    print("\n" + "=" * 60)
    print("Example: Loading authentik/core module")
    print("=" * 60)
    core_context = loader.load_module_context('authentik/core', max_files=5)
    print(f"Loaded {len(core_context.split('# File:')) - 1} files")
    print(f"Context length: {len(core_context):,} characters")
    
    # Save context summary
    summary = loader.create_context_summary()
    with open('/workspace/repo_summary.md', 'w') as f:
        f.write(summary)
    print("\nSaved repository summary to repo_summary.md")


if __name__ == '__main__':
    main()
