#!/usr/bin/env python3
"""
Quick runner script for security policy tests
Sets up paths correctly and runs tests from any directory
"""

import os
import sys
import subprocess

# Get the project root (parent of tests directory)
test_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(test_dir)

# Change to project root for tests to find policy files
os.chdir(project_root)

# Add server to Python path
server_dir = os.path.join(project_root, 'server')
if server_dir not in sys.path:
    sys.path.insert(0, server_dir)

# Run pytest from project root
args = sys.argv[1:] if len(sys.argv) > 1 else ['-v']
test_file = os.path.join(test_dir, 'test_sftp.py')

cmd = [sys.executable, '-m', 'pytest', test_file] + args

print(f"Running tests from: {project_root}")
print(f"Test file: {test_file}")
print(f"Command: {' '.join(cmd)}\n")

sys.exit(subprocess.call(cmd))
