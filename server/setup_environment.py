import os
import json
import csv
import hashlib
import secrets
import base64
from pathlib import Path

directories = [
        # Public area - accessible to all
        'sftp_root/public',
        'sftp_root/public/announcements',
        'sftp_root/public/shared',
        'sftp_root/public/readme',
        
        # Internal area - for internal users only
        'sftp_root/internal',
        'sftp_root/internal/projects',
        'sftp_root/internal/projects/project_alpha',
        'sftp_root/internal/projects/project_beta',
        'sftp_root/internal/reports',
        'sftp_root/internal/reports/2024',
        'sftp_root/internal/documentation',
        
        # Confidential area - high security
        'sftp_root/confidential',
        'sftp_root/confidential/finance',
        'sftp_root/confidential/finance/budgets',
        'sftp_root/confidential/finance/audits',
        'sftp_root/confidential/strategy',
        'sftp_root/confidential/hr',
        'sftp_root/confidential/.hidden',  # Hidden directory for CTF flag
        
        # User home directories
        'sftp_root/home',
        'sftp_root/home/alice',
        'sftp_root/home/alice/documents',
        'sftp_root/home/alice/downloads',
        'sftp_root/home/alice/.ssh',
        'sftp_root/home/bob',
        'sftp_root/home/bob/documents',
        'sftp_root/home/bob/projects',
        'sftp_root/home/eve',
        'sftp_root/home/eve/public_only',
        'sftp_root/home/charlie',
        'sftp_root/home/charlie/analysis',
        
        # Shared workspace
        'sftp_root/shared',
        'sftp_root/shared/team_alpha',
        'sftp_root/shared/team_beta',
        'sftp_root/shared/temp',
        
        # Admin area
        'sftp_root/admin',
        'sftp_root/admin/logs',
        'sftp_root/admin/configs',
        'sftp_root/admin/backups',
        
        # Test area for various permission scenarios
        'sftp_root/test',
        'sftp_root/test/read_only',
        'sftp_root/test/write_only',
        'sftp_root/test/no_access',
    ]

def create_directory_structure():
    """Create the jail_root directory structure for testing."""   
    
    print("Creating directory structure...")
    for dir_path in directories:
        os.makedirs(dir_path, exist_ok=True)
    
    # Create sample files with different content
    sample_files = {
        'sftp_root/public/welcome.txt': 'Welcome to the SFTP server!\nThis is a public file.',
        'sftp_root/public/announcements/notice.txt': 'System maintenance scheduled for next week.',
        'sftp_root/public/shared/public_data.csv': 'id,name,status\n1,Item1,active\n2,Item2,inactive',
        
        'sftp_root/internal/projects/project_alpha/README.md': '# Project Alpha\n\nInternal project documentation.',
        'sftp_root/internal/projects/project_beta/status.txt': 'Project Beta: In Progress\nDeadline: Q4 2024',
        'sftp_root/internal/reports/2024/q3_report.txt': 'Q3 2024 Report\n[Internal Use Only]',
        'sftp_root/internal/documentation/guide.md': '# Internal Guide\n\nFor employees only.',
        
        'sftp_root/confidential/finance/budgets/2024_budget.txt': 'CONFIDENTIAL: 2024 Annual Budget\n[Restricted Access]',
        'sftp_root/confidential/finance/audits/audit_2024.txt': 'CONFIDENTIAL: Audit Results 2024',
        'sftp_root/confidential/strategy/roadmap.txt': 'CONFIDENTIAL: 5-Year Strategic Roadmap',
        'sftp_root/confidential/hr/salaries.csv': 'CONFIDENTIAL: Employee,Salary\nDO NOT SHARE',
        'sftp_root/confidential/.hidden/flag.txt': 'FLAG{sftp_security_challenge_2024}\n\nCongratulations! You found the hidden flag.',
        
        'sftp_root/home/alice/documents/personal.txt': "Alice's personal notes",
        'sftp_root/home/alice/documents/work.txt': "Alice's work documents",
        'sftp_root/home/bob/documents/draft.txt': "Bob's draft document",
        'sftp_root/home/bob/projects/code.py': "# Bob's Python code\nprint('Hello, World!')",
        'sftp_root/home/eve/public_only/notes.txt': "Eve's public notes",
        'sftp_root/home/charlie/analysis/data.csv': "Charlie's analysis data",
        
        'sftp_root/shared/team_alpha/collaboration.txt': 'Team Alpha shared workspace',
        'sftp_root/shared/team_beta/planning.md': '# Team Beta Planning\n\nShared planning document',
        'sftp_root/shared/temp/scratch.txt': 'Temporary shared file',
        
        'sftp_root/admin/logs/access.log': '[ADMIN ONLY] Access log entries',
        'sftp_root/admin/configs/server.conf': '[ADMIN ONLY] Server configuration',
        'sftp_root/admin/backups/backup_list.txt': '[ADMIN ONLY] Backup inventory',
        
        'sftp_root/test/read_only/readonly.txt': 'This file should be read-only for most users',
        'sftp_root/test/write_only/writeonly.txt': 'This file is for write-only testing',
        'sftp_root/test/no_access/forbidden.txt': 'This file should not be accessible to regular users',
    }
    
    for file_path, content in sample_files.items():
        with open(file_path, 'w') as f:
            f.write(content)
    
    print(f"\n✅ Created {len(directories)} directories and {len(sample_files)} files")

def create_role_perms_csv():
    """Create role_perms.csv with comprehensive role-based permissions."""
    
    # Define role permissions
    # Format: role, resource, read, write, delete
    permissions = [
        # Admin role - full access to everything
        ['admin', '/', 'Y', 'Y', 'Y','Y'],
        ['admin', '/admin', 'Y', 'Y', 'Y','Y'],
        ['admin', '/confidential', 'Y', 'Y', 'Y','Y'],
        ['admin', '/confidential/.hidden', 'Y', 'Y', 'Y','Y'],

        # Security role - read access to confidential, manage security areas
        ['security', '/confidential', 'Y', 'N', 'N','N'],
        ['security', '/admin/logs', 'Y', 'Y', 'N','N'],
        ['security', '/admin/configs', 'Y', 'Y', 'N','N'],
        
        # Finance role - access to finance directories
        ['finance', '/confidential/finance', 'Y', 'Y', 'N','N'],
        ['finance', '/internal/reports', 'Y', 'Y', 'N','N'],
        
        # HR role - access to HR data
        ['hr', '/confidential/hr', 'Y', 'Y', 'N','N'],
        ['hr', '/home', 'Y', 'N', 'N','N'],  # Can read all home dirs for user management
        
        # Manager role - read confidential, write to internal
        ['manager', '/confidential', 'Y', 'N', 'N','N'],
        ['manager', '/internal', 'Y', 'Y', 'Y','N'],
        ['manager', '/shared', 'Y', 'Y', 'Y','N'],
        
        # Analyst role - work with projects and reports
        ['analyst', '/internal/projects', 'Y', 'Y', 'N','N'],
        ['analyst', '/internal/reports', 'Y', 'N', 'N','N'],
        ['analyst', '/internal/documentation', 'Y', 'N', 'N','N'],
        ['analyst', '/shared', 'Y', 'Y', 'N','N'],
        ['analyst', '/public', 'Y', 'N', 'N','N'],
        
        # Developer role - project access
        ['developer', '/internal/projects', 'Y', 'Y', 'Y','Y'],
        ['developer', '/internal/documentation', 'Y', 'Y', 'N','N'],
        ['developer', '/shared', 'Y', 'Y', 'N','N'],
        ['developer', '/public', 'Y', 'Y', 'N','N'],
        
        # Employee role - basic internal access
        ['employee', '/internal', 'Y', 'N', 'N','N'],
        ['employee', '/shared', 'Y', 'Y', 'N','N'],
        ['employee', '/public', 'Y', 'N', 'N','N'],
        
        # Contractor role - limited access
        ['contractor', '/internal/projects', 'Y', 'N', 'N','N'],
        ['contractor', '/shared', 'Y', 'Y', 'N','N'],
        ['contractor', '/public', 'Y', 'N', 'N','N'],
        
        # Guest role - minimal access
        ['guest', '/public', 'Y', 'N', 'N','N'],
        ['guest', '/shared/temp', 'Y', 'Y', 'N','N'],
        
        # Auditor role - read-only access to everything
        ['auditor', '/', 'Y', 'N', 'N','N'],
        
        # Test roles for specific scenarios
        ['test_readonly', '/test/read_only', 'Y', 'N', 'N','N'],
        ['test_writeonly', '/test/write_only', 'N', 'Y', 'N'],
        ['test_nodelete', '/test', 'Y', 'Y', 'N','N'],
    ]
    
    # Create data directory if it doesn't exist
    os.makedirs('server/data', exist_ok=True)
    
    # Write to CSV
    csv_file = 'server/data/role_perms.csv'
    with open(csv_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['role', 'resource', 'read', 'write', 'delete', 'execute'])
        writer.writerows(permissions)
    
    print(f"\n✅ Created {csv_file} with {len(permissions)} permission entries")
    return permissions

def create_mac_labels_json():
    """Create mac_labels.json with security labels and user clearances."""
    
    mac_config = {
        "security_levels": {
            "public": 0,
            "internal": 1,
            "confidential": 2,
            "secret": 3
        },
        
        "path_labels": {
            "/": "public",
            "/public": "public",
            "/internal": "internal",
            "/internal/projects": "internal",
            "/internal/reports": "internal",
            "/internal/documentation": "internal",
            "/confidential": "confidential",
            "/confidential/finance": "confidential",
            "/confidential/strategy": "confidential",
            "/confidential/hr": "confidential",
            "/confidential/.hidden": "secret",
            "/admin": "confidential",
            "/admin/logs": "internal",
            "/admin/configs": "confidential",
            "/admin/backups": "confidential",
            "/shared": "internal",
            "/shared/temp": "public",
            "/home": "internal",
            "/home/alice": "confidential",
            "/home/bob": "internal",
            "/home/eve": "public",
            "/home/charlie": "internal",
            "/test": "internal",
            "/test/no_access": "secret"
        },
        
        "user_clearances": {
            "alice": "secret",        # Admin - highest clearance
            "bob": "internal",        # Regular employee
            "eve": "public",
            "joseph": "confidential"         # Guest/contractor
        },
        
        "default_label": "public",
        "default_clearance": "public"
    }
    
    json_file = 'server/data/mac_labels.json'
    with open(json_file, 'w') as f:
        json.dump(mac_config, f, indent=2)
    
    print(f"✅ Created {json_file} with {len(mac_config['path_labels'])} path labels and {len(mac_config['user_clearances'])} user clearances")
    return mac_config

def create_dac_owners_csv():
    """Create dac_owners.csv with ownership and permission information."""
    
    # Format: path_prefix, owner, group, default_mode
    # Modes in octal: 755 = rwxr-xr-x, 644 = rw-r--r--, etc.
    dac_config = [
        ['/', 'root', 'root', '755'],
        
        # Public areas - world readable
        ['/public', 'root', 'root', '755'],
        ['/public/announcements', 'root', 'staff', '755'],
        ['/public/shared', 'root', 'user', '777'],
        
        # Internal areas - group readable
        ['/internal', 'root', 'employee', '750'],
        ['/internal/projects', 'root', 'developer', '770'],
        ['/internal/reports', 'root', 'analyst', '750'],
        ['/internal/documentation', 'root', 'employee', '750'],
        
        # Confidential areas - restricted
        ['/confidential', 'root', 'executive', '750'],
        ['/confidential/finance', 'root', 'finance', '750'],
        ['/confidential/strategy', 'root', 'executive', '750'],
        ['/confidential/hr', 'root', 'hr', '750'],
        ['/confidential/.hidden', 'admin', 'root', '700'],
        
        # User home directories - private
        ['/home', 'root', 'root', '755'],
        ['/home/alice', 'alice', 'alice', '700'],
        ['/home/alice/documents', 'alice', 'alice', '700'],
        ['/home/alice/.ssh', 'alice', 'alice', '700'],
        ['/home/bob', 'bob', 'bob', '750'],
        ['/home/bob/documents', 'bob', 'bob', '750'],
        ['/home/bob/projects', 'bob', 'developer', '750'],
        ['/home/eve', 'eve', 'eve', '755'],
        ['/home/eve/public_only', 'eve', 'user', '755'],
        ['/home/charlie', 'charlie', 'charlie', '750'],
        ['/home/charlie/analysis', 'charlie', 'analyst', '750'],
        
        # Shared workspaces - group writable
        ['/shared', 'root', 'user', '775'],
        ['/shared/team_alpha', 'root', 'team_alpha', '770'],
        ['/shared/team_beta', 'root', 'team_beta', '770'],
        ['/shared/temp', 'root', 'user', '777'],
        
        # Admin area - highly restricted
        ['/admin', 'root', 'admin', '750'],
        ['/admin/logs', 'root', 'admin', '750'],
        ['/admin/configs', 'root', 'admin', '750'],
        ['/admin/backups', 'root', 'admin', '750'],
        
        # Test areas with specific permissions
        ['/test', 'root', 'tester', '755'],
        ['/test/read_only', 'root', 'tester', '444'],
        ['/test/write_only', 'root', 'tester', '222'],
        ['/test/no_access', 'root', 'root', '000'],
    ]
    
    csv_file = 'server/data/dac_owners.csv'
    with open(csv_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['path_prefix', 'owner', 'group', 'default_mode'])
        writer.writerows(dac_config)
    
    print(f"✅ Created {csv_file} with {len(dac_config)} ownership entries")
    return dac_config

def create_users_json():
    """Create users.json with authentication information."""
    
    def hash_password(password, salt=None):
        """Create a salted hash using hashlib (simplified for demo)."""
        if salt is None:
            salt = secrets.token_bytes(16)
        else:
            salt = base64.b64decode(salt)
        
        # Simple PBKDF2 for demonstration (use scrypt or argon2 in production)
        dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return base64.b64encode(salt).decode(), base64.b64encode(dk).decode()
    
    # Define users with their passwords (for testing only!)
    test_users = [
        {
            "username": "alice",
            "password": "alice123",  # Admin user
            "uid": 1001,
            "gid": 1001,
            "groups": ["alice", "admin", "executives", "employees"],
            "description": "Alice Admin - Full system access"
        },
        {
            "username": "bob",
            "password": "bob456",    # Developer
            "uid": 1002,
            "gid": 1002,
            "groups": ["bob", "developers", "employees", "team_alpha"],
            "description": "Bob Developer - Internal access"
        },
        {
            "username": "eve",
            "password": "eve789",    # Guest
            "uid": 1003,
            "gid": 1003,
            "groups": ["eve", "users"],
            "description": "Eve Guest - Public access only"
        },
        {
            "username": "charlie",
            "password": "charlie321", # Analyst/Manager
            "uid": 1004,
            "gid": 1004,
            "groups": ["charlie", "analysts", "employees", "team_beta"],
            "description": "Charlie Analyst - Confidential read access"
        },
        {
            "username": "admin",
            "password": "admin@2024",  # System admin
            "uid": 0,
            "gid": 0,
            "groups": ["root", "admin"],
            "description": "System Administrator"
        }
    ]
    
    users_data = {"users": []}
    
    for user_info in test_users:
        salt, hash_val = hash_password(user_info["password"])
        
        user_entry = {
            "username": user_info["username"],
            "salt": salt,
            "password_hash": hash_val,
            "uid": user_info["uid"],
            "gid": user_info["gid"],
            "groups": user_info["groups"],
            "algorithm": "pbkdf2_sha256",
            "iterations": 100000,
            "description": user_info["description"]
        }
        users_data["users"].append(user_entry)
    
    json_file = 'server/data/users.json'
    with open(json_file, 'w') as f:
        json.dump(users_data, f, indent=2)
    
    # Also create a passwords file for testing reference (DO NOT use in production!)
    with open('server/data/test_passwords.txt', 'w') as f:
        f.write("TEST PASSWORDS (Delete in production!):\n")
        f.write("="*40 + "\n")
        for user_info in test_users:
            f.write(f"{user_info['username']}: {user_info['password']}\n")
            f.write(f"  Description: {user_info['description']}\n")
            f.write(f"  Groups: {', '.join(user_info['groups'])}\n\n")
    
    print(f"✅ Created {json_file} with {len(test_users)} users")
    print(f"✅ Created data/test_passwords.txt for testing reference")
    return users_data

def create_user_roles_json():
    """Create user_roles.json mapping users to their roles."""
    
    user_roles = {
        "alice": ["admin", "auditor"],
        "bob": ["developer", "employee"],
        "eve": ["guest"],
          "charlie": ["analyst"],
        "stephen": ["manager","hr"],
        "joseph": ["root"]
    }
    
    json_file = 'server/data/user_roles.json'
    with open(json_file, 'w') as f:
        json.dump(user_roles, f, indent=2)
    
    print(f"✅ Created {json_file} with role mappings for {len(user_roles)} users")
    return user_roles

def main():
    """Main setup function."""
    print("=" * 60)
    print("SFTP Server Environment Setup")
    print("=" * 60)
    
    # Create directory structure
    print("\n📁 Setting up jail_root directory structure...")
    create_directory_structure()
    
    # Create data configuration files
    print("\n📄 Creating data configuration files...")
    
    print("\n1. Creating role permissions...")
    create_role_perms_csv()
    
    print("\n2. Creating MAC labels...")
    create_mac_labels_json()
    
    print("\n3. Creating DAC ownership...")
    create_dac_owners_csv()
    
    print("\n5. Creating user-role mappings...")
    create_user_roles_json()

    print("\n5. Creating user data...")
    create_users_json()
    
    print("\n" + "=" * 60)
    print("✨ Setup Complete!")
    print("=" * 60)
    
    print("\n📋 Summary:")
    print("  • Created sftp_root/ jail directory with comprehensive structure")
    print("  • Created data/role_perms.csv with RBAC permissions")
    print("  • Created data/mac_labels.json with MAC security labels")
    print("  • Created data/dac_owners.csv with DAC ownership info")
    print("  • Created data/users.json with user authentication data")
    print("  • Created data/user_roles.json with user-role mappings")
    print("  • Created data/test_passwords.txt for testing reference")
    
    print("\n🔐 Security Zones Created:")
    print("  • /public - Accessible to all users")
    print("  • /internal - For employees and internal users")
    print("  • /confidential - High security, restricted access")
    print("  • /admin - System administration only")
    print("  • /home/* - User private directories")
    print("  • /shared - Collaborative workspaces")
    
    print("\n👥 Test Users Created:")
    print("  • alice (admin) - Full access, secret clearance")
    print("  • bob (developer) - Internal access, developer role")
    print("  • eve (guest) - Public only, minimal permissions")
    
    print("\n🏁 CTF Flag Location:")
    print("  • /confidential/.hidden/flag.txt")
    print("  • Protected by: MAC (secret label) + DAC (700) + RBAC (admin only)")
    

if __name__ == "__main__":
    main()
