#!/usr/bin/env python3
import sys
sys.path.insert(0, 'c:/Users/a/Documents/GitHub/SFTP-over-SSH-computer-security-project')

from server.policy import RBAC, load_RBAC_helper, RBAC_path_helper
import os
os.chdir('c:/Users/a/Documents/GitHub/SFTP-over-SSH-computer-security-project')

# Load RBAC policy
policy, paths = load_RBAC_helper('server/data/user_roles.json', 'server/data/role_perms.csv')

print("=== RBAC Debugging ===")
print(f"\nUnique paths in role_perms.csv:")
for p in sorted(set(paths)):
    print(f"  {p}")

print(f"\nAlice's roles and permissions:")
alice_policy = policy.get('alice')
if alice_policy:
    for role, resources in alice_policy.items():
        print(f"  Role: {role}")
        for resource, perms in resources.items():
            print(f"    Resource: {resource}, Permissions: {perms}")

test_path = "/admin/configs/server.conf"
matched_path = RBAC_path_helper(test_path, paths)
print(f"\nPath matching:")
print(f"  Input: {test_path}")
print(f"  Matched: {matched_path}")

print(f"\nRBAC test:")
result = RBAC("alice", test_path, "read")
print(f"  RBAC('alice', '{test_path}', 'read') = {result}")

# Check what permissions alice has for the matched path
if alice_policy:
    for role, resources in alice_policy.items():
        if matched_path in resources:
            print(f"  Alice's '{role}' role has permissions for '{matched_path}': {resources[matched_path]}")
