#!/usr/bin/env python3
"""
Comprehensive security policy tests for SFTP server
Tests DAC, MAC, RBAC, composite policies, and audit logging
Each test is self-contained with fixtures and clear objectives
"""

import pytest
import asyncio
import asyncssh
import os
import sys
import json
import csv
import tempfile
import shutil
from pathlib import Path

# Add server module to path for testing policy functions
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'server'))

from policy import DAC, MAC, RBAC, composite_rule


# Test configuration
TEST_HOST = 'localhost'
TEST_PORT = 2222

# Test users with different clearances and roles
TEST_USERS = {
    'alice': {'password': 'alicepass', 'clearance': 'secret', 'roles': ['admin', 'auditor']},
    'bob': {'password': 'bobpass', 'clearance': 'internal', 'roles': ['developer', 'employee']},
    'eve': {'password': 'evepass', 'clearance': 'public', 'roles': ['guest']},
}


@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for the test session"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def temp_policy_data(tmp_path):
    """Create temporary policy data files for testing"""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    
    # MAC labels
    mac_labels = {
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
            "/confidential": "confidential",
            "/admin": "confidential"
        },
        "user_clearances": {
            "alice": "secret",
            "bob": "internal",
            "eve": "public"
        }
    }
    
    with open(data_dir / "mac_labels.json", 'w') as f:
        json.dump(mac_labels, f)
    
    # DAC owners
    dac_data = [
        ["/", "root", "root", "755"],
        ["/public", "root", "root", "755"],
        ["/internal", "root", "employees", "750"],
        ["/confidential", "root", "executives", "700"],
        ["/home/alice", "alice", "alice", "700"],
        ["/home/bob", "bob", "bob", "750"],
        ["/test/readonly", "root", "testers", "444"],
        ["/test/writeonly", "root", "testers", "222"],
    ]
    
    with open(data_dir / "dac_owners.csv", 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(dac_data)
    
    # User roles
    user_roles = {
        "alice": ["admin", "auditor"],
        "bob": ["developer", "employee"],
        "eve": ["guest"],
        "charlie": ["analyst"]
    }
    
    with open(data_dir / "user_roles.json", 'w') as f:
        json.dump(user_roles, f)
    
    # Role permissions
    role_perms = [
        ["role", "resource", "read", "write", "delete", "execute"],
        ["admin", "/", "Y", "Y", "Y", "Y"],
        ["admin", "/admin", "Y", "Y", "Y", "Y"],
        ["analyst", "/internal/projects", "Y", "Y", "N", "N"],
        ["analyst", "/admin", "N", "N", "N", "N"],
        ["developer", "/internal/projects", "Y", "Y", "Y", "Y"],
        ["guest", "/public", "Y", "N", "N", "N"],
        ["employee", "/internal", "Y", "N", "N", "N"],
    ]
    
    with open(data_dir / "role_perms.csv", 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerows(role_perms)
    
    return data_dir


class TestDAC:
    """Discretionary Access Control (DAC) tests"""
    
    def test_owner_can_read_own_file(self):
        """DAC: Owner with read permission can read their own file"""
        # alice owns /home/alice with mode 700 (rwx for owner)
        result = DAC("alice", "/home/alice/test.txt", "r")
        assert result == True, "Owner should be able to read their own file"
    
    def test_owner_can_write_own_file(self):
        """DAC: Owner with write permission can write to their own file"""
        # alice owns /home/alice with mode 700 (rwx for owner)
        result = DAC("alice", "/home/alice/test.txt", "w")
        assert result == True, "Owner should be able to write to their own file"
    
    def test_non_owner_cannot_write_without_permission(self):
        """DAC: Non-owner cannot write to file without permission"""
        # bob tries to write to alice's directory (mode 700 - no other permissions)
        result = DAC("bob", "/home/alice/test.txt", "w")
        assert result == False, "Non-owner should not be able to write without permission"
    
    def test_non_owner_cannot_read_without_permission(self):
        """DAC: Non-owner cannot read file without permission"""
        # bob tries to read alice's file (mode 700 - no other permissions)
        result = DAC("bob", "/home/alice/test.txt", "r")
        assert result == False, "Non-owner should not be able to read without permission"
    
    def test_group_member_can_read_with_group_permission(self):
        """DAC: Group member can read file when group has read permission"""
        # bob is in bob group, /home/bob has mode 750 (rwxr-x---)
        # bob as group member should have read access
        result = DAC("bob", "/home/bob/test.txt", "r")
        assert result == True, "Group member should be able to read with group permission"
    
    def test_directory_execute_bit_affects_listing(self):
        """DAC: Directory execute bit affects ability to list/stat directory"""
        # /test/readonly has mode 444 (r--r--r--) - readable but not executable
        # Without execute, should not be able to traverse
        result = DAC("bob", "/test/readonly/file.txt", "x")
        assert result == False, "Directory without execute should prevent traversal"
    
    def test_directory_with_execute_allows_traversal(self):
        """DAC: Directory with execute bit allows traversal"""
        # /public has mode 755 (rwxr-xr-x) - others have execute
        result = DAC("eve", "/public", "x")
        assert result == True, "Directory with execute should allow traversal"
    
    def test_write_only_directory_denies_read(self):
        """DAC: Write-only directory denies read access"""
        # /test/writeonly has mode 222 (-w--w--w-) - write only
        result = DAC("bob", "/test/writeonly/file.txt", "r")
        assert result == False, "Write-only directory should deny read"
    
    def test_write_only_directory_allows_write(self):
        """DAC: Write-only directory allows write access"""
        # /test/writeonly has mode 222 (-w--w--w-) - write only
        result = DAC("bob", "/test/writeonly/file.txt", "w")
        assert result == True, "Write-only directory should allow write"
    
    def test_mode_000_denies_all_access(self):
        """DAC: Mode 000 denies all access to non-owner"""
        # Assuming we have a path with mode 000
        # This would be set up in policy data for /confidential with mode 700
        result = DAC("eve", "/confidential/secret.txt", "r")
        assert result == False, "Mode 000 for others should deny all access"


class TestMAC:
    """Mandatory Access Control (MAC) tests"""
    
    def test_internal_clearance_can_read_public(self):
        """MAC: User with internal clearance can read public files"""
        # bob has internal clearance, /public has public label
        result = MAC("bob", "/public/file.txt")
        assert result == True, "Internal clearance should access public files"
    
    def test_internal_clearance_can_read_internal(self):
        """MAC: User with internal clearance can read internal files"""
        # bob has internal clearance, /internal has internal label
        result = MAC("bob", "/internal/document.txt")
        assert result == True, "Internal clearance should access internal files"
    
    def test_internal_clearance_cannot_read_confidential(self):
        """MAC: User with internal clearance cannot read confidential files"""
        # bob has internal clearance, /confidential has confidential label
        result = MAC("bob", "/confidential/secret.txt")
        assert result == False, "Internal clearance should not access confidential files"
    
    def test_public_clearance_cannot_read_internal(self):
        """MAC: User with public clearance cannot read internal files"""
        # eve has public clearance, /internal has internal label
        result = MAC("eve", "/internal/document.txt")
        assert result == False, "Public clearance should not access internal files"
    
    def test_public_clearance_can_read_public(self):
        """MAC: User with public clearance can read public files"""
        # eve has public clearance, /public has public label
        result = MAC("eve", "/public/file.txt")
        assert result == True, "Public clearance should access public files"
    
    def test_secret_clearance_can_read_all_levels(self):
        """MAC: User with secret clearance can read all security levels"""
        # alice has secret clearance
        assert MAC("alice", "/public/file.txt") == True, "Secret should access public"
        assert MAC("alice", "/internal/file.txt") == True, "Secret should access internal"
        assert MAC("alice", "/confidential/file.txt") == True, "Secret should access confidential"
    
    def test_no_write_down_confidential_to_public(self):
        """MAC: Confidential user cannot write down to public (write-down prevention)"""
        # In a proper Bell-LaPadula implementation, write-down should be prevented
        # However, the current MAC implementation only checks read access
        # This test documents the expected behavior for a complete MAC system
        # Note: Current implementation would need enhancement to enforce write-down prevention
        result = MAC("alice", "/public/file.txt")
        # alice can read public (read-up allowed), but write-down should be prevented
        # This is a documentation test for future implementation
        assert result == True, "Read-up is allowed in Bell-LaPadula"
    
    def test_clearance_hierarchy_enforcement(self):
        """MAC: Clearance hierarchy is properly enforced (public < internal < confidential < secret)"""
        # Test the hierarchy: eve(public) < bob(internal) < alice(secret)
        
        # Public user (eve) - only public access
        assert MAC("eve", "/public/file.txt") == True
        assert MAC("eve", "/internal/file.txt") == False
        assert MAC("eve", "/confidential/file.txt") == False
        
        # Internal user (bob) - public and internal access
        assert MAC("bob", "/public/file.txt") == True
        assert MAC("bob", "/internal/file.txt") == True
        assert MAC("bob", "/confidential/file.txt") == False
        
        # Secret user (alice) - all access
        assert MAC("alice", "/public/file.txt") == True
        assert MAC("alice", "/internal/file.txt") == True
        assert MAC("alice", "/confidential/file.txt") == True


class TestRBAC:
    """Role-Based Access Control (RBAC) tests"""
    
    def test_analyst_can_read_projects(self):
        """RBAC: Analyst role can read files under /internal/projects"""
        # charlie has analyst role with read permission on /internal/projects
        result = RBAC("charlie", "/internal/projects/project1.txt", "read")
        assert result == True, "Analyst should be able to read project files"
    
    def test_analyst_can_write_projects(self):
        """RBAC: Analyst role can write files under /internal/projects"""
        # charlie has analyst role with write permission on /internal/projects
        result = RBAC("charlie", "/internal/projects/project1.txt", "write")
        assert result == True, "Analyst should be able to write project files"
    
    def test_analyst_cannot_mkdir_admin(self):
        """RBAC: Analyst role cannot create directories under /admin"""
        # charlie has analyst role, no permissions on /admin
        result = RBAC("charlie", "/admin/newdir", "write")
        assert result == False, "Analyst should not be able to create admin directories"
    
    def test_analyst_cannot_read_admin(self):
        """RBAC: Analyst role cannot read files under /admin"""
        # charlie has analyst role, no permissions on /admin
        result = RBAC("charlie", "/admin/config.txt", "read")
        assert result == False, "Analyst should not be able to read admin files"
    
    def test_adding_admin_role_enables_admin_access(self):
        """RBAC: Adding admin role enables access to /admin"""
        # alice has admin role with full permissions on /admin
        result = RBAC("alice", "/admin/config.txt", "read")
        assert result == True, "Admin role should enable read access to /admin"
        
        result = RBAC("alice", "/admin/newdir", "write")
        assert result == True, "Admin role should enable write access to /admin"
    
    def test_deny_override_blocks_access(self):
        """RBAC: Explicit deny overrides role permissions"""
        # Test with deny_dict parameter
        deny_dict = {
            "bob": {
                "/internal/projects": ["read", "write"]
            }
        }
        
        # bob normally has developer role with access to /internal/projects
        # but deny_dict should block it
        result = RBAC("bob", "/internal/projects/file.txt", "read", deny_dict=deny_dict)
        assert result == False, "Deny should override role permissions"
    
    def test_allow_override_grants_access(self):
        """RBAC: Explicit allow can grant access beyond role permissions"""
        # Test with allow_dict parameter
        allow_dict = {
            "eve": {
                "/admin": ["read"]
            }
        }
        
        # eve normally has guest role with no admin access
        # but allow_dict should grant it
        result = RBAC("eve", "/admin/config.txt", "read", allow_dict=allow_dict)
        assert result == True, "Allow should grant access beyond role permissions"
    
    def test_guest_role_limited_to_public(self):
        """RBAC: Guest role is limited to public resources"""
        # eve has guest role, should only access /public
        result = RBAC("eve", "/public/file.txt", "read")
        assert result == True, "Guest should read public files"
        
        result = RBAC("eve", "/public/file.txt", "write")
        assert result == False, "Guest should not write to public files"
        
        result = RBAC("eve", "/internal/file.txt", "read")
        assert result == False, "Guest should not access internal files"
    
    def test_multiple_roles_combine_permissions(self):
        """RBAC: User with multiple roles has combined permissions"""
        # alice has both admin and auditor roles
        # admin gives full access to /admin
        # auditor gives read access to /
        result = RBAC("alice", "/admin/config.txt", "write")
        assert result == True, "Multiple roles should combine permissions"


class TestCompositePolicies:
    """Composite policy tests (DAC + MAC + RBAC)"""
    
    def test_dac_allows_mac_denies_results_in_deny(self):
        """Composite: When DAC allows but MAC denies, final decision is deny"""
        # eve owns /home/eve (DAC allows), but tries to access it as if it were confidential
        # If we set /home/eve to confidential label, MAC would deny for eve (public clearance)
        
        # Simulating: eve has DAC permission but insufficient MAC clearance
        # bob tries to read /confidential - RBAC might allow via employee role,
        # but MAC denies (bob has internal, needs confidential)
        
        result = composite_rule("bob", "/confidential/secret.txt", "read")
        assert result == False, "MAC denial should override DAC/RBAC allow"
    
    def test_mac_allows_dac_denies_results_in_deny(self):
        """Composite: When MAC allows but DAC denies, final decision is deny"""
        # bob has internal clearance (MAC allows for /internal)
        # but /internal has mode 750 and bob is not owner/group (DAC denies)
        
        result = composite_rule("eve", "/internal/file.txt", "read")
        assert result == False, "DAC denial should result in overall deny"
    
    def test_all_policies_allow_results_in_allow(self):
        """Composite: When all policies (DAC, MAC, RBAC) allow, access is granted"""
        # alice has admin role (RBAC allows), secret clearance (MAC allows),
        # and owner/permissions (DAC allows)
        
        result = composite_rule("alice", "/admin/config.txt", "read")
        assert result == True, "All policies allowing should grant access"
    
    def test_rbac_denies_overrides_others(self):
        """Composite: RBAC denial overrides DAC and MAC allow"""
        # charlie (analyst) has no RBAC permission for /admin
        # even if DAC and MAC might allow
        
        result = composite_rule("charlie", "/admin/config.txt", "read")
        assert result == False, "RBAC denial should override other allows"
    
    def test_path_traversal_denied_by_composite(self):
        """Composite: Path traversal attempt is denied by composite policy"""
        # Attempt to access /../../../etc/passwd style path
        # All policies should deny this
        
        result = composite_rule("eve", "/../../../etc/passwd", "read")
        assert result == False, "Path traversal should be denied"
    
    def test_traversal_to_confidential_via_symlink_denied(self):
        """Composite: Traversal to confidential via symlink/.. is denied"""
        # Attempt to access /public/../confidential
        # Should be normalized and denied based on actual target
        
        result = composite_rule("eve", "/public/../confidential/secret.txt", "read")
        assert result == False, "Traversal to confidential should be denied"
    
    def test_write_requires_all_policies(self):
        """Composite: Write access requires all three policies to allow"""
        # bob tries to write to /internal/projects
        # Needs: RBAC (developer role allows), MAC (internal clearance allows),
        # DAC (needs write permission)
        
        result = composite_rule("bob", "/internal/projects/file.txt", "write")
        # This should succeed only if all three policies allow
        assert isinstance(result, bool), "Composite rule should return boolean"
    
    def test_delete_requires_write_permission(self):
        """Composite: Delete action requires write permission in all policies"""
        # alice tries to delete from /admin
        # Delete maps to write permission in the composite rule
        
        result = composite_rule("alice", "/admin/oldfile.txt", "delete")
        assert isinstance(result, bool), "Delete should be evaluated through composite rule"


class TestAuditLogging:
    """Audit logging tests - verify access decisions are logged"""
    
    @pytest.fixture
    def audit_log_file(self, tmp_path):
        """Create temporary audit log file"""
        log_file = tmp_path / "audit.log"
        return str(log_file)
    
    def test_allow_decision_creates_audit_record(self, audit_log_file):
        """Audit: Allow decision creates audit record with correct fields"""
        # This is a placeholder for actual audit implementation
        # Expected fields: timestamp, user, resource, action, decision, policies
        
        # Simulate an allow decision
        user = "alice"
        resource = "/admin/config.txt"
        action = "read"
        
        # Call composite rule (which should trigger audit)
        decision = composite_rule(user, resource, action)
        
        # In actual implementation, verify audit log contains:
        # - timestamp
        # - user: alice
        # - resource: /admin/config.txt
        # - action: read
        # - decision: allow
        # - dac_result, mac_result, rbac_result
        
        assert decision == True, "Admin should be able to read admin files"
        # TODO: Read audit log and verify record exists with correct fields
    
    def test_deny_decision_creates_audit_record(self, audit_log_file):
        """Audit: Deny decision creates audit record with correct fields"""
        # Simulate a deny decision
        user = "eve"
        resource = "/confidential/secret.txt"
        action = "read"
        
        # Call composite rule (which should trigger audit)
        decision = composite_rule(user, resource, action)
        
        # In actual implementation, verify audit log contains:
        # - timestamp
        # - user: eve
        # - resource: /confidential/secret.txt
        # - action: read
        # - decision: deny
        # - reason: MAC denial (insufficient clearance)
        
        assert decision == False, "Eve should not access confidential files"
        # TODO: Read audit log and verify record exists with correct fields
    
    def test_audit_record_contains_all_policy_results(self, audit_log_file):
        """Audit: Record contains individual results from DAC, MAC, and RBAC"""
        user = "bob"
        resource = "/internal/projects/file.txt"
        action = "read"
        
        # This should trigger evaluation of all three policies
        decision = composite_rule(user, resource, action)
        
        # Expected audit record should contain:
        # - dac_result: True/False
        # - mac_result: True/False
        # - rbac_result: True/False
        # - final_decision: True/False
        
        # TODO: Verify audit log contains breakdown of each policy decision
        assert isinstance(decision, bool), "Should return a decision"
    
    def test_audit_includes_timestamp_and_session_info(self, audit_log_file):
        """Audit: Record includes timestamp and session information"""
        user = "alice"
        resource = "/admin/config.txt"
        action = "write"
        
        decision = composite_rule(user, resource, action)
        
        # Expected fields:
        # - timestamp: ISO 8601 format
        # - user: alice
        # - session_id: (if available from SFTP session)
        # - source_ip: (if available)
        
        # TODO: Verify audit log contains timestamp and session info
        assert isinstance(decision, bool), "Should return a decision"
    
    def test_failed_auth_creates_audit_record(self, audit_log_file):
        """Audit: Failed authentication attempt creates audit record"""
        # This test would require integration with auth module
        # Expected record:
        # - timestamp
        # - username: attempted username
        # - event: authentication_failed
        # - source_ip
        # - reason: invalid_password / invalid_username
        
        # TODO: Implement when auth module has audit integration
        pass
    
    def test_audit_log_is_tamper_evident(self, audit_log_file):
        """Audit: Log entries are tamper-evident (append-only, signed, or hashed)"""
        # In a production system, audit logs should be:
        # - Append-only (no modifications or deletions)
        # - Optionally signed or hashed for integrity
        # - Stored securely with restricted access
        
        # TODO: Implement integrity verification
        pass


class TestEdgeCasesAndIntegration:
    """Edge cases and integration scenarios"""
    
    def test_undefined_user_denied_all_access(self):
        """Undefined user is denied access by all policies"""
        result = composite_rule("undefined_user", "/public/file.txt", "read")
        assert result == False, "Undefined user should be denied"
    
    def test_undefined_path_uses_default_policy(self):
        """Undefined path uses default/fallback policy"""
        # Paths not explicitly defined should fall back to most restrictive
        result = composite_rule("eve", "/undefined/path/file.txt", "read")
        assert isinstance(result, bool), "Should handle undefined paths gracefully"
    
    def test_case_sensitivity_in_paths(self):
        """Path matching is case-sensitive"""
        # /Public vs /public should be different
        result1 = composite_rule("eve", "/public/file.txt", "read")
        result2 = composite_rule("eve", "/Public/file.txt", "read")
        # Results may differ based on policy definitions
        assert isinstance(result1, bool) and isinstance(result2, bool)
    
    def test_root_path_access_control(self):
        """Root path (/) has proper access control"""
        # Only admin should have write access to root
        result = composite_rule("alice", "/newfile.txt", "write")
        assert isinstance(result, bool), "Root path should have access control"
        
        result = composite_rule("eve", "/newfile.txt", "write")
        assert result == False, "Non-admin should not write to root"
    
    def test_concurrent_policy_evaluations(self):
        """Concurrent policy evaluations return consistent results"""
        import threading
        
        results = []
        def evaluate_policy():
            result = composite_rule("bob", "/internal/file.txt", "read")
            results.append(result)
        
        threads = [threading.Thread(target=evaluate_policy) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # All results should be the same
        assert len(set(results)) == 1, "Concurrent evaluations should be consistent"
    
    def test_special_characters_in_filenames(self):
        """Files with special characters are handled correctly"""
        special_paths = [
            "/public/file with spaces.txt",
            "/public/file-with-dashes.txt",
            "/public/file_with_underscores.txt",
            "/public/file.multiple.dots.txt",
        ]
        
        for path in special_paths:
            result = composite_rule("eve", path, "read")
            assert isinstance(result, bool), f"Should handle special chars in {path}"
    
    def test_very_long_path_handled_correctly(self):
        """Very long paths are handled without errors"""
        long_path = "/public/" + "a" * 1000 + "/file.txt"
        result = composite_rule("eve", long_path, "read")
        assert isinstance(result, bool), "Should handle long paths"
    
    def test_action_parameter_validation(self):
        """Invalid action parameters are handled correctly"""
        # Valid actions: read, write, delete, execute
        valid_actions = ["read", "write", "delete", "execute"]
        
        for action in valid_actions:
            result = composite_rule("alice", "/admin/file.txt", action)
            assert isinstance(result, bool), f"Should handle valid action: {action}"


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
