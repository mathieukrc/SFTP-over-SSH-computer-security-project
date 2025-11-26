 SFTP-over-SSH-computer-security-project

## How to run

First, generate your ssh keys for server/server.py and place them in the server folder.
You can then run:

pip install -r requirements.txt

To get all of the packages required to run the code.

After that, the server can be run using:

python3 server/server.py


And a client can be started with:

python3 client/client.py --host 127.0.0.1 --port 2222 --username bob

Where bob can be replaced with whatever username you are trying to connect to.

The tests are located inside of the tests folder and can be run with:

python3 tests/run_security_tests.py



## Access Control Layers

### Discretionary Access Control (DAC)

DAC uses standard Unix permissions. The flag’s directory /confidential/.hidden has mode 700, meaning only its owner (admin) has any permissions (read, write, delete and execute) it. All other users are denied by DAC. The server’s policy code enforces this by checking the user’s identity against the file’s owner and mode bits. By default the policy is deny: a non-owner cannot read,write,delete or execute anything in the directory. For example, a regular employee “bob” will be denied to open on the flag directory because the DAC check fails (he is neither owner nor in the owner’s group).

### Mandatory Access Control

MAC labels files with sensitivity labels, and gives users clearances. We label the directory /confidential and all its subdirectories with the label confidential/secret. We enforce no read up policy, meaning a user cannot read above their clearance. This way in our configuration, only admins have secret clearance, meaning only they can read secret labeled files. Any user with lower clearance, including internal or public, is denied by MAC. So even if somehow a user had file ownership, MAC would still prevent reading a secret-labeled flag unless their clearance was sufficiently high
### Role-Based Access Control (RBAC)

RBAC binds permissions to user roles. Our system assigns users to roles, such as admin, developer, guest, among others, with each role having privileges on path prefixes. For example, the /confidential area is restricted to the admin role. Other roles have no permissions there. The authorize function checks RBAC ,DAC and MAC, and requires all policies to agree to grant access by default. For example, even a user with secret clearance needs an admin role to read the flag. If the user doesn't have an admin role, then the RBAC check is enough to deny them, so they cannot access /confidential regardless of DAC or MAC.
### Path Handling and Authorization

Every request is first canonicalized and authorized before touching the filesystem. A helper canon_sftp_path normalizes the client path (removing “.”, “.”, etc.) into a POSIX path. Then the server calls authorize(user, op, canon_path), which combines DAC, MAC, and RBAC checks (default-deny if any fail). Only if authorize returns allowed does the server proceed. Next, the code uses safe_join(jail_root, client_path) to map the client path to an OS path under the jail. The safe_join function calls os.path.realpath on the combined path and verifies that it still lies within the jail directory. If the resolved path attempts to escape (e.g., via “.” or symlink), safe_join raises a PermissionError. In effect, no OS file operation is performed before both canonicalization and authorization succeed. This ensures that traversal or symlink exploits cannot bypass the access checks.

## Users and Intended Access

Alice: admin, has full system access
Bob: developer, has only access to internal files
Eve: guest, has only access to public files
Charlie: analyst, only access to confidential files
Admin: admin account, full system access
and some others created for testing purposes
