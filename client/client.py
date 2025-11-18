import asyncio, asyncssh, sys
import stat
from typing import Tuple
from define_commands import pwd, ls, mkdir, stat, get, put

host = None
port = None
username = None

async def perform_action(input_text:str, sftp:asyncssh.SFTPClient) -> Tuple[bool, bool, str]:
    parameters = input_text.split(" ")

    if parameters[0] == "quit":
        return True, True, ""

    elif parameters[0] == "pwd":
        try:
            cwd = await pwd(sftp)
            return False, True, cwd
        except Exception as e:
            return False, False, str(e)

    elif parameters[0] == "ls":
        try:
            chosen_path = "" if len(parameters) == 1 else parameters[1]
            output = await ls(sftp, chosen_path)

            text_output = ""
            for o in output:
                text_output += f"'{o}'   "

            return False, True, text_output
        except Exception as e:
            return False, False, str(e)

    elif parameters[0] == "mkdir":
        try:
            if len(parameters) == 1:
                return False, False, "missing 'path' argument"
            path = parameters[1]

            await mkdir(sftp, path)
            return False, True, ""
        except Exception as e:
            return False, False, str(e)

    elif parameters[0] == "stat":
        try:
            if len(parameters) == 1:
                return False, False, "missing 'path' argument"
            path = parameters[1]

            stats = await stat(sftp, path)
            broken_down = stats.split(", ")

            text_output = ""
            for o in broken_down:
                text_output += o + "\n"

            return False, True, text_output
        except Exception as e:
            return False, False, str(e)

    elif parameters[0] == "get":
        try:
            if len(parameters) == 1:
                return False, False, "missing 'rpath' argument"
            rpath = parameters[1]
            lpath = "" if len(parameters) == 2 else parameters[2]

            await get(sftp, rpath, lpath)

            return False, True, ""
        except Exception as e:
            return False, False, str(e)

    elif parameters[0] == "put":
        try:
            if len(parameters) == 1:
                return False, False, "missing 'lpath, rpath' arguments"
            elif len(parameters) == 2:
                return False, False, "missing 'rpath' argument"
            lpath = parameters[1]
            rpath = parameters[2]
            await put(sftp, lpath, rpath)
            return False, True, ""
        except Exception as e:
            return False, False, str(e)

    else:
        return False, False, "Invalid command"


async def run_cli():
    password = input("Enter password: ")
    try:
        async with asyncssh.connect(host=host, port=port, username=username, password=password, known_hosts=(["server/ssh_host_ed25519_key.pub"], [], [])) as conn:
            async with conn.start_sftp_client() as sftp:
                print("Successfully connected")
                while True:
                    text = input("sftp> ")
                    quit, success, message = await perform_action(text, sftp)

                    if message != "":
                        print(message if success else f"Error: {message}")

                    if quit:
                        break

    except Exception as e:
        print("Unsuccessful attempt")

if __name__ == "__main__":
    for i in range(1, len(sys.argv) - 1, 2):
        if sys.argv[i] == "--host":
            host = sys.argv[i+1]
        elif sys.argv[i] == "--port":
            port = int(sys.argv[i+1])
        elif sys.argv[i] == "--username":
            username = sys.argv[i+1]
        else:
            print(f"Unknown parameter {sys.argv[i]}. Valid parameters are --host, --port and --username.")
        
    if host is None:
        print("Missing parameter: --host")
    elif port is None:
        print("Missing parameter: --port")
    elif username is None:
        print("Missing parameter: --username")
    else:
        asyncio.run(run_cli())
