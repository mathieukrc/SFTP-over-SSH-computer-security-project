import json

import argon2

USER_PATH = "server/data/users.json"
user_file = json.load(open(USER_PATH, "r"))
print("Loaded user file")


def check_password(username: str, password: str) -> bool:
    hasher = argon2.PasswordHasher()

    user = next((u for u in user_file if u["username"] == username), None)
    if user is not None:
        hash = user["password_hash"]
        try:
            hasher.verify(hash, password)
            return True
        except argon2.exceptions.VerifyMismatchError:
            pass

    return False


