import hashlib
import base64
n = 2048
r = 8
p = 1
salt = "salt"
dklen = 64
def check_password(plain_passphrase, hashed_passphrase):
    plain_passphrase = plain_passphrase.encode("utf-8")
    hashed_plain_passphrase = hashlib.scrypt(password=plain_passphrase, salt=salt.encode("utf-8"), n=n, r=r, p=p, dklen=dklen)
    print(hashed_passphrase)
    print(base64.b64encode(hashed_plain_passphrase).decode("utf-8"))
    if str(base64.b64encode(hashed_plain_passphrase).decode("utf-8")) == hashed_passphrase:
        return True
    else:
        return False
