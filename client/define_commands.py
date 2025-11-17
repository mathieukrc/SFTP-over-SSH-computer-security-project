import asyncio, asyncssh, sys
from typing import List, Union

async def pwd(sftp:asyncssh.SFTPClient) -> str:
    value = await sftp.getcwd()
    return str(value)

async def ls(sftp:asyncssh.SFTPClient, path:str) -> List[str]:
    value = await sftp.listdir(path)
    return value

async def mkdir(sftp:asyncssh.SFTPClient, path:str) -> None:
    await sftp.mkdir(path)

async def stat(sftp:asyncssh.SFTPClient, path:str) -> str:
    value = await sftp.lstat(path)
    return str(value)

async def get(sftp:asyncssh.SFTPClient, rpath:str, lpath:str) -> None:
    await sftp.get(rpath, lpath if lpath != "" else None)

async def put(sftp:asyncssh.SFTPClient, lpath:str, rpath:str) -> None:
    await sftp.put(lpath, rpath)
        

    
    

