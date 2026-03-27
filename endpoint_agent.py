import os
import hashlib
import json
import socket
import getpass
import datetime
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

SERVER_URL = "http://127.0.0.1:8000/log"

USB_PATH = "E:\\"   # example USB drive

def sha256(file_path):
    h = hashlib.sha256()
    with open(file_path,'rb') as f:
        while chunk := f.read(4096):
            h.update(chunk)
    return h.hexdigest()


def create_fingerprint(file_path):

    fingerprint = {
        "hostname": socket.gethostname(),
        "user": getpass.getuser(),
        "timestamp": datetime.datetime.now().isoformat(),
        "file": os.path.basename(file_path),
        "hash": sha256(file_path)
    }

    return fingerprint


def embed_metadata(file_path, fingerprint):

    try:
        with open(file_path, "ab") as f:
            tag = "\nFINGERPRINT:" + json.dumps(fingerprint)
            f.write(tag.encode())
    except:
        pass


def send_log(fp):

    try:
        requests.post(SERVER_URL, json=fp)
    except:
        print("server unreachable")


class USBMonitor(FileSystemEventHandler):

    def on_created(self, event):

        if event.is_directory:
            return

        path = event.src_path
        print("file copied:", path)

        fp = create_fingerprint(path)

        embed_metadata(path, fp)

        send_log(fp)


if __name__ == "__main__":

    observer = Observer()
    observer.schedule(USBMonitor(), USB_PATH, recursive=False)

    observer.start()

    print("USB monitoring started")

    try:
        while True:
            pass
    except KeyboardInterrupt:
        observer.stop()

    observer.join()
