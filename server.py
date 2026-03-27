from fastapi import FastAPI
from datetime import datetime
import json
import os

app = FastAPI()

LOG_DIR = "logs"

os.makedirs(LOG_DIR, exist_ok=True)


@app.post("/log")
async def receive_log(data: dict):

    date = datetime.now().strftime("%Y-%m-%d")
    filename = f"{LOG_DIR}/{date}.log"

    with open(filename, "a") as f:
        f.write(json.dumps(data) + "\n")

    return {"status":"ok"}
