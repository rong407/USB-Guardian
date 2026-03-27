import json
import os

LOG_DIR = "logs"

def extract_fingerprint(file_path):

    with open(file_path,'rb') as f:
        data = f.read().decode(errors="ignore")

    if "FINGERPRINT:" in data:
        fp = data.split("FINGERPRINT:")[-1]
        return json.loads(fp)

    return None


def search_log(hash_value):

    for file in os.listdir(LOG_DIR):

        with open(os.path.join(LOG_DIR,file)) as f:

            for line in f:
                record = json.loads(line)

                if record["hash"] == hash_value:
                    return record

    return None


file = input("file to investigate: ")

fp = extract_fingerprint(file)

if not fp:
    print("no fingerprint found")
else:

    print("fingerprint found:", fp)

    result = search_log(fp["hash"])

    if result:
        print("SOURCE IDENTIFIED")
        print(result)
    else:
        print("log not found")
