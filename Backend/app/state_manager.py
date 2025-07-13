import json
import os
from threading import Lock

STATUS_FILE = "data/report_status.json"
lock = Lock()


os.makedirs("data", exist_ok=True)

def load_statuses():
    if not os.path.exists(STATUS_FILE):
        return {}
    with open(STATUS_FILE, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {}

def save_statuses(statuses):
    with open(STATUS_FILE, "w") as f:
        json.dump(statuses, f)

def set_status(report_id, status):
    with lock:
        statuses = load_statuses()
        statuses[report_id] = status
        save_statuses(statuses)

def get_status(report_id):
    with lock:
        statuses = load_statuses()
        return statuses.get(report_id, "not_found")
