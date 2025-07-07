"""
app.py

A Flask application that:
1. Receives GitHub webhook events (push, pull_request opened, pull_request merged).
2. Verifies the HMAC-SHA1 signature using SECRET_TOKEN.
3. Formats a single descriptive string for each event.
4. Stores only that string and a timestamp in local MongoDB.
5. Serves a UI at "/" (index.html) that polls "/api/events" every 15 seconds
   and displays the latest 50 events.
"""

import os
import hmac
import hashlib
from datetime import datetime
from flask import Flask, request, abort, jsonify, render_template
from pymongo import MongoClient
from dotenv import load_dotenv

# 1) Load environment variables from .env
load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")                     # e.g. mongodb://localhost:27017/github_events
DATABASE_NAME = os.getenv("DATABASE_NAME", "github_events")
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "events")
SECRET_TOKEN = os.getenv("SECRET_TOKEN")               # Must match what you set in GitHub webhook secret

# 2) Initialize Flask app
app = Flask(__name__)

# 3) Initialize MongoDB client & collection
client = MongoClient(MONGO_URI)
db = client[DATABASE_NAME]
collection = db[COLLECTION_NAME]

def verify_signature(payload: bytes, signature_header: str) -> bool:
    """
    Verifies the GitHub HMAC-SHA1 signature header.
    If SECRET_TOKEN is not set or signature_header is missing, we skip verification.
    """
    if not SECRET_TOKEN or not signature_header:
        return True

    sha_name, signature = signature_header.split("=")
    if sha_name != "sha1":
        return False

    computed = hmac.new(SECRET_TOKEN.encode(), msg=payload, digestmod=hashlib.sha1)
    return hmac.compare_digest(computed.hexdigest(), signature)

def format_timestamp(iso_ts: str) -> str:
    """
    Convert GitHub's ISO8601 UTC timestamp (e.g. "2021-04-01T21:30:00Z")
    into: "1st April 2021 - 09:30 PM UTC" with correct ordinal suffix.
    """
    dt = datetime.strptime(iso_ts, "%Y-%m-%dT%H:%M:%SZ")
    day = dt.day
    # Determine ordinal suffix
    if 11 <= day <= 13:
        suffix = "th"
    else:
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(day % 10, "th")
    return dt.strftime(f"%-d{suffix} %B %Y - %I:%M %p UTC")

@app.route("/")
def index():
    """
    Renders the main UI (templates/index.html). That page’s JS will poll /api/events.
    """
    return render_template("index.html")

@app.route("/api/events", methods=["GET"])
def get_events():
    """
    Returns a JSON array of the latest 50 "formatted" event strings
    sorted by insertion time (descending).
    """
    docs = collection.find().sort("inserted_at", -1).limit(50)
    # We only return the "formatted" field for each doc
    events = [doc["formatted"] for doc in docs]
    return jsonify(events), 200

@app.route("/webhook", methods=["POST"])
def handle_webhook():
    """
    Receives GitHub webhook POSTs at /webhook.
    Verifies signature (if SECRET_TOKEN set), then parses the payload:
      - "push" events
      - "pull_request" opened
      - "pull_request" closed & merged
    Formats a single string per event, inserts into MongoDB, returns status.
    """
    signature = request.headers.get("X-Hub-Signature")

    # 1) Verify HMAC signature
    if not verify_signature(request.data, signature):
        abort(403, "Invalid signature")

    event_type = request.headers.get("X-GitHub-Event")
    payload = request.get_json()

    # Prepare the document to insert
    doc = {
        "inserted_at": datetime.utcnow(),
        "formatted": ""
    }

    # 2) Handle "push" event
    if event_type == "push":
        author = payload["pusher"]["name"]
        to_branch = payload["ref"].split("/")[-1]  # e.g. "refs/heads/main" -> "main"
        ts = payload["head_commit"]["timestamp"]  # e.g. "2021-04-01T21:30:00Z"
        doc["formatted"] = (
            f"\"{author}\" pushed to \"{to_branch}\" on {format_timestamp(ts)}"
        )

    # 3) Handle "pull_request" opened or merged
    elif event_type == "pull_request":
        action = payload["action"]
        pr = payload["pull_request"]
        author = pr["user"]["login"]
        from_branch = pr["head"]["ref"]
        to_branch = pr["base"]["ref"]

        if action == "opened":
            ts = pr["created_at"]  # e.g. "2021-04-01T09:00:00Z"
            doc["formatted"] = (
                f"\"{author}\" submitted a pull request from \"{from_branch}\" "
                f"to \"{to_branch}\" on {format_timestamp(ts)}"
            )
        elif action == "closed" and pr.get("merged"):
            ts = pr["merged_at"]  # e.g. "2021-04-02T12:00:00Z"
            doc["formatted"] = (
                f"\"{author}\" merged branch \"{from_branch}\" to \"{to_branch}\" "
                f"on {format_timestamp(ts)}"
            )
        else:
            # ignore other PR actions (e.g. closed without merge, reopened, etc.)
            return jsonify({"status": "ignored"}), 200
    else:
        # ignore any other event type (e.g. issues, comments, etc.)
        return jsonify({"status": "ignored"}), 200

    # 4) Insert into MongoDB
    collection.insert_one(doc)
    return jsonify({"status": "stored"}), 201

if __name__ == "__main__":
    # Run the Flask app on port 5000 in debug mode
    app.run(host="0.0.0.0", port=5000, debug=True)
