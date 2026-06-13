from flask import Flask, request, jsonify
import json
import datetime

app = Flask(__name__)

LOG_FILE = "/logs/http_honeypot.log"

def log_attempt(data):
    entry = {
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "ip": request.remote_addr,
        "method": request.method,
        "path": request.path,
        "user_agent": request.headers.get("User-Agent", ""),
        "data": data
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    print(f"[ATTACK] {entry}")

@app.route("/", methods=["GET"])
def index():
    log_attempt({})
    return """
    <html>
    <head><title>Admin Login</title></head>
    <body>
        <h2>Admin Panel</h2>
        <form method="POST" action="/login">
            <input type="text" name="username" placeholder="Username"/><br/>
            <input type="password" name="password" placeholder="Password"/><br/>
            <input type="submit" value="Login"/>
        </form>
    </body>
    </html>
    """

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    log_attempt({"username": username, "password": password})
    return """
    <html>
    <body>
        <h2>Invalid credentials. Please try again.</h2>
        <a href="/">Back</a>
    </body>
    </html>
    """

@app.route("/<path:path>", methods=["GET", "POST"])
def catch_all(path):
    log_attempt({"body": request.get_data(as_text=True)})
    return "Not Found", 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)