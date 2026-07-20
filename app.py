from flask import Flask, request, render_template
from waf.middleware import inspect_and_decide
from waf import logger

app = Flask(__name__)

FAKE_USERS = {"admin": "SuperSecret123", "student": "password123"}

@app.before_request
def waf_gate():
    result = inspect_and_decide()
    if result is not None:
        return result

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    message = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if FAKE_USERS.get(username) == password:
            message = f"Welcome back, {username}!"
        else:
            message = "Invalid username or password."
    return render_template("login.html", message=message)

@app.route("/search")
def search():
    query = request.args.get("q", "")
    results = [f"Result for '{query}' #1", f"Result for '{query}' #2"] if query else []
    return render_template("search.html", query=query, results=results)

@app.route("/file")
def file_view():
    filename = request.args.get("name", "")
    if filename:
        content = f"[simulated] Contents of '{filename}' would appear here."
    else:
        content = ""
    return render_template("file.html", filename=filename, content=content)

@app.route("/ping")
def ping_tool():
    host = request.args.get("host", "")
    if host:
        result = f"[simulated] Ping results for '{host}' would appear here."
    else:
        result = ""
    return render_template("ping.html", host=host, result=result)

@app.route("/dashboard")
def dashboard():
    logs = logger.read_all_logs()
    
    total = len(logs)
    blocked = sum(1 for r in logs if r["action"] == "BLOCKED")
    allowed = total - blocked
    
    category_counts = {}
    ip_counts = {}
    for r in logs:
        if r["category"]:
            category_counts[r["category"]] = category_counts.get(r["category"], 0) + 1
        if r["action"] == "BLOCKED":
            ip_counts[r["ip"]] = ip_counts.get(r["ip"], 0) + 1
            
    recent = list(reversed(logs))[:20]
    
    return render_template(
        "dashboard.html",
        total=total,
        blocked=blocked,
        allowed=allowed,
        category_counts=category_counts,
        ip_counts=ip_counts,
        recent=recent
    )

if __name__ == "__main__":
    app.run(debug=True, port=5000)