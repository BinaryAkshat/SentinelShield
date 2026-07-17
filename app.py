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

@app.route("/login", methods=["POST"])
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

if __name__ == "__main__":
    app.run(debug=True, port=5000)