from flask import Flask, request

app = Flask(__name__)

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE"])
def catch_all(path):
    print("=" * 60)
    print(f"METHOD:  {request.method}")
    print(f"PATH:    /{path}")
    print(f"HEADERS: {dict(request.headers)}")
    print(f"ARGS:    {dict(request.args)}")
    print(f"FORM:    {dict(request.form)}")
    print("=" * 60)
    return "Request received. Check your terminal.\n"

if __name__ == "__main__":
    app.run(debug=True, port=5000)