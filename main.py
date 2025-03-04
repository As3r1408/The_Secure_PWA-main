from flask import Flask, render_template, request, redirect, url_for
import user_management as dbHandler

app = Flask(__name__)

# Security: Restrict redirects to internal routes
def is_safe_redirect(url):
    return url.startswith("/") and "://" not in url

@app.route("/success.html", methods=["GET", "POST"])
def addFeedback():
    if request.method == "GET":
        url = request.args.get("url", "")
        if is_safe_redirect(url):
            return redirect(url, code=302)
        return redirect(url_for("home"))  # Redirect safely

    if request.method == "POST":
        feedback = request.form.get("feedback", "").strip()
        dbHandler.insertFeedback(feedback)

    dbHandler.listFeedback()  # Ensure feedback updates before rendering
    return render_template("success.html", state=True, value="Back")

@app.route("/signup.html", methods=["POST", "GET"])
def signup():
    if request.method == "GET":
        return render_template("signup.html")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        dob = request.form.get("dob", "").strip()

        try:
            dbHandler.insertUser(username, password, dob)
            return redirect(url_for("home"))
        except ValueError as e:
            return render_template("signup.html", error=str(e))

    return render_template("signup.html")

@app.route("/index.html", methods=["POST", "GET"])
@app.route("/", methods=["POST", "GET"])
def home():
    if request.method == "GET":
        return render_template("index.html")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        isLoggedIn = dbHandler.retrieveUsers(username, password)
        if isLoggedIn:
            return render_template("success.html", value=username, state=True)
        else:
            return render_template("index.html", error="Invalid username or password.")

    return render_template("index.html")

# Secure error handling
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template("500.html"), 500

if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=True, host="0.0.0.0", port=5000)
