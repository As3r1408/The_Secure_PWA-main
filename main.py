from flask import Flask, render_template, request, redirect, url_for, session
import user_management as dbHandler
from flask_wtf.csrf import CSRFProtect
import pyotp
from forms import LoginForm, SignupForm, FeedbackForm, OTPForm

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
csrf = CSRFProtect(app)

# Security: Restrict redirects to internal routes
def is_safe_redirect(url):
    return url.startswith("/") and "://" not in url

@app.route("/success.html", methods=["GET", "POST"])
def addFeedback():
    form = FeedbackForm()
    if request.method == "GET":
        feedbacks = dbHandler.listFeedback()  # Get feedback data
        return render_template("success.html", form=form, state=True, value="Back", feedbacks=feedbacks)

    if request.method == "POST" and form.validate_on_submit():
        feedback = form.feedback.data.strip()
        dbHandler.insertFeedback(feedback)
        feedbacks = dbHandler.listFeedback()  # Get updated feedback data
        return render_template("success.html", form=form, state=True, value="Back", feedbacks=feedbacks)

@app.route("/signup.html", methods=["POST", "GET"])
def signup():
    form = SignupForm()
    if request.method == "GET":
        return render_template("signup.html", form=form)

    if request.method == "POST" and form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data.strip()
        dob = form.dob.data.strip()

        try:
            dbHandler.insertUser(username, password, dob)
            otp_secret = dbHandler.retrieveUsers(username, password)
            return render_template("signup_success.html", otp_secret=otp_secret)
        except ValueError as e:
            return render_template("signup.html", form=form, error=str(e))

    return render_template("signup.html", form=form)

@app.route("/index.html", methods=["POST", "GET"])
@app.route("/", methods=["POST", "GET"])
def home():
    form = LoginForm()
    if request.method == "GET":
        return render_template("index.html", form=form)

    if request.method == "POST" and form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data.strip()
        otp_secret = dbHandler.retrieveUsers(username, password)
        if otp_secret:
            session['username'] = username
            session['otp_secret'] = otp_secret
            return redirect(url_for("two_factor"))
        else:
            return render_template("index.html", form=form, error="Invalid username or password.")
    return render_template("index.html", form=form)

@app.route("/two_factor", methods=["GET", "POST"])
def two_factor():
    if 'username' not in session:
        return redirect(url_for('home'))

    form = OTPForm()
    if request.method == "POST" and form.validate_on_submit():
        otp = form.otp.data.strip()
        totp = pyotp.TOTP(session['otp_secret'])
        if totp.verify(otp):
            return redirect(url_for("addFeedback"))
        else:
            return render_template("two_factor.html", form=form, error="Invalid OTP")

    return render_template("two_factor.html", form=form)

@app.route("/protected")
def protected():
    if 'username' not in session:
        return redirect(url_for('home'))
    return 'You are authenticated!'

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
