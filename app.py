from flask import Flask, render_template, request, redirect, url_for
from flask_wtf.csrf import CSRFProtect
from config import Config
import user_management as dbHandler

app = Flask(__name__)
app.config.from_object(Config)
CSRFProtect(app)


@app.route("/success.html", methods=["POST", "GET"])
def addFeedback():
    if request.method == "POST":
        feedback = request.form["feedback"]
        dbHandler.insertFeedback(feedback)

    feedback_list = dbHandler.getFeedbackList()
    return render_template(
        "/success.html", state=True, value="Back", feedback_list=feedback_list
    )


@app.route("/signup.html", methods=["POST", "GET"])
def signup():
    if request.method != "POST":
        return render_template("/signup.html")

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    DoB = request.form.get("DoB", "")
    dbHandler.insertUser(username, password, DoB)
    return redirect(url_for("home", msg="Account created successfully! Please log in."))


@app.route("/index.html", methods=["POST", "GET"])
@app.route("/", methods=["POST", "GET"])
def home():
    match request.method:
        case "GET":
            msg = request.args.get("msg", "")
            return render_template("/index.html", msg=msg)

        case "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")

            userCredentialsCorrect = dbHandler.authenticateUser(username, password)

            if not userCredentialsCorrect:
                return render_template(
                    "/index.html", msg="Invalid username or password."
                )

            feedbackList = dbHandler.getFeedbackList()

            return render_template(
                "/success.html",
                value=username,
                state=True,
                feedback_list=feedbackList,
            )
        case _:
            return render_template(
                "/index.html", msg="An error occurred. Please try again."
            )


if __name__ == "__main__":
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    app.run(debug=True, host="0.0.0.0", port=3000)
