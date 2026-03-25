from flask import current_app
from flask_mail import Mail, Message

mail = Mail()


def send_otp_email(recipient: str, code: str) -> None:
    display_name = current_app.config.get(
        "MAIL_DISPLAY_NAME", "The Unsecure PWA Company"
    )
    display_from = current_app.config.get(
        "MAIL_DISPLAY_FROM", current_app.config["MAIL_USERNAME"]
    )

    msg = Message(
        subject="Your verification code",
        sender=f"{display_name} <{display_from}>",
        recipients=[recipient],
        body=(
            f"Your verification code is: {code}\n\n"
            "This code expires in 10 minutes.\n\n"
            "If you did not request this code, please ignore this email. "
            "Your account has not been accessed."
        ),
    )
    mail.send(msg)
