import uuid
import hashlib

from flask import Flask, render_template, request, \
    make_response, redirect, url_for
from models import User, db, user_message, init_data

app = Flask(__name__)

#init_data()

db.create_all()


@app.route("/", methods=["GET"])
def index():

    session_token = request.cookies.get("session_token")
    user = db.query(User).filter_by(session_token=session_token).first()
    if user is None:
        response = make_response(
            redirect(url_for("login"))
        )
        return response

    return render_template("main_page.html", user=user)


@app.route("/", methods=["POST"])
def index_post():

    session_token = request.cookies.get("session_token")
    user = db.query(User).filter_by(session_token=session_token).first()
    if user is None:
        response = make_response(
            redirect(url_for("login"))
        )
        return response

    user_post = request.form.get("user_post")
    user = user_message(user_post=user_post)

    db.add(user)
    db.commit()

    return render_template("main_page.html", user=user)


@app.route("/login")
def login():
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login_post():
    name = request.form.get("name")
    lastname = request.form.get("lastname")
    email = request.form.get("email")
    password = request.form.get("password")

    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    user = db.query(User).filter_by(email=email).first()

    if not user:
        user = User(name=name, email=email, lastname=lastname, password=hashed_password)

        db.add(user)
        db.commit()

    if hashed_password != user.password:
        return "password is wrong try again!"
    elif hashed_password == user.password:
        session_token = str(uuid.uuid4())

        user.session_token = session_token

        db.add(user)
        db.commit()

    response = make_response(
        redirect(url_for("index"))
    )
    response.set_cookie("session_token", session_token, httponly=True, samesite='Strict')

    return response


@app.route("/profile/")
def profile_view():
    session_token = request.cookies.get("session_token")
    user = db.query(User).filter_by(session_token=session_token).first()
    if user is None:
        response = make_response(
            redirect(url_for("login"))
        )
        return response
    return render_template("profile.html", user=user)


@app.route("/profile/edit", methods=["GET"])
def profile_edit_get():
    session_token = request.cookies.get("session_token")
    user = db.query(User).filter_by(session_token=session_token).first()
    if user is None:
        response = make_response(
            redirect(url_for("login"))
        )
        return response
    return render_template("edit.html", user=user)


@app.route("/profile/edit", methods=["POST"])
def profile_edit_post():
    session_token = request.cookies.get("session_token")
    user = db.query(User).filter_by(session_token=session_token).first()
    if user is None:
        response = make_response(
            redirect(url_for("login"))
        )
        return response
    user.email = request.form.get("email")
    user.name = request.form.get("name")
    user.lastname = request.form.get("lastname")

    db.add(user)
    db.commit()

    return render_template("profile.html", user=user)


@app.route("/profile/delete", methods=["POST"])
def profile_delete_post():
    session_token = request.cookies.get("session_token")
    user = db.query(User).filter_by(session_token=session_token).first()
    if user is None:
        response = make_response(
            redirect(url_for("login"))
        )
        return response

    db.delete(user)
    db.commit()

    return make_response(
        redirect(url_for("login"))
    )


@app.route("/list", methods=["GET"])
def list_users():
    session_token = request.cookies.get("session_token")
    user = db.query(User).filter_by(session_token=session_token).first()
    if user is None:
        response = make_response(
            redirect(url_for("login"))
        )
        return response

    users = db.query(User).all()

    return render_template("list_users.html", users=users, user=user)


@app.route("/profiles/<user_uid>")
def view_user(user_uid):
    user = db.query(User).filter_by(uid=user_uid).first()
    return render_template("other_user.html", user=user)


@app.route("/profile/password", methods=["GET"])
def profile_password_get():
    session_token = request.cookies.get("session_token")
    user = db.query(User).filter_by(session_token=session_token).first()
    if user is None:
        response = make_response(
            redirect(url_for("login"))
        )
        return response
    return render_template("password.html", user=user)


@app.route("/profile/password", methods=["POST"])
def profile_password_post():
    session_token = request.cookies.get("session_token")
    user = db.query(User).filter_by(session_token=session_token).first()
    old_password = request.form.get("old-password")
    new_password = request.form.get("new-password")
    if user is None:
        response = make_response(
            redirect(url_for("login"))
        )
        return response
    hashed_old_password = hashlib.sha256(old_password.encode()).hexdigest()
    hashed_new_password = hashlib.sha256(new_password.encode()).hexdigest()

    if hashed_old_password == user.password:
        user.password = hashed_new_password
    else:
        return "Wrong (old) password! Go back and try again."

    db.add(user)
    db.commit()

    return render_template("profile.html", user=user)


@app.route("/converter", methods=["GET"])
def converter():
    session_token = request.cookies.get("session_token")
    user = db.query(User).filter_by(session_token=session_token).first()
    if user is None:
        response = make_response(
            redirect(url_for("login"))
        )
        return response
    return render_template("converter.html", user=user)


@app.route("/converter", methods=["POST"])
def converter_post():
    session_token = request.cookies.get("session_token")
    user = db.query(User).filter_by(session_token=session_token).first()
    if user is None:
        response = make_response(
            redirect(url_for("login"))
        )
        return response
    enota = request.form.get("enota")
    stevilo = int(request.form.get("stevilo"))
    if str(enota) == "milliseconds":
        answer = stevilo * 10**3
    elif str(enota) == "microseconds":
        answer = stevilo * 10**6
    elif str(enota) == "nanoseconds":
        answer = stevilo * 10**9
    elif str(enota) == "picoseconds":
        answer = stevilo * 10**12

    return render_template("converter_rezultat.html", stevilo=stevilo, enota=enota, user=user, answer=answer)

"""""
@app.route("/send", methods=["GET"])
def profile_edit_get():
    session_token = request.cookies.get("session_token")
    user = db.query(User).filter_by(session_token=session_token).first()
    if user is None:
        response = make_response(
            redirect(url_for("login"))
        )
        return response
    return render_template("sent_page.html", user=user)


@app.route("/send", methods=["POST"])
def message_post():
    session_token = request.cookies.get("session_token")
    user = db.query(User).filter_by(session_token=session_token).first()
    if user is None:
        response = make_response(
            redirect(url_for("login"))
        )
        return response

    receiver = request.form.get("receiver")
    message = request.form.get("message")

    user = User(receiver=receiver, message=message, sender=user)

    db.add(user)
    db.commit()

    return render_template("profile.html")
"""

if __name__ == '__main__':
    app.run()
