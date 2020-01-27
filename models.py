import os

from sqla_wrapper import SQLAlchemy
import uuid


db = SQLAlchemy(os.getenv("DATABASE_URL", "sqlite:///localhost.sqlite"))


class User(db.Model):
    uid = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, unique=True)
    email = db.Column(db.String, unique=True)
    lastname = db.Column(db.String)
    password = db.Column(db.String)
    session_token = db.Column(db.String)

    def profile_url(self):
        return f"/profiles/{self.uid}"


class message(db.Model):
    uid = db.Column(db.Integer, primary_key=True)
    user_post = db.Column(db.String)


"""
class Message(models.Model):
    sender = models.ForeignKey
    receiver = models.ForeignKey
    message = models.Column(models.String)
"""

def init_data():
    db.drop_all()
    db.create_all()
    for j in range(1, 6):
        uporabnik1 = User(
            name="Uporabnik" + str(j),
            email="uporabnik" + str(j) + "@neki.domena.si",
            lastname="Uporabnikpriimek" + str(j),
            password="password",
            session_token=str(uuid.uuid4()),
        )
        db.add(uporabnik1)
    db.commit()
