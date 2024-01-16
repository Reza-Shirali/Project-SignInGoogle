from database import db
from flask_login import UserMixin

class User(UserMixin, db.Model):
    id = db.Column(db.String(500), primary_key=True)
    name = db.Column(db.String(500))
    email = db.Column(db.String(500), unique=True)
    profile_pic = db.Column(db.String(500))
    is_active = db.Column(db.Boolean, default=True)

    def get(unique_id):
        user = db.session.query(User).filter_by(id=unique_id).first()
        return user