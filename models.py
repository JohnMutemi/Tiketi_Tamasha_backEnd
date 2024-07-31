from init import db
from flask_login import UserMixin

class Org(db.Model, UserMixin):
    __tablename__ = "org"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    occasion = db.Column(db.String(120))
    location = db.Column(db.String(120))
    price = db.Column(db.Integer, nullable=False)
    address = db.Column(db.String(120))
    contact = db.Column(db.Integer, unique=True, nullable=False)
    requirement = db.Column(db.String(80), nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    details = db.Column(db.String(1000))
    accomodation = db.Column(db.String(120))
    special = db.Column(db.String(120))

    def __repr__(self):
        return f"Org('{self.name}', '{self.email}', '{self.password}', '{self.occasion}', '{self.location}', '{self.price}', '{self.accomodation}', '{self.details}', '{self.address}', '{self.contact}', '{self.requirement}')"
