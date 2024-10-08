from flask_sqlalchemy import SQLAlchemy
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy import MetaData
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import validates
from sqlalchemy.orm import validates, relationship, backref

convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
}

metadata = MetaData(naming_convention=convention)
db = SQLAlchemy(metadata=metadata)

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    _password_hash = db.Column(db.String(1000), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    otp = db.Column(db.String(6), nullable=True)
    otp_expiration = db.Column(db.DateTime, nullable=True)

    events = db.relationship('Event', back_populates='organizer', cascade='all, delete-orphan')
    tickets = db.relationship('Ticket', back_populates='user', cascade='all, delete-orphan')

    serialize_rules = ('-_password_hash', '-events.organizer') 

    def __repr__(self):
        return f'<User {self.username}>'

    @property
    def password_hash(self):
        return self._password_hash

    @password_hash.setter
    def password_hash(self, password):
        self._password_hash = generate_password_hash(password)

    def set_password(self, password):
        self.password_hash = password

    def check_password(self, password):
        return check_password_hash(self._password_hash, password)

    @validates('username')
    def validate_username(self, key, username):
        if not username:
            raise ValueError("Username cannot be empty")
        if len(username) > 50:
            raise ValueError("Username must be 50 characters or less")
        return username

    @validates('email')
    def validate_email(self, key, email):
        if not email:
            raise ValueError("Email cannot be empty")
        if len(email) > 120:
            raise ValueError('Email must be 120 characters or less')
        return email

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'created_at': self.created_at.strftime('%Y-%m-%d %H:%M:%S') if self.created_at else None,
        }

    def is_admin(self):
        return self.role == 'admin'

    def create_user(self, username, email, password, role):
        if not self.is_admin():
            raise PermissionError("Only admins can create users.")
        new_user = User(username=username, email=email, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        return new_user

    def update_user(self, user_id, **kwargs):
        if not self.is_admin():
            raise PermissionError("Only admins can update users.")
        user = User.query.get(user_id)
        for key, value in kwargs.items():
            if hasattr(user, key):
                setattr(user, key, value)
        db.session.commit()
        return user

    def delete_user(self, user_id):
        if not self.is_admin():
            raise PermissionError("Only admins can delete users.")
        user = User.query.get(user_id)
        db.session.delete(user)
        db.session.commit()

    def manage_event(self, event_id, **kwargs):
        if not self.is_admin():
            raise PermissionError("Only admins can manage events.")
        event = Event.query.get(event_id)
        for key, value in kwargs.items():
            if hasattr(event, key):
                setattr(event, key, value)
        db.session.commit()
        return event

    def delete_event(self, event_id):
        if not self.is_admin():
            raise PermissionError("Only admins can delete events.")
        event = Event.query.get(event_id)
        db.session.delete(event)
        db.session.commit()

class Event(db.Model, SerializerMixin):
    __tablename__ = 'events'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(100), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    organizer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    total_tickets = db.Column(db.Integer, nullable=False)
    remaining_tickets = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    image_url = db.Column(db.String(255), nullable=True)

    organizer = db.relationship('User', back_populates='events')
    tickets = db.relationship('Ticket', back_populates='event', cascade='all, delete-orphan')
    event_categories = db.relationship('EventCategory', back_populates='event', cascade='all, delete-orphan')

    serialize_rules = ('-tickets.event', '-event_categories.event')


class Payment(db.Model, SerializerMixin):
    __tablename__ = 'payments'
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.Integer, db.ForeignKey('tickets.id'), nullable=False)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    payment_method = db.Column(db.String(50), nullable=False)
    payment_status = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    mpesa_transaction_id = db.Column(db.String(255))
    phone_number = db.Column(db.String(20))  

    ticket = db.relationship('Ticket', back_populates='payments')

    serialize_rules = ('-ticket.payments',)


class Category(db.Model, SerializerMixin):
    __tablename__ = 'categories'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

    event_categories = db.relationship('EventCategory', back_populates='category', cascade='all, delete-orphan')

    serialize_rules = ('-event_categories.category',)

class EventCategory(db.Model, SerializerMixin):
    __tablename__ = 'event_categories'
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), primary_key=True)
    category_id = db.Column(db.Integer, db.ForeignKey('categories.id'), primary_key=True)

    event = db.relationship('Event', back_populates='event_categories')
    category = db.relationship('Category', back_populates='event_categories')

    serialize_rules = ('-event.event_categories', '-category.event_categories')

class RevokedToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(120), unique=True, nullable=False)
    revoked_at = db.Column(db.DateTime, default=datetime.utcnow)

class BookedEvent(db.Model):
    __tablename__ = 'booked_events'
    
    id = db.Column(db.Integer, primary_key=True)
    image_url = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    description = db.Column(db.Text, nullable=False)
    
    TICKET_TYPES = ['Early', 'VIP', 'Regular']
    ticket_type = db.Column(db.Enum(*TICKET_TYPES, name="ticket_types"), nullable=False)
    
    PAYMENT_STATUS = ['Pending', 'Verified']
    payment_status = db.Column(db.Enum(*PAYMENT_STATUS, name="payment_status"), nullable=False)
    
    def __repr__(self):
        return f'<BookedEvent {self.name} - {self.ticket_type}>'



class Ticket(db.Model, SerializerMixin):
    __tablename__ = 'tickets'
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    ticket_type = db.Column(db.String(50), nullable=False)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    purchased_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    quantity = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), nullable=False)

    event = db.relationship('Event', back_populates='tickets')
    user = db.relationship('User', back_populates='tickets')
    payments = db.relationship('Payment', back_populates='ticket', cascade='all, delete-orphan')

    serialize_rules = ('-event.tickets', '-user.tickets', '-payments.ticket')
