from flask import Flask, request, jsonify, make_response, session, send_file, current_app
from flask_migrate import Migrate
from flask_cors import CORS
from flask_restful import Api, Resource
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from flask_jwt_extended.exceptions import RevokedTokenError
from werkzeug.security import generate_password_hash
from werkzeug.exceptions import NotFound
from datetime import timedelta, datetime
from threading import Timer
from dotenv import load_dotenv
import jwt
from jwt.exceptions import InvalidTokenError
from utils import generate_otp, send_otp_to_email
from datetime import datetime, timedelta
from sqlalchemy.exc import SQLAlchemyError
import random, os, requests
from flask_otp import OTP
from sqlalchemy.orm import joinedload
from intasend import APIService
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from ics import Calendar, Event

otp = OTP()
otp.init_app(current_app)

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*", "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]}})

# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(' DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["JWT_SECRET_KEY"] = "fsbdgfnhgvjnvhmvh" + str(random.randint(1, 1000000000000))
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=1)
app.config["SECRET_KEY"] = "JKSRVHJVFBSRDFV" + str(random.randint(1, 1000000000000))
app.json.compact = False
api = Api(app)


from models import db, User, Event, Category, Payment, Ticket, RevokedToken, BookedEvent
db.init_app(app)
jwt = JWTManager(app)
migrate=Migrate(app, db)


@app.errorhandler(NotFound)
def handle_not_found(e):
    response = make_response(
        jsonify({'error': 'NotFound', 'message': 'The requested resource does not exist'}),
        404
    )
    response.headers['Content-Type'] = 'application/json'
    return response

app.register_error_handler(404, handle_not_found)


@app.route('/sessions/<string:key>', methods=['GET'])
def show_cookies(key):
    session['username'] = session.get('username') or 'jack_daniels'
    session_value = session.get(key, 'Key not found')
    response = make_response(jsonify({
        'session': {
            'session_key': key,
            'session_value': session_value,
            'session_access': session.accessed,
        },
        'cookie': [{cookie: request.cookies[cookie]}
                   for cookie in request.cookies], }), 200)
    response.set_cookie('cookie_name', 'cookie')
    return response
@app.route('/')

def index():
    return '<h3> Tiketi Tamasha Backend Repository</h3>'

class UserResource(Resource):

    @jwt_required()
    def post(self):
        user_identity = get_jwt_identity()
        current_user = User.query.get(user_identity['user_id'])

        if not current_user or current_user.role != 'admin':
            return {'message': 'Access denied. Admins only.'}, 403

        data = request.get_json()

        if not data or 'email' not in data or 'password' not in data:
            return {'error': 'Email and password are required.'}, 400

        hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')

        try:
            user = User(
                email=data['email'],
                _password_hash=hashed_password,
                username=data.get('username', ''),
                role=data.get('role', 'user')
            )
            db.session.add(user)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 500
        
        return {'message': 'User created successfully', 'user_id': user.id}, 201

    @jwt_required()
    def get(self, user_id=None):
        user_identity = get_jwt_identity()
        current_user = User.query.get(user_identity['user_id'])

        if not current_user or current_user.role != 'admin':
            return {'message': 'Access denied. Admins only.'}, 403

        if user_id:
            user = User.query.get(user_id)
            if not user:
                return {'message': 'User not found.'}, 404
            return user.to_dict(), 200

        users = User.query.all()
        return {'users': [user.to_dict() for user in users]}, 200

    @jwt_required()
    def put(self, user_id):
        user_identity = get_jwt_identity()
        current_user = User.query.get(user_identity['user_id'])

        if not current_user or current_user.role != 'admin':
            return {'message': 'Access denied. Admins only.'}, 403

        data = request.get_json()
        user = User.query.get(user_id)

        if not user:
            return {'message': 'User not found.'}, 404

        if 'email' in data:
            user.email = data['email']
        if 'password' in data:
            user._password_hash = generate_password_hash(data['password'], method='pbkdf2:sha256')
        if 'username' in data:
            user.username = data['username']
        if 'role' in data:
            user.role = data['role']

        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 500

        return {'message': 'User updated successfully'}, 200

    @jwt_required()
    def delete(self, user_id):
        user_identity = get_jwt_identity()
        current_user = User.query.get(user_identity['user_id'])

        if not current_user or current_user.role != 'admin':
            return {'message': 'Access denied. Admins only.'}, 403

        user = User.query.get(user_id)
        if not user:
            return {'message': 'User not found.'}, 404

        try:
            db.session.delete(user)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return {'error': str(e)}, 500

        return {'message': 'User deleted successfully'}, 200
class Login(Resource):

    def post(self):
        username = request.form.get('username')
        password = request.form.get('password')
        stay_logged_in = request.form.get('stayLoggedIn') == 'true'

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            # Set token expiration based on stay_logged_in
            if stay_logged_in:
                expires = timedelta(days=30)  # Long expiration for stay logged in
            else:
                expires = timedelta(hours=1)  # Short expiration for a regular session
            access_token = create_access_token(identity={'user_id': user.id, 'role': user.role}, expires_delta=expires)
            return {
                'message': f"Welcome {user.username}",
                'access_token': access_token,
                'username': user.username,
                'email': user.email,
                'role': user.role,
                'user_id': user.id
            }, 200
        else:
            return {"error": "Invalid username or password"}, 401


# Handle Registration and Approval 
class PublicRegister(Resource):
    def post(self):
        username = request.form.get('username')
        _password_hash = request.form.get('password')
        email = request.form.get('email')
        role = request.form.get('role')

        print(f"Received registration data: username={username}, email={email}, role={role}")

        # Validate required fields
        if not username or not _password_hash or not email or not role:
            return {'message': 'Username, password, role, and email are required'}, 400
        
        if role not in ['event_organizer', 'customer']:
            return {'message': 'Invalid role. Choose either "event_organizer" or "customer"'}, 400

        # Check if the user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return {'message': 'User already exists'}, 400

        # Hash the password for security
        hashed_password = generate_password_hash(_password_hash)

        # Generate and send OTP
        otp_code = generate_otp()
        otp_expiration = datetime.utcnow() + timedelta(minutes=10)  # OTP expires in 10 minutes
        print(f"Generated OTP: {otp_code}")
        send_otp_to_email(email, otp_code)

        # Create a new user instance with OTP and save it
        new_user = User(
            username=username,
            email=email,
            _password_hash=hashed_password,
            role=role,
            otp=otp_code,
            otp_expiration=otp_expiration
        )

        db.session.add(new_user)
        db.session.commit()

        print(f"Stored user with OTP in database: {new_user}")

        return {'message': 'OTP sent to email. Please verify.'}, 200

class VerifyOTP(Resource):
    def post(self):
        entered_otp = request.json.get('otp')
        print(f"Received OTP for verification: {entered_otp}")

        # Validate the OTP input
        if not entered_otp:
            return {'message': 'OTP is required'}, 400

        # Retrieve the user record from the database using the OTP
        user = User.query.filter_by(otp=entered_otp).first()
        if not user:
            return {'message': 'Invalid OTP'}, 400

        # Check if the OTP is expired
        if datetime.utcnow() > user.otp_expiration:
            return {'message': 'OTP has expired'}, 400

        try:
            # Complete user registration by clearing the OTP fields
            user.otp = None
            user.otp_expiration = None
            db.session.commit()

            print(f"User registered successfully: {user.username}")

            return {'message': 'User registered and logged in successfully'}, 201
        except Exception as e:
            current_app.logger.error(f"Error occurred during OTP verification: {e}")
            return {'message': 'Internal server error'}, 500


class AdminRegister(Resource):
    @jwt_required()
    def post(self):
        current_user = get_jwt_identity()
        current_user_role = current_user['role']

        # Only allow admins to register new admins
        if current_user_role != 'admin':
            return {'message': 'Unauthorized. Only admins can register new admins.'}, 403

        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        role = request.form.get('role')

        if not username or not password or not email or not role:
            return {'message': 'Username, password, role, and email are required'}, 400
        
        if role != 'admin':
            return {'message': 'Invalid role. Only "admin" role can be registered here.'}, 400

        # Check for the allowed email domain
        allowed_domains = ['gmail.com']
        email_domain = email.split('@')[-1]

        if email_domain not in allowed_domains:
            return {'message': f'Invalid email domain. Admins must use an email ending in @{allowed_domains[0]}'}, 400

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return {'message': 'User already exists'}, 400

        try:
            new_user = User(username=username, email=email, role=role)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()

            return {'message': 'Admin registered successfully'}, 201
        except Exception as e:
            print(f"Error occurred during registration: {e}")
            return {'message': 'Internal server error'}, 500

    
class EventsResource(Resource):
    
    def get(self):
        print("Fetching all events")
        events = Event.query.all()
        event_list = []

        for event in events:
            event_list.append({
                'id': event.id,
                'title': event.title,
                'description': event.description,
                'location': event.location,
                'start_time': event.start_time.isoformat(),
                'end_time': event.end_time.isoformat(),
                'total_tickets': event.total_tickets,
                'remaining_tickets': event.remaining_tickets,
                'image_url': event.image_url,
                'organizer_id':event.organizer_id
            })

        print(f"Event list: {event_list}")
        return jsonify(event_list)

    @jwt_required()
    def post(self):
        print("Received POST request to create an event")
        current_user = get_jwt_identity()
        print(f"Current user: {current_user}")

        data = request.get_json()
        if not data:
            return {'message': 'No data provided'}, 400

        required_fields = ['title', 'description', 'location', 'start_time', 'end_time', 'total_tickets', 'remaining_tickets', 'image_url']
        if not all(field in data for field in required_fields):
            return {'message': 'Missing fields in request'}, 400

        current_user_role = current_user['role']
        if current_user_role not in ['admin', 'event_organizer']:
            return {'message': 'Unauthorized. Only admins or event organizers can create events.'}, 403

        try:
            event = Event(
                title=data['title'],
                description=data['description'],
                location=data['location'],
                start_time=datetime.fromisoformat(data['start_time']),
                end_time=datetime.fromisoformat(data['end_time']),
                total_tickets=int(data['total_tickets']),
                remaining_tickets=int(data['remaining_tickets']),
                image_url=data['image_url'],
                organizer_id=current_user['user_id'] if current_user_role == 'event_organizer' else None
            )
            db.session.add(event)
            db.session.commit()
            print(f"Event created successfully: {event}")
            return {'message': 'Event created successfully', 'event': event.to_dict()}, 201
        except Exception as e:
            print(f"Error occurred during event creation: {e}")
            return {'message': 'Internal server error'}, 500

    @jwt_required()
    def patch(self, event_id):
        print(f"Received PATCH request for event ID {event_id}")
        current_user = get_jwt_identity()
        if current_user['role'] not in ['admin', 'event_organizer']:
            return {'message': 'Access denied'}, 403

        event = Event.query.get(event_id)
        if not event:
            return {'message': 'Event not found'}, 404

        data = request.get_json()
        if not data:
            return {'message': 'No data provided'}, 400

        try:
            event.title = data.get('title', event.title)
            event.description = data.get('description', event.description)
            event.location = data.get('location', event.location)
            event.start_time = datetime.fromisoformat(data.get('start_time', event.start_time.isoformat()))
            event.end_time = datetime.fromisoformat(data.get('end_time', event.end_time.isoformat()))
            event.total_tickets = int(data.get('total_tickets', event.total_tickets))
            event.remaining_tickets = int(data.get('remaining_tickets', event.remaining_tickets))
            event.image_url = data.get('image_url', event.image_url)

            db.session.commit()
            print(f"Event updated successfully: {event}")
            return {'message': 'Event updated successfully'}, 200
        except Exception as e:
            print(f"Error occurred during event update: {e}")
            return {'message': 'Internal server error'}, 500

    @jwt_required()
    def delete(self, event_id):
        print(f"Received DELETE request for event ID {event_id}")
        current_user = get_jwt_identity()
        if current_user['role'] != 'admin':
            return {'message': 'Access denied'}, 403

        event = Event.query.get(event_id)
        if not event:
            return {'message': 'Event not found'}, 404

        try:
            db.session.delete(event)
            db.session.commit()
            print(f"Event deleted successfully: {event_id}")
            return {'message': 'Event deleted successfully'}, 200
        except Exception as e:
            print(f"Error occurred during event deletion: {e}")
            return {'message': 'Internal server error'}, 500
class EventAttendeesResource(Resource):
    @jwt_required()
    def get(self, event_id):
        try:
            print(f"Fetching attendees for event ID {event_id}")

            # Fetch the event first to ensure it exists
            event = Event.query.get(event_id)
            if not event:
                return {'message': 'Event not found'}, 404

            # Fetch the tickets related to the event
            tickets = Ticket.query.filter_by(event_id=event_id).all()

            # Extract attendee information
            attendees = [
                {
                    'id': ticket.user.id,
                    'name': ticket.user.username,
                    'email': ticket.user.email,
                    'ticket_type': ticket.ticket_type,
                    'quantity': ticket.quantity
                }
                for ticket in tickets if ticket.user is not None
            ]

         

            # Return the list of event attendees
            return jsonify(attendees)

        except Exception as e:
            print(f"Error fetching attendees: {e}")
            return {'message': 'An error occurred while fetching attendees.'}, 500

        

   


class OrganizerEvents(Resource):

    @jwt_required()
    def get(self):
        print("Received GET request for organizer events")
        current_user = get_jwt_identity()
        print(f"Current user: {current_user}")

        if current_user['role'] not in ['admin', 'event_organizer']:
            return {'message': 'Unauthorized. Only admins or event organizers can view events.'}, 403

        try:
            events = Event.query.filter_by(organizer_id=current_user['user_id']).all()
            events_list = [event.to_dict() for event in events]
            print(f"Events retrieved successfully: {events_list}")
            return {'events': events_list}, 200
        except SQLAlchemyError as e:
            print(f"Error occurred while retrieving events: {e}")
            return {'message': 'Internal server error'}, 500

    @jwt_required()
    def post(self):
        print("Received POST request to create an event")
        current_user = get_jwt_identity()
        print(f"Current user: {current_user}")

        data = request.get_json()
        if not data:
            return {'message': 'No data provided'}, 400

        required_fields = ['title', 'description', 'location', 'start_time', 'end_time', 'total_tickets', 'remaining_tickets', 'image_url']
        if not all(field in data for field in required_fields):
            return {'message': 'Missing fields in request'}, 400

        if current_user['role'] != 'event_organizer':
            return {'message': 'Unauthorized. Only event organizers can create events.'}, 403

        try:
            event = Event(
                title=data['title'],
                description=data['description'],
                location=data['location'],
                start_time=datetime.fromisoformat(data['start_time']),
                end_time=datetime.fromisoformat(data['end_time']),
                total_tickets=int(data['total_tickets']),
                remaining_tickets=int(data['remaining_tickets']),
                image_url=data['image_url'],
                organizer_id=current_user['user_id']
            )
            db.session.add(event)
            db.session.commit()
            print(f"Event created successfully: {event}")
            return {'message': 'Event created successfully', 'event': event.to_dict()}, 201
        except SQLAlchemyError as e:
            db.session.rollback()
            print(f"Error occurred during event creation: {e}")
            return {'message': 'Internal server error'}, 500
        except Exception as e:
            print(f"Unexpected error occurred: {e}")
            return {'message': 'Unexpected error'}, 500

    @jwt_required()
    def patch(self, event_id):
        print(f"Received PATCH request for event ID {event_id}")
        current_user = get_jwt_identity()
        if current_user['role'] != 'event_organizer':
            return {'message': 'Access denied'}, 403

        event = Event.query.get(event_id)
        if not event or event.organizer_id != current_user['user_id']:
            return {'message': 'Event not found or access denied'}, 404

        data = request.get_json()
        if not data:
            return {'message': 'No data provided'}, 400

        try:
            event.title = data.get('title', event.title)
            event.description = data.get('description', event.description)
            event.location = data.get('location', event.location)
            event.start_time = datetime.fromisoformat(data.get('start_time', event.start_time.isoformat()))
            event.end_time = datetime.fromisoformat(data.get('end_time', event.end_time.isoformat()))
            event.total_tickets = int(data.get('total_tickets', event.total_tickets))
            event.remaining_tickets = int(data.get('remaining_tickets', event.remaining_tickets))
            event.image_url = data.get('image_url', event.image_url)

            db.session.commit()
            print(f"Event updated successfully: {event}")
            return {'message': 'Event updated successfully'}, 200
        except SQLAlchemyError as e:
            db.session.rollback()
            print(f"Error occurred during event update: {e}")
            return {'message': 'Internal server error'}, 500
        except Exception as e:
            print(f"Unexpected error occurred: {e}")
            return {'message': 'Unexpected error'}, 500

    @jwt_required()
    def delete(self, event_id):
        print(f"Received DELETE request for event ID {event_id}")
        current_user = get_jwt_identity()
        if current_user['role'] != 'event_organizer':
            return {'message': 'Access denied'}, 403

        event = Event.query.get(event_id)
        if not event or event.organizer_id != current_user['user_id']:
            return {'message': 'Event not found or access denied'}, 404

        try:
            db.session.delete(event)
            db.session.commit()
            print(f"Event deleted successfully: {event_id}")
            return {'message': 'Event deleted successfully'}, 200
        except SQLAlchemyError as e:
            db.session.rollback()
            print(f"Error occurred during event deletion: {e}")
            return {'message': 'Internal server error'}, 500
        except Exception as e:
            print(f"Unexpected error occurred: {e}")
            return {'message': 'Unexpected error'}, 500


revoked_tokens = set() 

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    token = RevokedToken.query.filter_by(jti=jti).first()
    return token is not None

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    try:
        token = get_jwt()
        # Process token
    except InvalidTokenError:
        return jsonify({"msg": "Invalid token"}), 401
    
class Logout(Resource):
    @jwt_required()
    def post(self):
        jti = get_jwt()['jti']
        revoked_token = RevokedToken(jti=jti)
        db.session.add(revoked_token)
        db.session.commit()
        session.clear()
        response_data = {"message": "Logout successful"}
        print("Response Data:", response_data)  
        return response_data, 200

@app.errorhandler(Exception)
def handle_exception(e):
    response = {
        "message": "An unexpected error occurred.",
        "error": str(e)
    }
    print("Exception occurred:", e)  
    print("Response Data:", response)  
    return jsonify(response), 5

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        print("Session user_id:", user_id)  
        
        if not user_id:
            error_response = {"error": "No active session"}
            print("Error Response:", error_response)  
            return jsonify(error_response), 401

        user = User.query.get(user_id)
        if user:
            user_data = user.to_dict()
            print("User Data:", user_data)  
            return jsonify(user_data), 200
        
        error_response = {"error": "User not found"}
        print("Error Response:", error_response) 
        return jsonify(error_response), 404
class CategoryResource(Resource):
    def get(self, category_id=None):
        if category_id:
            # Fetch a single category by ID
            category = Category.query.get_or_404(category_id)
            return category.to_dict(), 200
        else:
            # Fetch all categories
            categories = Category.query.all()
            return [category.to_dict() for category in categories], 200

    @jwt_required()
    def post(self):
        # Check if the user is an admin
        current_user = get_jwt_identity()
        if current_user.get('role') != 'admin':  # Adjust based on how role is stored in JWT
            return {'message': 'Admin access required'}, 403

        # Handle JSON data for creating a new category
        data = request.get_json()
        name = data.get('name')

        if not name:
            return {'message': 'Name is required'}, 400

        new_category = Category(name=name)
        db.session.add(new_category)
        db.session.commit()
        return new_category.to_dict(), 201

    @jwt_required()
    def put(self, category_id):
        # Check if the user is an admin
        current_user = get_jwt_identity()
        if current_user.get('role') != 'admin':  # Adjust based on how role is stored in JWT
            return {'message': 'Admin access required'}, 403

        # Handle JSON data for updating an existing category
        category = Category.query.get_or_404(category_id)
        data = request.get_json()
        name = data.get('name')

        if not name:
            return {'message': 'Name is required'}, 400

        category.name = name
        db.session.commit()
        return category.to_dict(), 200

    @jwt_required()
    def delete(self, category_id):
        # Check if the user is an admin
        current_user = get_jwt_identity()
        if current_user.get('role') != 'admin':  # Adjust based on how role is stored in JWT
            return {'message': 'Admin access required'}, 403

        # Handle deletion of a category
        category = Category.query.get_or_404(category_id)
        db.session.delete(category)
        db.session.commit()
        return '', 204
    
class TicketResource(Resource):
    def get(self, ticket_id=None):
        # Retrieve the user_id from the query parameters
        user_id = request.args.get('user_id')
        
        if ticket_id:
            # Retrieve a specific ticket by ID
            ticket = Ticket.query.get(ticket_id)
            if ticket:
                # Fetch the event details if the ticket exists
                event = Event.query.get(ticket.event_id)
                return {
                    'id': ticket.id,
                    'event_id': ticket.event_id,
                    'user_id': ticket.user_id,
                    'ticket_type': ticket.ticket_type,
                    'price': float(ticket.price),
                    'quantity': ticket.quantity,
                    'status': ticket.status,
                    'event': {
                        'title': event.title if event else 'Unknown Event',
                        'start_time': ticket.event.start_time.isoformat(),
                        'end_time': ticket.event.end_time.isoformat()
                    }
                }, 200
            return {'error': 'Ticket not found'}, 404

        # List all tickets or filter by user_id
        if user_id:
            tickets = Ticket.query.filter_by(user_id=user_id).all()
        else:
            tickets = Ticket.query.all()

        # Fetch event details for each ticket
        return [
            {
                'id': ticket.id,
                'event_id': ticket.event_id,
                'user_id': ticket.user_id,
                'ticket_type': ticket.ticket_type,
                'price': float(ticket.price),
                'quantity': ticket.quantity,
                'status': ticket.status,
                'event': {
                    'title': Event.query.get(ticket.event_id).title if Event.query.get(ticket.event_id) else 'Unknown Event'
                }
            }
            for ticket in tickets
        ], 200
    
class UserRole(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'error': 'No active session'}), 401
        
        user = User.query.get(user_id)
        if user:
            return jsonify({'role': user.role}), 200

        return jsonify({'error': 'User not found'}), 404

    
class BookTicket(Resource):
    @jwt_required()  
    def post(self):
        user_id = get_jwt_identity()['user_id']
        if not user_id:
            return jsonify({'error': 'No active session'}), 401
        
        user = User.query.get(user_id)
        if user and user.role == 'customer':
            # Perform the booking
            return jsonify({'message': 'Booking successful'}), 200
        
        return jsonify({'error': 'Unauthorized to book tickets'}), 403
    
class AdminDashboard(Resource):
    @jwt_required()
    def get(self, user_id=None, event_id=None, category_id=None, transaction_id=None):
        claims = get_jwt_identity()
        if claims['role'] != 'admin':
            return {'message': 'Access denied'}, 403

        if user_id:
            user = User.query.get_or_404(user_id)
            return user.to_dict(), 200
        
        if event_id:
            event = Event.query.get_or_404(event_id)
            return event.to_dict(), 200
        
        if category_id:
            category = Category.query.get_or_404(category_id)
            return category.to_dict(), 200
        
        if transaction_id:
            transaction = Transaction.query.get_or_404(transaction_id)
            return transaction.to_dict(), 200

        # Overview of users, events, categories, and transactions
        users = User.query.all()
        events = Event.query.all()
        categories = Category.query.all()
        transactions = Transaction.query.all()
        
        return {
            'users': [user.to_dict() for user in users],
            'events': [event.to_dict() for event in events],
            'categories': [category.to_dict() for category in categories],
            'transactions': [transaction.to_dict() for transaction in transactions]
        }, 200

class Transaction(Resource):
    def get(self):
        # Get the user_id from the query parameters (for user-specific history)
        user_id = request.args.get('user_id')

        # Query transactions with eager loading to optimize database access
        transactions_query = Payment.query.options(
            joinedload(Payment.ticket).joinedload(Ticket.user),
            joinedload(Payment.ticket).joinedload(Ticket.event)
        )

        if user_id:
            # Filter by user_id if provided
            transactions_query = transactions_query.filter(Ticket.user_id == user_id)

        transactions = transactions_query.all()

        transaction_list = []
        for payment in transactions:
            ticket = payment.ticket
            user = ticket.user
            event = ticket.event
            
            transaction_list.append({
                'id': payment.id,
                'user': user.username if user else 'Unknown',
                'event': event.title if event else 'Unknown',
                'amount': float(payment.amount),  
                'method': payment.payment_method,
                'status': payment.payment_status,
                'date': payment.created_at.strftime('%Y-%m-%d %H:%M:%S')  
            })

        return jsonify(transaction_list)

    def post(self):
        # Extract data from the request
        data = request.get_json()
        payment_id = data.get('payment_id')
        action = data.get('action')

        if action not in ['approve', 'deny']:
            return {'message': 'Invalid action'}, 400

        # Find the payment by id
        payment = Payment.query.get(payment_id)

        if not payment:
            return {'message': 'Payment not found'}, 404

        # Handle the refund logic based on the action
        if action == 'approve':
            payment.payment_status = 'refunded'
        elif action == 'deny':
            payment.payment_status = 'refund_denied'

        # Commit the changes to the database
        db.session.commit()

        return {'message': f'Refund {action}d successfully'}, 200
    
class Mpesa(Resource):
    def post(self):
        data = request.json
        phone_number = data.get('phone_number')
        amount = data.get('amount')
        email = data.get('email')
        
        if not phone_number or not amount:
            return jsonify({'error': 'Phone number and amount are required.'}), 400

        try:
            service = APIService(
                token='ISSecretKey_test_997023a2-63e1-4864-aa10-3268377569be',
                publishable_key='ISPubKey_test_93dd9667-9e6e-4e4a-99b4-dc9795a392a9',
                test=True
            )
            
            # Initiate the payment
            response = service.collect.mpesa_stk_push(
                phone_number=phone_number,
                email=email,
                amount=amount,
                narrative="Ticket Payment"
            )

            invoice_id = response.get('invoice', {}).get('invoice_id')
            if not invoice_id:
                return jsonify({'error': 'Failed to initiate payment.'}), 500

            print(f"Invoice ID: {invoice_id}")

            # Function to check payment status
            def check_status():
                try:
                    status_response = service.collect.status(invoice_id=invoice_id)
                    print('Status Check Response:', status_response)

                    if status_response and status_response.get('invoice'):
                        status = status_response['invoice'].get('state')
                        print('Payment Status:', status)

                        if status != 'PROCESSING':
                            print(f"Final status: {status}")
                            return jsonify({'message': 'Transaction complete', 'status': status}), 200

                        # If still processing, check again after 6 seconds
                        Timer(6.0, check_status).start()

                    else:
                        print('Invalid response structure:', status_response)
                        return jsonify({'error': 'Failed to check status.'}), 500

                except Exception as e:
                    print('Status Check Error:', str(e))
                    return jsonify({'error': 'Failed to check status.'}), 500

            # Start the status check after 6 seconds
            Timer(6.0, check_status).start()

            return jsonify({'message': 'STK Push initiated', 'data': response}), 201

        except Exception as e:
            print('STK Push Error:', str(e))
            return jsonify({'error': 'Failed to initiate payment.', 'details': str(e)}), 500


# saving to database

            # payment = Payment(
            #     amount=amount,
            #     payment_method='MPESA',
            #     payment_status='Pending',
            #     mpesa_transaction_id=response.get('transaction_id'),
            #     phone_number=phone_number
            # )
            # db.session.add(payment)
            # db.session.commit()

            return jsonify(response)
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    def get(self, payment_id):
        try:
            response = self.intasend.verify_payment(payment_id)
            return jsonify(response)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    

# Define the routes
def initiate_transaction():
    data = request.json
    phone_number = data.get('phone_number')
    amount = data.get('amount')
    email = data.get('email')
    ticket_id = data.get('ticket_id')
    user_id = data.get('user_id')
    
    if not phone_number or not amount or not ticket_id or not user_id:
        return jsonify({'error': 'Phone number, amount, ticket_id, and user_id are required.'}), 400

    try:
        service = APIService(
            token='ISSecretKey_test_997023a2-63e1-4864-aa10-3268377569be',
            publishable_key='ISPubKey_test_93dd9667-9e6e-4e4a-99b4-dc9795a392a9',
            test=True
        )
        
        # Initiate the payment
        response = service.collect.mpesa_stk_push(
            phone_number=phone_number,
            email=email,
            amount=amount,
            narrative="Ticket Payment"
        )
        
        invoice_id = response.get('invoice', {}).get('invoice_id')
        if not invoice_id:
            return jsonify({'error': 'Failed to initiate payment.'}), 500
        
        # Update ticket status to "pending"
        # (Add your database update logic here)
        # Example (assuming SQLAlchemy):
        ticket = Ticket.query.filter_by(id=ticket_id).first()
        if ticket:
            ticket.status = 'pending'
            db.session.commit()

        return jsonify({'message': 'Transaction initiated and ticket status set to pending.', 'data': response}), 201

    except Exception as e:
        return jsonify({'error': 'Failed to initiate payment.', 'details': str(e)}), 500

@app.route('/callback-url', methods=['POST'])
def callback_url():
    json_data = request.get_json()
    transaction_id = json_data.get('transaction_id')
    payment_status = json_data.get('status')

    payment = Payment.query.filter_by(mpesa_transaction_id=transaction_id).first()
    if payment:
        if payment_status == 'success':
            payment.payment_status = 'Completed'
        else:
            payment.payment_status = 'Failed'
        db.session.commit()

    return jsonify({"status": payment_status}), 200


@app.route('/confirm-payment', methods=['POST'])
def confirm_payment():
    data = request.json
    invoice_id = data.get('invoice_id')
    
    if not invoice_id:
        return jsonify({'error': 'Invoice ID is required.'}), 400
    
    try:
        service = APIService(
            token='ISSecretKey_test_997023a2-63e1-4864-aa10-3268377569be',
            publishable_key='ISPubKey_test_93dd9667-9e6e-4e4a-99b4-dc9795a392a9',
            test=True
        )
        status_response = service.collect.status(invoice_id=invoice_id)
        status = status_response.get('invoice', {}).get('state')
        
        if status == 'SUCCESSFUL':
            # Update ticket status and associate with user
            # Assuming the data includes user and ticket details
            user_id = data.get('user_id')
            ticket_id = data.get('ticket_id')
            
            # Fetch and update the ticket and user in the database
            # (Add your database update logic here)
            
            return jsonify({'message': 'Payment confirmed and ticket booked.'}), 200
        else:
            return jsonify({'error': 'Payment not completed successfully.'}), 400
        
    except Exception as e:
        return jsonify({'error': 'Failed to confirm payment.', 'details': str(e)}), 500


@app.route('/download-receipt/<int:payment_id>', methods=['GET'])
def download_receipt(payment_id):
    try:
       
        payment = Payment.query.get(payment_id)

        if not payment:
            return jsonify({"error": "Payment not found"}), 404

        # Create a PDF buffer in memory
        pdf_buffer = BytesIO()

        # Create a canvas to generate the PDF
        pdf = canvas.Canvas(pdf_buffer, pagesize=letter)
        pdf.setTitle("Payment Receipt")

        # Add text and details to the PDF
        pdf.drawString(100, 750, "Payment Receipt")
        pdf.drawString(100, 730, f"Payment ID: {payment.id}")
        pdf.drawString(100, 710, f"Amount: {payment.amount} KES")
        pdf.drawString(100, 690, f"Payment Method: {payment.payment_method}")
        pdf.drawString(100, 670, f"Payment Status: {payment.payment_status}")
        pdf.drawString(100, 650, f"Date: {payment.created_at.strftime('%Y-%m-%d %H:%M:%S')}")

        # Finish the PDF
        pdf.showPage()
        pdf.save()

        # Move the buffer position to the start
        pdf_buffer.seek(0)

        # Send the PDF as a file download
        return send_file(pdf_buffer, as_attachment=True, download_name=f"receipt_{payment_id}.pdf", mimetype='application/pdf')

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
class BookedEventResource(Resource):
    def get(self, event_id=None):
        if event_id:
            event = BookedEvent.query.get_or_404(event_id)
            return {
                'id': event.id,
                'image_url': event.image_url,
                'name': event.name,
                'date': event.date.strftime('%Y-%m-%d %H:%M:%S'),
                'description': event.description,
                'ticket_type': event.ticket_type,
                'payment_status': event.payment_status
            }
        else:
            events = BookedEvent.query.all()
            return [{
                'id': event.id,
                'image_url': event.image_url,
                'name': event.name,
                'date': event.date.strftime('%Y-%m-%d %H:%M:%S'),
                'description': event.description,
                'ticket_type': event.ticket_type,
                'payment_status': event.payment_status
            } for event in events]

    def post(self):
        data = request.json
        new_event = BookedEvent(
            image_url=data.get('image_url'),
            name=data.get('name'),
            date=datetime.strptime(data.get('date'), '%Y-%m-%d %H:%M:%S'),
            description=data.get('description'),
            ticket_type=data.get('ticket_type'),
            payment_status=data.get('payment_status')
        )
        db.session.add(new_event)
        db.session.commit()
        return {'message': 'Event created successfully'}, 201

    def put(self, event_id):
        data = request.json
        event = BookedEvent.query.get_or_404(event_id)

        event.image_url = data.get('image_url', event.image_url)
        event.name = data.get('name', event.name)
        event.date = datetime.strptime(data.get('date'), '%Y-%m-%d %H:%M:%S')
        event.description = data.get('description', event.description)
        event.ticket_type = data.get('ticket_type', event.ticket_type)
        event.payment_status = data.get('payment_status', event.payment_status)

        db.session.commit()
        return {'message': 'Event updated successfully'}

    def delete(self, event_id):
        event = BookedEvent.query.get_or_404(event_id)
        db.session.delete(event)
        db.session.commit()
        return {'message': 'Event deleted successfully'}

class GenerateICS(Resource):
    def get(self, ticket_id):
        # Fetch the ticket from the database
        ticket = Ticket.query.filter_by(id=ticket_id).first()

        if not ticket:
            return jsonify({"message": "Ticket not found"}), 404

        # Fetch the associated event
        event = Event.query.filter_by(id=ticket.event_id).first()

        if not event:
            return jsonify({"message": "Event not found"}), 404

        # Create a new calendar and event
        c = Calendar()
        e = Event()
        e.name = event.title
        e.begin = event.start_time  # Ensure this is a datetime object
        e.description = f"Event: {event.title}\nTicket ID: {ticket_id}"
        e.location = event.location

        # Add event to calendar
        c.events.add(e)

        # Write the calendar data to a temporary in-memory buffer
        file_content = BytesIO()
        file_content.write(c.serialize().encode("utf-8"))  # Use `serialize()` to get the calendar data
        file_content.seek(0)  # Reset the buffer pointer to the beginning

        # Define the file name for download
        file_name = f"{event.title.replace(' ', '_')}.ics"

        # Send the file as an attachment
        return send_file(file_content, as_attachment=True, download_name=file_name, mimetype='text/calendar')
# Create a new resource for updating ticket status
class UpdateTicketStatus(Resource):
    def put(self, ticket_id):
        data = request.get_json()
        ticket = Ticket.query.get(ticket_id)
        
        if not ticket:
            return {'message': 'Ticket not found'}, 404
        
        if 'status' in data:
            ticket.status = data['status']
            db.session.commit()
            return {'message': 'Ticket status updated successfully'}, 200
        else:
            return {'message': 'Status not provided'}, 400
# API end points
api.add_resource(UpdateTicketStatus, '/update-ticket-status/<int:ticket_id>')
api.add_resource(Mpesa, '/mpesa', '/mpesa/<string:payment_id>')
api.add_resource(GenerateICS, '/generate_ics/<int:ticket_id>')
api.add_resource(EventAttendeesResource, '/events/<int:event_id>/attendees')
api.add_resource(Transaction, '/payments')
api.add_resource(CategoryResource, '/categories', '/categories/<int:category_id>')
api.add_resource(UserResource, '/users', '/users/<int:user_id>')
api.add_resource(Login, '/login')
api.add_resource(CheckSession, '/session')
api.add_resource(Logout, '/logout')
api.add_resource(PublicRegister, '/register')
api.add_resource(AdminRegister, '/register/admin') 
api.add_resource(OrganizerEvents, '/organizer-events', '/organizer-events/<int:event_id>') 
api.add_resource(TicketResource, '/tickets', '/tickets/<int:ticket_id>')
api.add_resource(UserRole, '/user-role')
api.add_resource(BookTicket, '/book-ticket')
api.add_resource(
    AdminDashboard,
    '/admin-dashboard',
    '/admin-dashboard/users/<int:user_id>',
    '/admin-dashboard/events/<int:event_id>',
    '/admin-dashboard/categories',
    '/admin-dashboard/categories/<int:category_id>',
    '/admin-dashboard/transactions',
    '/admin-dashboard/transactions/<int:transaction_id>'
)
api.add_resource(EventsResource, '/events','/events/<int:event_id>')
api.add_resource(VerifyOTP, '/verify-otp')
api.add_resource(BookedEventResource, '/api/booked-events', '/api/booked-events/<int:event_id>')

if __name__ == '__main__':
    app.run(port=5555, debug=True)