from flask import Flask, request, jsonify, make_response, session, url_for,  render_template, redirect
from flask_migrate import Migrate
from flask_cors import CORS
from flask_restful import Api, Resource
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from flask_jwt_extended.exceptions import RevokedTokenError
from werkzeug.exceptions import NotFound
from datetime import timedelta, datetime
from jwt.exceptions import DecodeError
from utils import generate_totp_secret, generate_totp_token, send_email
from datetime import datetime, timedelta
import random, pyotp, os

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*", "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]}})
app.config['SQLALCHEMY_DATABASE_URI'] =os.environ.get('DATABASE_URI') 
app.config["JWT_SECRET_KEY"] = "fsbdgfnhgvjnvhmvh" + str(random.randint(1, 1000000000000))
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=1)
app.config["SECRET_KEY"] = "JKSRVHJVFBSRDFV" + str(random.randint(1, 1000000000000))
app.json.compact = False
api = Api(app)

from models import db, User, Event, Category, EventCategory, Payment, Ticket, RevokedToken
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
    return render_template('index.html')

class UserResource(Resource):
    @jwt_required()
    def get(self, user_id=None):
        user_identity = get_jwt_identity()
        current_user = User.query.get(user_identity['user_id'])

        if not current_user:
            return {'error': 'User not found'}, 404

        if current_user.role != 'admin':
            return {'message': 'Access denied'}, 403

        if user_id:
            user = User.query.get(user_id)
            if user:
                return user.to_dict(), 200
            return {'error': 'User not found'}, 404
        
        users = User.query.all()
        return [user.to_dict() for user in users], 200
     
    @jwt_required()
    def delete(self, user_id):
        user_identity = get_jwt_identity()
        current_user = User.query.get(user_identity['user_id'])

        if not current_user:
            return {'error': 'User not found'}, 404

        if current_user.role != 'admin':
            return {'message': 'Access denied'}, 403

        user = User.query.get(user_id)
        if not user:
            return {'error': 'User not found'}, 404
        
        try:
            db.session.delete(user)
            db.session.commit()
            return {'message': 'User deleted successfully'}, 200
        except Exception as e:
            print(f"Error occurred during user deletion: {e}")
            return {'message': 'Internal server error'}, 500

    @jwt_required()
    def put(self, user_id):
        user_identity = get_jwt_identity()
        current_user = User.query.get(user_identity['user_id'])

        if not current_user:
            return {'error': 'User not found'}, 404

        if current_user.role != 'admin':
            return {'message': 'Access denied'}, 403

        user = User.query.get(user_id)
        if not user:
            return {'error': 'User not found'}, 404
        
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        role = request.form.get('role')

        if username:
            user.username = username
        if password:
            user.set_password(password)
        if email:
            user.email = email
        if role:
            if role not in ['event_organizer', 'customer', 'admin']:
                return {'message': 'Invalid role. Choose either "event_organizer", "customer", or "admin"'}, 400
            user.role = role

        try:
            db.session.commit()
            return {'message': 'User updated successfully'}, 200
        except Exception as e:
            print(f"Error occurred during user update: {e}")
            return {'message': 'Internal server error'}, 500


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
        password = request.form.get('password')
        email = request.form.get('email')
        role = request.form.get('role')

        if not username or not password or not email or not role:
            return {'message': 'Username, password, role, and email are required'}, 400
        
        if role not in ['event_organizer', 'customer']:
            return {'message': 'Invalid role. Choose either "event_organizer" or "customer"'}, 400

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return {'message': 'User already exists'}, 400

        try:
            new_user = User(username=username, email=email, role=role)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()

            return {'message': 'User registered successfully. Waiting for admin approval.'}, 201
        except Exception as e:
            app.logger.error(f"Error occurred during registration: {e}")
            return {'message': 'Internal server error'}, 500
       
class GenerateOTP(Resource):
    def post(self):
        user_email = request.form.get('email')
        if not user_email:
            print("Email is required")  # Debug print statement
            return jsonify({"error": "Email is required"}), 400

        user = User.query.filter_by(email=user_email).first()
        if not user:
            print(f"User with email {user_email} not found")  # Debug print statement
            return jsonify({"error": "User not found"}), 404

        otp_secret = generate_totp_secret()
        otp_token = generate_totp_token(otp_secret)
        otp_expiration = datetime.utcnow() + timedelta(minutes=10)
        
        # Save OTP secret and token to the user's record
        user.otp_secret = otp_secret
        user.otp = otp_token
        user.otp_expiration = otp_expiration
        db.session.commit()

        print(f"Generated OTP for user {user_email}: {otp_token}")  # Debug print statement

        subject = "Your OTP Code"
        body = f"Your OTP code is {otp_token}. It is valid for 10 minutes."

        if send_email(user_email, subject, body):
            print(f"OTP sent to {user_email}")  # Debug print statement
            return jsonify({"message": "OTP sent successfully"}), 200
        else:
            print(f"Failed to send OTP to {user_email}")  # Debug print statement
            return jsonify({"error": "Failed to send OTP"}), 500
        
class VerifyOTP(Resource):
    def post(self):
        data = request.get_json()
        email = data.get('email')
        token_from_request = data.get('token')

        if not email or not token_from_request:
            print("Email and token are required")  # Debug print statement
            return jsonify({"error": "Email and token are required"}), 400

        user = User.query.filter_by(email=email).first()

        if user:
            totp = pyotp.TOTP(user.otp_secret, interval=200)

            # Print for debugging
            print(f"Token from request: {token_from_request}")
            print(f"User token secret: {user.otp_secret}")
            print(f"Current OTP: {totp.now()}")

            # Verify the token
            is_valid = totp.verify(token_from_request, valid_window=1)
            print(f"Token Verification Result: {is_valid}")

            if is_valid and user.otp_expiration > datetime.utcnow():
                user.otp_verified = True
                user.otp = None
                user.otp_expiration = None
                db.session.commit()
                print("Token verified successfully, user is now verified")  # Debug print statement
                return jsonify({"message": "Token verified successfully, user is now verified"}), 200
            else:
                print("Invalid or expired token")  # Debug print statement
                return jsonify({"error": "Invalid or expired token"}), 400
        else:
            print("User not found")  # Debug print statement
            return jsonify({"error": "User not found"}), 404

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

    
class EventsList(Resource):
    def get(self):
        print("Fetching all events")  # Debug
        events = Event.query.all()
        event_list = []

        for event in events:
            tickets = Ticket.query.filter_by(event_id=event.id).all()
            event_list.append({
                'id': event.id,
                'title': event.title,
                'description': event.description,
                'location': event.location,
                'start_time': event.start_time,
                'end_time': event.end_time,
                'total_tickets': event.total_tickets,
                'remaining_tickets': event.remaining_tickets,
                'tickets': [{'ticket_type': t.ticket_type, 'price': t.price, 'quantity': t.quantity, 'status': t.status} for t in tickets],
                'image_url': event.image_url
            })

        print(f"Event list: {event_list}")  # Debug
        return jsonify(event_list)

    @jwt_required()
    def post(self):
        print("Received POST request to create an event")  # Debug
        current_user = get_jwt_identity()
        print(f"Current user: {current_user}")  # Debug

        current_user_role = current_user['role']
        current_user_id = current_user['user_id']

        title = request.form.get('title')
        description = request.form.get('description')
        location = request.form.get('location')
        start_time = request.form.get('start_time')
        end_time = request.form.get('end_time')
        total_tickets = request.form.get('total_tickets')
        remaining_tickets = request.form.get('remaining_tickets')
        image_url = request.form.get('image_url')

        print(f"Received data: title={title}, description={description}, location={location}, start_time={start_time}, end_time={end_time}, total_tickets={total_tickets}, remaining_tickets={remaining_tickets}, image_url={image_url}")  # Debug

        if not title or not description or not location or not start_time or not end_time or not total_tickets or not remaining_tickets or not image_url:
            return {'message': 'All fields are required'}, 400

        if current_user_role not in ['admin', 'event_organizer']:
            return {'message': 'Unauthorized. Only admins or event organizers can create events.'}, 403

        try:
            event = Event(
                title=title,
                description=description,
                location=location,
                start_time=datetime.fromisoformat(start_time),
                end_time=datetime.fromisoformat(end_time),
                total_tickets=int(total_tickets),
                remaining_tickets=int(remaining_tickets),
                image_url=image_url,
                organizer_id=current_user_id if current_user_role == 'event_organizer' else None
            )
            db.session.add(event)
            db.session.commit()
            print("Event created successfully")  
            return {'message': 'Event created successfully'}, 201
        except Exception as e:
            print(f"Error occurred during event creation: {e}")  
            return {'message': 'Internal server error'}, 500

    @jwt_required()
    def delete(self):
        print("Received DELETE request to delete an event")  
        current_user = get_jwt_identity()
        print(f"Current user: {current_user}")  

        current_user_role = current_user['role']

        if current_user_role != 'admin':
            return {'message': 'Unauthorized. Only admins can delete events.'}, 403

        event_id = request.form.get('event_id')
        print(f"Event ID to delete: {event_id}")  

        if not event_id:
            return {'message': 'Event ID is required'}, 400

        event = Event.query.get(event_id)

        if not event:
            return {'message': 'Event not found'}, 404

        try:
            db.session.delete(event)
            db.session.commit()
            print("Event deleted successfully") 
            return {'message': 'Event deleted successfully'}, 200
        except Exception as e:
            print(f"Error occurred during event deletion: {e}")  
            return {'message': 'Internal server error'}, 500
        
class EventById(Resource):
    def get(self, event_id):
        # Fetch the event by ID
        event = Event.query.get(event_id)
        
        if not event:
            return {'message': 'Event not found'}, 404

        # Fetch related tickets
        tickets = Ticket.query.filter_by(event_id=event.id).all()
        
        # Prepare the event details
        event_details = {
            'id': event.id,
            'title': event.title,
            'description': event.description,
            'location': event.location,
            'start_time': event.start_time,
            'end_time': event.end_time,
            'total_tickets': event.total_tickets,
            'remaining_tickets': event.remaining_tickets,
            'tickets': [{'ticket_type': t.ticket_type, 'price': t.price, 'quantity': t.quantity, 'status': t.status} for t in tickets],
            'image_url': event.image_url 
        }
        return(event_details)

class OrganizerDashboard(Resource):
    @jwt_required()
    def post(self):
        user_id = get_jwt_identity()['user_id']
        user = User.query.get(user_id)

        if not user:
            return {'message': 'User not found'}, 404

        if user.role != 'event_organizer':
            return {'message': 'Access denied'}, 403

        # Parse and validate form data
        try:
            title = request.form['title']
            description = request.form['description']
            location = request.form['location']
            start_time = datetime.strptime(request.form['start_time'], '%Y-%m-%dT%H:%M:%S')
            end_time = datetime.strptime(request.form['end_time'], '%Y-%m-%dT%H:%M:%S')
            total_tickets = int(request.form['total_tickets'])
            remaining_tickets = int(request.form['remaining_tickets'])
            image_url = request.form['image_url']
        except (KeyError, ValueError, TypeError):
            return {'message': 'Invalid input data'}, 400

        new_event = Event(
            title=title,
            description=description,
            location=location,
            start_time=start_time,
            end_time=end_time,
            total_tickets=total_tickets,
            remaining_tickets=remaining_tickets,
            image_url=image_url,
            organizer_id=user.id
        )

        db.session.add(new_event)
        db.session.commit()

        return {'id': new_event.id, 'message': 'Event created successfully'}, 201

    @jwt_required()
    def put(self):
        user_id = get_jwt_identity()['user_id']
        user = User.query.get(user_id)

        if not user:
            return {'message': 'User not found'}, 404

        if user.role != 'event_organizer':
            return {'message': 'Access denied'}, 403

        event_id = request.form.get('event_id')
        event = Event.query.get(event_id)

        if not event:
            return {'message': 'Event not found'}, 404

        if event.organizer_id != user.id:
            return {'message': 'Access denied'}, 403

        # Update event with provided data
        try:
            event.title = request.form.get('title', event.title)
            event.description = request.form.get('description', event.description)
            event.location = request.form.get('location', event.location)
            if 'start_time' in request.form:
                event.start_time = datetime.strptime(request.form['start_time'], '%Y-%m-%dT%H:%M:%S')
            if 'end_time' in request.form:
                event.end_time = datetime.strptime(request.form['end_time'], '%Y-%m-%dT%H:%M:%S')
            event.total_tickets = int(request.form.get('total_tickets', event.total_tickets))
            event.remaining_tickets = int(request.form.get('remaining_tickets', event.remaining_tickets))
            event.image_url = request.form.get('image_url', event.image_url)
        except (ValueError, TypeError):
            return {'message': 'Invalid input data'}, 400

        db.session.commit()

        return {'message': 'Event updated successfully'}, 200

    @jwt_required()
    def patch(self):
        user_id = get_jwt_identity()['user_id']
        user = User.query.get(user_id)

        if not user:
            return {'message': 'User not found'}, 404

        if user.role != 'event_organizer':
            return {'message': 'Access denied'}, 403

        event_id = request.form.get('event_id')
        event = Event.query.get(event_id)

        if not event:
            return {'message': 'Event not found'}, 404

        if event.organizer_id != user.id:
            return {'message': 'Access denied'}, 403

        # Update event with provided data
        try:
            if 'title' in request.form:
                event.title = request.form['title']
            if 'description' in request.form:
                event.description = request.form['description']
            if 'location' in request.form:
                event.location = request.form['location']
            if 'start_time' in request.form:
                event.start_time = datetime.strptime(request.form['start_time'], '%Y-%m-%dT%H:%M:%S')
            if 'end_time' in request.form:
                event.end_time = datetime.strptime(request.form['end_time'], '%Y-%m-%dT%H:%M:%S')
            if 'total_tickets' in request.form:
                event.total_tickets = int(request.form['total_tickets'])
            if 'remaining_tickets' in request.form:
                event.remaining_tickets = int(request.form['remaining_tickets'])
            if 'image_url' in request.form:
                event.image_url = request.form['image_url']
        except (ValueError, TypeError):
            return {'message': 'Invalid input data'}, 400

        db.session.commit()

        return {'message': 'Event updated successfully'}, 200

    @jwt_required()
    def delete(self):
        user_id = get_jwt_identity()['user_id']
        user = User.query.get(user_id)

        if not user:
            return {'message': 'User not found'}, 404

        if user.role != 'event_organizer':
            return {'message': 'Access denied'}, 403

        event_id = request.form.get('event_id')
        event = Event.query.get(event_id)

        if not event:
            return {'message': 'Event not found'}, 404

        if event.organizer_id != user.id:
            return {'message': 'Access denied'}, 403

        db.session.delete(event)
        db.session.commit()

        return {'message': 'Event deleted successfully'}, 200
# Handle logout operation
revoked_tokens = set() 

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    token = RevokedToken.query.filter_by(jti=jti).first()
    return token is not None

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
    return jsonify(response), 500

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
            category = Category.query.get(category_id)
            if category:
                return category.to_dict(), 200
            return {'error': 'Category not found'}, 404
        
        categories = Category.query.all()
        return [category.to_dict() for category in categories], 200
    
class TicketResource(Resource):
    def get(self, ticket_id=None):
        if ticket_id:
            ticket = Ticket.query.get(ticket_id)
            if ticket:
                return {
                    'id': ticket.id,
                    'event_id': ticket.event_id,
                    'user_id': ticket.user_id,
                    'ticket_type': ticket.ticket_type,
                    'price': float(ticket.price),
                    'quantity': ticket.quantity,
                    'status': ticket.status
                }, 200
            return {'error': 'Ticket not found'}, 404
        
        # List all tickets
        tickets = Ticket.query.all()
        return [
            {
                'id': ticket.id,
                'event_id': ticket.event_id,
                'user_id': ticket.user_id,
                'ticket_type': ticket.ticket_type,
                'price': float(ticket.price),
                'quantity': ticket.quantity,
                'status': ticket.status
            }
            for ticket in tickets
        ], 200

    @jwt_required()
    def post(self):
        user_id = get_jwt_identity()['user_id']
        if not user_id:
            return {'message': 'User not found'}, 404

        event_id = request.form.get('event_id')
        ticket_type = request.form.get('ticket_type')
        price = request.form.get('price')
        quantity = request.form.get('quantity')
        status = request.form.get('status')

        if not event_id or not ticket_type or not price or not quantity or not status:
            return {'message': 'All fields are required'}, 400

        new_ticket = Ticket(
            event_id=event_id,
            user_id=user_id,
            ticket_type=ticket_type,
            price=price,
            quantity=quantity,
            status=status
        )

        db.session.add(new_ticket)
        db.session.commit()

        return {'id': new_ticket.id, 'message': 'Ticket created successfully'}, 201

    @jwt_required()
    def put(self, ticket_id):
        ticket = Ticket.query.get(ticket_id)
        if not ticket:
            return {'message': 'Ticket not found'}, 404

        user_id = get_jwt_identity()['user_id']
        if ticket.user_id != user_id:
            return {'message': 'Access denied'}, 403

        ticket.ticket_type = request.form.get('ticket_type', ticket.ticket_type)
        ticket.price = request.form.get('price', ticket.price)
        ticket.quantity = request.form.get('quantity', ticket.quantity)
        ticket.status = request.form.get('status', ticket.status)

        db.session.commit()

        return {'message': 'Ticket updated successfully'}, 200

    @jwt_required()
    def delete(self, ticket_id):
        ticket = Ticket.query.get(ticket_id)
        if not ticket:
            return {'message': 'Ticket not found'}, 404

        user_id = get_jwt_identity()['user_id']
        if ticket.user_id != user_id:
            return {'message': 'Access denied'}, 403

        db.session.delete(ticket)
        db.session.commit()

        return {'message': 'Ticket deleted successfully'}, 200
    
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
    def get(self):
        claims = get_jwt_identity()
        if claims['role'] != 'admin':
            return {'message': 'Access denied'}, 403
        
        users = User.query.all()
        events = Event.query.all()
        
        return {
            'users': [user.to_dict() for user in users],
            'events': [event.to_dict() for event in events]
        }, 200

    @jwt_required()
    def post(self):
        claims = get_jwt_identity()
        if claims['role'] != 'admin':
            return {'message': 'Access denied'}, 403
        
        username = request.form.get('username')
        email = request.form.get('email')
        role = request.form.get('role')
        password = request.form.get('password')  # Ensure to hash this password before saving

        if not username or not email or not role or not password:
            return {'message': 'All fields are required'}, 400

        if role not in ['admin', 'event_organizer', 'user']:
            return {'message': 'Invalid role'}, 400

        try:
            user = User(username=username, email=email, role=role, password=password)
            db.session.add(user)
            db.session.commit()
            return {'message': 'User created successfully'}, 201
        except Exception as e:
            return {'message': 'Internal server error'}, 500

    @jwt_required()
    def delete(self, user_id):
        claims = get_jwt_identity()
        if claims['role'] != 'admin':
            return {'message': 'Access denied'}, 403

        user = User.query.get(user_id)
        if not user:
            return {'message': 'User not found'}, 404
        
        try:
            db.session.delete(user)
            db.session.commit()
            return {'message': 'User deleted successfully'}, 200
        except Exception as e:
            return {'message': 'Internal server error'}, 500

    @jwt_required()
    def put(self, user_id):
        claims = get_jwt_identity()
        if claims['role'] != 'admin':
            return {'message': 'Access denied'}, 403

        user = User.query.get(user_id)
        if not user:
            return {'message': 'User not found'}, 404

        username = request.form.get('username', user.username)
        email = request.form.get('email', user.email)
        role = request.form.get('role', user.role)

        try:
            user.username = username
            user.email = email
            user.role = role
            db.session.commit()
            return {'message': 'User updated successfully'}, 200
        except Exception as e:
            return {'message': 'Internal server error'}, 500

    @jwt_required()
    def patch(self, event_id):
        claims = get_jwt_identity()
        if claims['role'] != 'admin':
            return {'message': 'Access denied'}, 403

        event = Event.query.get(event_id)
        if not event:
            return {'message': 'Event not found'}, 404

        title = request.form.get('title', event.title)
        description = request.form.get('description', event.description)
        location = request.form.get('location', event.location)
        start_time = request.form.get('start_time', event.start_time)
        end_time = request.form.get('end_time', event.end_time)
        total_tickets = request.form.get('total_tickets', event.total_tickets)
        remaining_tickets = request.form.get('remaining_tickets', event.remaining_tickets)
        image_url = request.form.get('image_url', event.image_url)

        try:
            event.title = title
            event.description = description
            event.location = location
            event.start_time = datetime.fromisoformat(start_time) if start_time else event.start_time
            event.end_time = datetime.fromisoformat(end_time) if end_time else event.end_time
            event.total_tickets = int(total_tickets) if total_tickets else event.total_tickets
            event.remaining_tickets = int(remaining_tickets) if remaining_tickets else event.remaining_tickets
            event.image_url = image_url
            db.session.commit()
            return {'message': 'Event updated successfully'}, 200
        except Exception as e:
            return {'message': 'Internal server error'}, 500

    @jwt_required()
    def delete_event(self, event_id):
        claims = get_jwt_identity()
        if claims['role'] != 'admin':
            return {'message': 'Access denied'}, 403

        event = Event.query.get(event_id)
        if not event:
            return {'message': 'Event not found'}, 404

        try:
            db.session.delete(event)
            db.session.commit()
            return {'message': 'Event deleted successfully'}, 200
        except Exception as e:
            return {'message': 'Internal server error'}, 500
        
    
@jwt.user_identity_loader
def user_identity_lookup(user):
    return {'user_id': user['user_id'], 'role': user['role']}
# AP end points

api.add_resource(UserResource, '/users', '/users/<int:user_id>')
api.add_resource(Login, '/login')
api.add_resource(CheckSession, '/session')
api.add_resource(Logout, '/logout')
api.add_resource(PublicRegister, '/register')
api.add_resource(AdminRegister, '/register/admin')
api.add_resource( OrganizerDashboard, '/organizer-dashboard')
api.add_resource(CategoryResource, '/categories', '/categories/<int:category_id>')
api.add_resource(TicketResource, '/tickets', '/tickets/<int:ticket_id>')
api.add_resource(UserRole, '/user-role')
api.add_resource(BookTicket, '/book-ticket')
api.add_resource(AdminDashboard, '/admin-dashboard', '/admin-dashboard/<int:user_id>', '/admin-dashboard/events/<int:event_id>')
api.add_resource(EventsList, '/events')
api.add_resource(EventById, '/events/<int:event_id>')
api.add_resource(GenerateOTP, '/request-otp')
api.add_resource(VerifyOTP, '/verify-otp')

# api.add_resource(Notifications, '/notifications')
if __name__ == '__main__':
    app.run(port=5555, debug=True)