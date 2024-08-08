from flask import Flask, request, jsonify, make_response, session, url_for,  render_template, redirect, current_app
from flask_migrate import Migrate
from flask_cors import CORS
from flask_restful import Api, Resource
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from flask_jwt_extended.exceptions import RevokedTokenError
from werkzeug.exceptions import NotFound
from datetime import timedelta, datetime
from jwt.exceptions import DecodeError
from utils import generate_otp, send_otp_to_email
from datetime import datetime, timedelta
import random, pyotp
from flask_otp import OTP

otp = OTP()
otp.init_app(current_app)

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*", "methods": ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]}})

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config["JWT_SECRET_KEY"] = "fsbdgfnhgvjnvhmvh" + str(random.randint(1, 1000000000000))
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=1)
app.config["SECRET_KEY"] = "JKSRVHJVFBSRDFV" + str(random.randint(1, 1000000000000))
app.json.compact = False
api = Api(app)

from models import db, User, Event, Category, Payment, Ticket, RevokedToken
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

        # Generate and send OTP
        otp_code = generate_otp()
        send_otp_to_email(email, otp_code)

        # Temporarily store the OTP and user details in session
        session['otp'] = otp_code
        session['user_details'] = {'username': username, 'password': password, 'role': role, 'email': email}
        
        return {'message': 'OTP sent to email. Please verify.'}, 200
    
class VerifyOTP(Resource):
    def post(self):
        entered_otp = request.form.get('otp')

        if not entered_otp:
            return {'message': 'OTP is required'}, 400

        # Retrieve stored OTP and user details
        stored_otp = session.get('otp')
        user_details = session.get('user_details')

        if not stored_otp or stored_otp != entered_otp:
            return {'message': 'Invalid OTP'}, 400

        try:
            # Complete user registration
            new_user = User(username=user_details['username'], 
                            email=user_details['email'], 
                            role=user_details['role'])
            new_user.set_password(user_details['password'])
            db.session.add(new_user)
            db.session.commit()

            # Clean up session
            session.pop('otp', None)
            session.pop('user_details', None)

            return {'message': 'User registered and Logged in successfully'}, 201
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
                'image_url': event.image_url
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

class CategoryListResource(Resource):
    def get(self):
        # Fetch all categories
        categories = Category.query.all()
        return [category.to_dict() for category in categories], 200

    def post(self):
        # Handle form data for creating a new category
        data = request.form
        name = data.get('name')

        if not name:
            return {'message': 'Name is required'}, 400

        new_category = Category(name=name)
        db.session.add(new_category)
        db.session.commit()
        return new_category.to_dict(), 201

class CategoryResource(Resource):
    def get(self, category_id):
        # Fetch a single category by ID
        category = Category.query.get_or_404(category_id)
        return category.to_dict(), 200

    def put(self, category_id):
        # Handle form data for updating an existing category
        category = Category.query.get_or_404(category_id)
        data = request.form
        name = data.get('name')

        if not name:
            return {'message': 'Name is required'}, 400

        category.name = name
        db.session.commit()
        return category.to_dict(), 200

    def delete(self, category_id):
        # Handle deletion of a category
        category = Category.query.get_or_404(category_id)
        db.session.delete(category)
        db.session.commit()
        return '', 204
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
    
@jwt.user_identity_loader
def user_identity_lookup(user):
    return {'user_id': user['user_id'], 'role': user['role']}


def get_transactions():
    # queries the Payment model to fetch all transactions
    transactions = Payment.query.all()

    transaction_list = []
    for payment in transactions:
        # fetches the associated ticket
        ticket = Ticket.query.get(payment.ticket_id)
        user = User.query.get(ticket.user_id)
        event = Event.query.get(ticket.event_id)
        
        # appending transaction data to the list
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

# API end points
api.add_resource(CategoryListResource, '/categories')
api.add_resource(CategoryResource, '/categories/<int:category_id>')
api.add_resource(UserResource, '/users', '/users/<int:user_id>')
api.add_resource(Login, '/login')
api.add_resource(CheckSession, '/session')
api.add_resource(Logout, '/logout')
api.add_resource(PublicRegister, '/register')
api.add_resource(AdminRegister, '/register/admin')
api.add_resource( OrganizerDashboard, '/organizer-dashboard')
api.add_resource(TicketResource, '/tickets', '/tickets/<int:ticket_id>')
api.add_resource(UserRole, '/user-role')
api.add_resource(BookTicket, '/book-ticket')
api.add_resource(AdminDashboard, '/admin-dashboard', '/admin-dashboard/<int:user_id>', '/admin-dashboard/events/<int:event_id>')
api.add_resource(EventsResource, '/events','/events/<int:event_id>')
api.add_resource(VerifyOTP, '/verify-otp')

if __name__ == '__main__':
    app.run(port=5555, debug=True)