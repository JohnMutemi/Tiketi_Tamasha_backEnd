
import random
import secrets
from flask import Flask, request, jsonify, make_response, session, url_for,  render_template, redirect
from flask_migrate import Migrate
from flask_cors import CORS
from flask_restful import Api, Resource
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from flask_jwt_extended.exceptions import RevokedTokenError
from werkzeug.exceptions import NotFound
from datetime import timedelta, datetime
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config["JWT_SECRET_KEY"] = "fsbdgfnhgvjnvhmvh" + str(random.randint(1, 1000000000000))
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=1)
app.config["SECRET_KEY"] = "JKSRVHJVFBSRDFV" + str(random.randint(1, 1000000000000))
app.json.compact = False
api = Api(app)

from models import db, User, Event, Category, EventCategory, Payment, Ticket, RevokedToken, Customer
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
    def get(self, user_id=None):
        if user_id:
            user = User.query.get(user_id)
            if user:
                return user.to_dict(), 200
            return {'error': 'User not found'}, 404
        users = User.query.all()
        return [user.to_dict() for user in users], 200
     
    def delete(self, user_id):
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
    def put(self, user_id):
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
            if role not in ['event_organizer', 'customer']:
                return {'message': 'Invalid role. Choose either "event_organizer" or "customer"'}, 400
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
            session['user_id'] = user.id

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
                'role':user.role,
                'user_id': user.id
            }, 200
        else:
            return {"error": "Invalid username or password"}, 401
class Register(Resource):
    def post(self):
        print(f"Received data: {request.form}")

        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        role = request.form.get('role')

        print(f"Extracted - Username: {username}, Email: {email}, Role: {role}, Password: {password}")

        if not username or not password or not email or not role:
            print("Missing required fields.")
            return {'message': 'username, password, role, and email are required'}, 400
        if role not in ['event_organizer', 'customer']:
            print('Invalid role provided')
            return {'message': 'Invalid role. Choose either "event_organizer" or "customer"'}, 400
        
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            print(f"User already exists: {existing_user.username}")
            return {'message': 'User already exists'}, 400

        try:
            new_user = User(username=username, email=email, role=role)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            print(f"User created: {new_user.username}")

            success_message = {'message': 'User registered successfully'}
            response = make_response(success_message)
            response.status_code = 201

            return response
        except Exception as e:
            print(f"Error occurred during registration: {e}")
            return {'message': 'Internal server error'}, 500

class EventsList(Resource):
    def get(self):
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
                'image_url': event.image_url  # Include image_url here
            })

        return jsonify(event_list)

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
            'image_url': event.image_url  # Include image_url here
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

# AP end points

api.add_resource(UserResource, '/users', '/users/<int:user_id>')
api.add_resource(Login, '/login')
api.add_resource(CheckSession, '/session')
api.add_resource(Logout, '/logout')
api.add_resource(Register, '/register')
api.add_resource(EventsList, '/events')
api.add_resource(EventById, '/events/<int:event_id>')
api.add_resource( OrganizerDashboard, '/organizer-dashboard')
api.add_resource(CategoryResource, '/categories', '/categories/<int:category_id>')
api.add_resource(TicketResource, '/tickets', '/tickets/<int:ticket_id>')
api.add_resource(UserRole, '/user-role')
api.add_resource(BookTicket, '/book-ticket')
if __name__ == '__main__':
    app.run(port=5555, debug=True)