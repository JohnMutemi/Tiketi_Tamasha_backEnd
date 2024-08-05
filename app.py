
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
from models import Customer

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
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
                'tickets': [{'ticket_type': t.ticket_type, 'price': t.price, 'quantity': t.quantity, 'status': t.status} for t in tickets]
            })

        return jsonify(event_list)
class OrganizerDashboard(Resource):
    @jwt_required()
    def get(self):
        user_id = get_jwt_identity()['user_id']
        user = User.query.get(user_id)

        if not user:
            return {'message': 'User not found'}, 404

        if user.role != 'event_organizer':
            return {'message': 'Access denied'}, 403
        
    

        events = Event.query.filter_by(organizer_id=user.id).all()
        dashboard_data = []

        for event in events:
            tickets = Ticket.query.filter_by(event_id=event.id).all()
            total_tickets = sum(ticket.quantity for ticket in tickets)
            remaining_tickets = event.remaining_tickets

            dashboard_data.append({
                'event_id': event.id,
                'event_title': event.title,
                'total_tickets': total_tickets,
                'remaining_tickets': remaining_tickets,
                'attendees': [{'username': User.query.get(t.user_id).username, 'ticket_type': t.ticket_type, 'quantity': t.quantity} for t in tickets]
            })

        return jsonify(dashboard_data)
    
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


# @app.before_first_request
# def create_tables():
#     db.create_all()

@app.route('/')
def customer():
    customers = Customer.query.all()
    return render_template('index.html', customers=customers)

@app.route('/add_customer', methods=['GET', 'POST'])
def add_customer():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        
        new_customer = Customer(name=name, email=email, phone=phone)
        try:
            # Add and commit the new customer to the database
            db.session.add(new_customer)
            db.session.commit()
            return jsonify({"message": "Customer added successfully"}), 201
        except Exception as e:
            db.session.rollback()
            return jsonify({"error": str(e), "message": "An unexpected error occurred."}), 500

    return render_template('add_customer.html')

# Route to list all customers
@app.route('/customers')
def list_customers():
    customers = Customer.query.all()
    customer_list = [{"id": c.id, "name": c.name, "email": c.email, "phone": c.phone} for c in customers]
    return jsonify(customer_list)

# API endpoints

api.add_resource(UserResource, '/users', '/users/<int:user_id>')
api.add_resource(Login, '/login')
api.add_resource(CheckSession, '/session')
api.add_resource(Logout, '/logout')
api.add_resource(Register, '/register')
api.add_resource(EventsList, '/events')
api.add_resource( OrganizerDashboard, '/organizer/dashboard')

if __name__ == '__main__':
    app.run(port=5555, debug=True)