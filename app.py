
import random
from flask import Flask, request, jsonify, make_response, session, url_for,  render_template
from flask_migrate import Migrate
from flask_cors import CORS
from flask_restful import Api, Resource
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
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

from models import db, User, Event, Category, EventCategory, Payment, Ticket
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
class Login(Resource):
    def post(self):
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            access_token = create_access_token(identity={'user_id': user.id, 'role':user.role})
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
        # Print the incoming data to check if the request data is being received
        print(f"Received data: {request.form}")

        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        role=request.form.get('role')

        # Print the extracted values to ensure they are correctly extracted
        print(f"Extracted - Username: {username}, Email: {email}, Role: {role}, Password: {password}")

        if not username or not password or not email or not role:
            print("Missing required fields.")
            return {'message': 'username, password, role, and email are required'}, 400
        if role not in ['event_organizer', 'customer']:
            print('Invalid role provided')
            return {'message': 'Invalid role. Choose either "event_organizer"  or "customer"'}
        # Check if the user already exist
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            print(f"User already exists: {existing_user.username}")
            return {'message': 'User already exists'}, 400

        try:
            # Attempt to create a new user
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

class Logout(Resource):
    def post(self):
        session.pop('user_id', None)
        return jsonify({"message": "Logout successful"})
# API endpoints

api.add_resource(UserResource, '/users', '/users/<int:user_id>')
api.add_resource(Login, '/login')
api.add_resource(Logout, '/logout')
api.add_resource(Register, '/register')
if __name__ == '__main__':
    app.run(port=5555, debug=True)