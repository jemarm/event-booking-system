from datetime import datetime
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Api, Resource
from flask import Flask, request, jsonify
print("Starting Flask server...")


print("Imported all modules...")

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'


api = Api(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Defines a model to store user information


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)


print("Defined User model...")

# Defines a resource to handle POST requests for user registration


class Register(Resource):
    def post(self):
        data = request.get_json()
        hashed_password = bcrypt.generate_password_hash(
            data['password']).decode('utf-8')
        new_user = User(username=data['username'],
                        email=data['email'], password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User registered successfully'})


print("Defined Register resource...")

# Defines a resource to handle POST request for user login


class Login(Resource):
    def post(self):
        data = request.get_json()
        user = User.query.filter_by(email=data['email']).first()
        if user and bcrypt.check_password_hash(user.password, data['password']):
            access_token = create_access_token(
                identity={'username': user.username, 'email': user.email})
            return jsonify({'token': access_token})
        return jsonify({'message': 'Invalid credentials'}), 401


print("Defined Login resource...")

# Defines a reouse to handle GET requests for retrieving the authenticated users profile


class Profile(Resource):
    @jwt_required()
    def get(self):
        current_user = get_jwt_identity
        return jsonify({'user': current_user})


print("Defined Profile resource...")

# Defines a resoruce to handle POST requests for creating events and GET request for retrieving specific event


class EventResource(Resource):
    @jwt_required()
    def post(self):
        current_user = get_jwt_identity()
        data = request.get_json()
        new_event = Event(
            title=data['title'],
            description=data['description'],
            data=datetime.strptime(data['date'], '%Y-%m-%d %H:%M:%S'),
            location=data['location'],
            organizer_id=current_user['id']
        )
        db.session.add(new_event)
        db.session.commit()
        return jsonify({'message': 'Event created successfully'})

    @jwt_required
    def get(self, event_id):
        event = Event.query.get_or_404(event_id)
        return jsonify({
            'title': event.title,
            'description': event.description,
            'date': event.date.strftime('%Y-%m-%d %H:%M:%S'),
            'location': event.location,
            'organizer_id': event.organizer_id
        })


print("Defined EventResource resource...")

# Defines a resource to handle GET requets for retrieving a list of all events


class EventListResource(Resource):
    @jwt_required()
    def get(self):
        events = Event.query.all()
        event_list = [{
            'id': event.id,
            'title': event.title,
            'description': event.description,
            'date': event.date.strftime('%Y-%m-%d %H:%M:%S'),
            'location': event.location,
            'organizer_id': event.organizer_id
        } for event in events]
        return jsonify(event_list)


# Defines a model to store event information
class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=True)
    date = db.Column(db.DateTime, nullable=False)
    location = db.Column(db.String(120), nullable=False)
    organizer_id = db.Column(
        db.Integer, db.ForeignKey('user.id'), nullable=False)
    organizer = db.relationship(
        'User', backref=db.backref('events', lazy=True))


# Add API resources
api.add_resource(Register, '/register')
api.add_resource(Login, '/login')
api.add_resource(Profile, '/profile')

print("Added API resources...")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("Created database tables...")
    print("Flask server is running...")
    app.run(debug=True)
