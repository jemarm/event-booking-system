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

print("Configured Flask app...")

api = Api(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

print("Initialized Flask extensions...")


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)


print("Defined User model...")


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


class Profile(Resource):
    @jwt_required()
    def get(self):
        current_user = get_jwt_identity()
        return jsonify({'user': current_user})


print("Defined Profile resource...")

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
