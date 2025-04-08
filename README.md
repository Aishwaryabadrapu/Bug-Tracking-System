# Bug-Tracking-System
// Backend (Flask + PostgreSQL)
# app.py
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://username:password@localhost/bugtracker'
app.config['SECRET_KEY'] = 'secretkey'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), nullable=False)

class Bug(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    description = db.Column(db.Text)
    status = db.Column(db.String(50), default='Open')
    priority = db.Column(db.String(50))
    assignee_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    reporter_id = db.Column(db.Integer, db.ForeignKey('user.id'))

# Routes
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    hashed_pw = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], password=hashed_pw, role=data['role'])
    db.session.add(new_user)
    db.session.commit()
    return jsonify(message="User registered"), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        token = create_access_token(identity={'id': user.id, 'role': user.role})
        return jsonify(token=token)
    return jsonify(message="Invalid credentials"), 401

@app.route('/bugs', methods=['GET', 'POST'])
@jwt_required()
def bugs():
    if request.method == 'POST':
        data = request.json
        bug = Bug(title=data['title'], description=data['description'], priority=data['priority'],
                  assignee_id=data['assignee_id'], reporter_id=get_jwt_identity()['id'])
        db.session.add(bug)
        db.session.commit()
        return jsonify(message="Bug reported"), 201
    else:
        bug_list = Bug.query.all()
        return jsonify(bugs=[{'id': b.id, 'title': b.title, 'status': b.status} for b in bug_list])

if __name__ == '__main__':
    app.run(debug=True)

// Frontend (React + Axios)
// App.jsx
import React, { useState, useEffect } from 'react';
import axios from 'axios';

function App() {
  const [bugs, setBugs] = useState([]);
  const [token, setToken] = useState(localStorage.getItem('token'));

  useEffect(() => {
    if (token) {
      axios.get('http://localhost:5000/bugs', {
        headers: { Authorization: `Bearer ${token}` }
      }).then(res => setBugs(res.data.bugs));
    }
  }, [token]);

  const login = async () => {
    const res = await axios.post('http://localhost:5000/login', { username: 'admin', password: 'admin' });
    localStorage.setItem('token', res.data.token);
    setToken(res.data.token);
  };

  return (
    <div className="p-4">
      {!token ? <button onClick={login} className="bg-blue-500 text-white px-4 py-2 rounded">Login</button>
              : <div>
                  <h1 className="text-xl font-bold">Bug Tracker</h1>
                  <ul>
                    {bugs.map(bug => (
                      <li key={bug.id}>{bug.title} - {bug.status}</li>
                    ))}
                  </ul>
                </div>}
    </div>
  );
}

export default App;
