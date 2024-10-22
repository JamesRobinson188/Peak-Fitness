from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
import os
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date
import openai
openai.api_key = 'OPENAI_API_KEY'

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.root_path, 'database/users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'gy543gy9gh254uy932gy7543ghu896534jyu86954hgy85473gty754r3ghy785h8uy9y43hu89'


db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    pushups = db.Column(db.Integer, nullable=False, default=0)
    pullups = db.Column(db.Integer, nullable=False, default=0)
    anonymous_mode = db.Column(db.Boolean, default=False)
    awards = db.Column(db.Integer, nullable=False, default=0)
    points = db.Column(db.Integer, nullable=False, default=0)
    age = db.Column(db.Integer, nullable=True, default=0)
    height = db.Column(db.Integer, nullable=True, default=0)
    weight = db.Column(db.Float, nullable=True, default=0)
    activity_level = db.Column(db.String(30), nullable=True, default="moderately_active")
    gender = db.Column(db.Boolean, default=True)
    goal = db.Column(db.Boolean, default=True)

    chats = db.relationship('Chat', backref='user', cascade='all, delete-orphan')
    exercises = db.relationship('Exercise', backref='user', cascade='all, delete-orphan')
    climbs = db.relationship('Climb', backref='user', cascade='all, delete-orphan')
    inbox = db.relationship('Inbox', backref='user', cascade='all, delete-orphan')
    calories = db.relationship('Calories', backref='user', cascade='all, delete-orphan')

    def update_points(self):
        self.points = self.pushups + self.pullups * 2
        for exercise in self.exercises:
            self.points += exercise.count
        for climb in self.climbs:
            self.points += climb.points


class Chat(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(500), nullable=False)


class Exercise(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    count = db.Column(db.Integer, nullable=False, default=0)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class Climb(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    grade = db.Column(db.String(10), nullable=False)
    points = db.Column(db.Integer, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class Inbox(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    type_of_message = db.Column(db.String(30), nullable=False, default="System")
    sender = db.Column(db.String(30), nullable=False, default="System")
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class Calories(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    calories = db.Column(db.Integer, nullable=False)
    description = db.Column(db.String(255), nullable=True)
    day = db.Column(db.Date, nullable=False, default=date.today)

@app.context_processor
def inject_user_exercises():
    if session.get("logged_in"):
        username = session.get("username")
        user = User.query.filter_by(username=username).first()
        if user:
            user_exercises = Exercise.query.filter_by(user_id=user.id).all()
            return dict(user_exercises=user_exercises)
    return dict(user_exercises=[])


@app.route('/')
def home():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    users = User.query.order_by(User.points.desc(), User.username).all()
    user_data = [{'username': (user.username if not user.anonymous_mode else "Anonymous"),
                  'pullups': user.pullups, 'pushups': user.pushups} for user in users]

    return render_template('index.html', users=user_data)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session["logged_in"] = True
            session["username"] = username
            return redirect(url_for("home"))
        else:
            error = "Invalid credentials. Please try again."

    return render_template("login.html", error=error)


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            error = "User already exists. Please choose a different one."
        else:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            session["logged_in"] = True
            session["username"] = username
            return redirect(url_for("home"))

    return render_template("register.html", error=error)



@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    return redirect(url_for("login"))


@app.route('/pushups', methods=['GET', 'POST'])
def pushups():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    username = session.get("username")
    user = User.query.filter_by(username=username).first()

    if not user:
        return redirect(url_for("login"))

    if request.method == 'POST':
        change = request.form.get("change")

        if change == "increase":
            user.pushups += 1
        elif change == "decrease" and user.pushups > 0:
            user.pushups -= 1
        elif change == "increase10":
            user.pushups += 10
        elif change == "decrease10" and user.pushups > 9:
            user.pushups -= 10

        db.session.commit()

    count = user.pushups

    return render_template('pushups.html', count=count, name=username)


@app.route('/pullups', methods=['GET', 'POST'])
def pullups():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    username = session.get("username")
    user = User.query.filter_by(username=username).first()

    if not user:
        return redirect(url_for("login"))

    if request.method == 'POST':
        change = request.form.get("change")

        if change == "increase":
            user.pullups += 1
        elif change == "decrease" and user.pullups > 0:
            user.pullups -= 1
        elif change == "increase10":
            user.pullups += 10
        elif change == "decrease10" and user.pullups > 9:
            user.pullups -= 10

        db.session.commit()

    count = user.pullups

    return render_template('pullups.html', count=count, name=username)


@app.route('/api/leaderboard')
def api_leaderboard():
    users = User.query.order_by(User.points.desc(), User.username).all()
    user_data = [{'username': (user.username if not user.anonymous_mode else "Anonymous"),
                  'pullups': user.pullups,
                  'pushups': user.pushups,
                  'awards': user.awards,
                  'points': user.points}
                  for user in users]

    return jsonify(user_data)


@app.route('/update_pushups', methods=['POST'])
def update_pushups():
    if not session.get("logged_in"):
        return jsonify({'error': 'Not logged in'}), 401

    username = session.get("username")
    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json()
    change = data.get('change')

    if change not in ['increase', 'decrease', 'increase10', 'decrease10']:
        return jsonify({'error': 'Invalid action'}), 400

    if change == "increase":
        user.pushups += 1
    elif change == "decrease" and user.pushups > 0:
        user.pushups -= 1
    elif change == "increase10":
        user.pushups += 10
    elif change == "decrease10" and user.pushups > 9:
        user.pushups -= 10

    user.update_points()
    db.session.commit()

    return jsonify({'count': user.pushups})


@app.route('/update_pullups', methods=['POST'])
def update_pullups():
    if not session.get("logged_in"):
        return jsonify({'error': 'Not logged in'}), 401

    username = session.get("username")
    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json()
    change = data.get('change')

    if change not in ['increase', 'decrease', 'increase10', 'decrease10']:
        return jsonify({'error': 'Invalid action'}), 400

    if change == "increase":
        user.pullups += 1
    elif change == "decrease" and user.pullups > 0:
        user.pullups -= 1
    elif change == "increase10":
        user.pullups += 10
    elif change == "decrease10" and user.pullups > 9:
        user.pullups -= 10

    user.update_points()
    db.session.commit()

    return jsonify({'count': user.pullups})


@app.route('/chat', methods=['GET', 'POST'])
def chat():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    if request.method == 'POST' and request.is_json:
        data = request.get_json()
        message = data.get("message", "")
        if message:
            user = User.query.filter_by(username=session.get("username")).first()
            if user:
                new_message = Chat(user_id=user.id, message=message)
                db.session.add(new_message)
                db.session.commit()

            total_chats = Chat.query.count()
            if total_chats > 30:
                oldest_message = Chat.query.order_by(Chat.id.asc()).first()
                db.session.delete(oldest_message)
                db.session.commit()


                return jsonify({'status': 'success', 'message': 'Message sent'})

        return jsonify({'status': 'error', 'message': 'Invalid message'})

    messages = Chat.query.join(User).order_by(Chat.id.asc()).all()
    return render_template('chat.html', messages=messages)


@app.route('/get_messages')
def get_messages():
    messages = Chat.query.join(User).order_by(Chat.id.asc()).all()
    messages_data = [{'username': message.user.username, 'message': message.message} for message in messages]
    return jsonify(messages_data)


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    username = session.get("username")
    user = User.query.filter_by(username=username).first()
    error = None

    if request.method == 'POST':
        new_username = request.form.get("new_username")
        new_password = request.form.get("new_password")
        anonymous_mode = request.form.get("anonymous_mode") == 'on'
        age = request.form.get("age")
        height = request.form.get("height")
        weight = request.form.get("weight")
        gender = request.form.get("gender")
        activity_level = request.form.get("activity_level")
        goal = request.form.get("goal")

        if new_username and new_username != username:
            existing_user = User.query.filter_by(username=new_username).first()
            if existing_user:
                error = "Username already exists. Please choose a different one."
            else:
                user.username = new_username
                session["username"] = new_username

        if new_password:
            user.password = generate_password_hash(new_password, method='pbkdf2:sha256')

        user.anonymous_mode = anonymous_mode

        if age is not None and age.strip() != '':
            user.age = age
        if height is not None and height.strip() != '':
            user.height = height
        if weight is not None and weight.strip() != '':
            user.weight = weight
        if gender:
            user.gender = gender == 'male'
        if activity_level:
            user.activity_level = activity_level
        if goal:
            user.goal = goal == 'bulk' 

        if not error:
            db.session.commit()

    return render_template('settings.html', user=user, error=error, current_gender=user.gender, current_activity_level=user.activity_level, current_goal=user.goal)


@app.route('/achievements')
def achievements():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    username = session.get("username")
    user = User.query.filter_by(username=username).first()

    if not user:
        return redirect(url_for("home"))

    total_points = user.points
    total_exercises = total_points
    trophy = None
    num_awards = 0

    if total_exercises >= 100000:
        trophy = "Diamond"
        num_awards = 5
    elif total_exercises >= 50000:
        trophy = "Platinum"
        num_awards = 4
    elif total_exercises >= 10000:
        trophy = "Gold"
        num_awards = 3
    elif total_exercises >= 5000:
        trophy = "Silver"
        num_awards = 2
    elif total_exercises >= 1000:
        trophy = "Bronze"
        num_awards = 1

    if num_awards > user.awards:
        message = f"Congratulations! You have reached {trophy} by earning {total_exercises} points!"
        new_message = Inbox(user_id=user.id, message=message, timestamp=datetime.utcnow())
        db.session.add(new_message)
        user.awards = num_awards
        db.session.commit()

    return render_template('achievements.html', username=username, total_exercises=total_exercises, trophy=trophy)


@app.route('/social', methods=['GET', 'POST'])
def social():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    if request.method == 'POST':
        search_query = request.form.get("search_query")
        users = User.query.filter(User.username.contains(search_query)).all()
        return render_template('social.html', users=users, search_query=search_query)

    return render_template('social.html')


@app.route('/search_users', methods=['POST'])
def search_users():
    if not session.get("logged_in"):
        return jsonify({'error': 'Not logged in'}), 401

    search_query = request.json.get('search_query')
    users = User.query.filter(User.username.contains(search_query)).all()
    user_data = [{
        'username': user.username,
        'pullups': user.pullups,
        'pushups': user.pushups,
        'total': user.pushups + user.pullups,
        'awards': user.awards,
        'exercises': [{'name': exercise.name, 'count': exercise.count} for exercise in user.exercises],
        'climbs': [{'name': climb.name, 'grade': climb.grade} for climb in user.climbs]
    } for user in users]
    return jsonify(user_data)


@app.route('/exercise', methods=['GET', 'POST'])
def exercise():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    username = session.get("username")
    user = User.query.filter_by(username=username).first()

    if request.method == 'POST':
        if 'exercise_name' in request.form:
            exercise_name = request.form.get("exercise_name")
            if exercise_name:
                new_exercise = Exercise(name=exercise_name, user_id=user.id)
                db.session.add(new_exercise)
                user.update_points()
                db.session.commit()

        elif 'delete_exercise_id' in request.form:
            exercise_id = request.form.get("delete_exercise_id")
            exercise_to_delete = Exercise.query.get(exercise_id)
            if exercise_to_delete and exercise_to_delete.user_id == user.id:
                db.session.delete(exercise_to_delete)
                user.update_points()
                db.session.commit()

    user_exercises = Exercise.query.filter_by(user_id=user.id).all()
    return render_template('exercise.html', exercises=user_exercises, user_exercises=user_exercises)


@app.route('/update_exercise/<int:exercise_id>', methods=['POST'])
def update_exercise(exercise_id):
    if not session.get("logged_in"):
        return jsonify({'error': 'Not logged in'}), 401

    exercise = Exercise.query.get(exercise_id)
    if not exercise or exercise.user.username != session.get("username"):
        return jsonify({'error': 'Exercise not found or access denied'}), 404

    data = request.get_json()
    change = data.get('change')

    if change not in ['increase', 'decrease', 'increase10', 'decrease10']:
        return jsonify({'error': 'Invalid action'}), 400

    if change == "increase":
        exercise.count += 1
    elif change == "decrease" and exercise.count > 0:
        exercise.count -= 1
    elif change == "increase10":
        exercise.count += 10
    elif change == "decrease10" and exercise.count > 9:
        exercise.count -= 10

    exercise.user.update_points()
    db.session.commit()

    return jsonify({'count': exercise.count})



@app.route('/delete_exercise/<int:exercise_id>', methods=['POST'])
def delete_exercise(exercise_id):
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    exercise = Exercise.query.get(exercise_id)
    if not exercise or exercise.user.username != session.get("username"):
        return redirect(url_for("exercise"))

    db.session.delete(exercise)
    db.session.commit()
    return redirect(url_for("exercise"))


@app.route('/exercise_tracker/<int:exercise_id>')
def exercise_tracker(exercise_id):
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    exercise = Exercise.query.get_or_404(exercise_id)
    return render_template('exercise_tracker.html', exercise=exercise)


@app.route('/climb', methods=['GET', 'POST'])
def climb():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    username = session.get("username")
    user = User.query.filter_by(username=username).first()

    if request.method == 'POST':
        climb_name = request.form.get("climb_name")
        grade = request.form.get("grade")
        lead_climb = 'extra_points' in request.form

        if lead_climb:
            climb_name += " (lead)"
        extra_points_claimed = 'extra_points' in request.form
        points = calculate_points_for_grade(grade)
        if extra_points_claimed:
            points += 20

        new_climb = Climb(name=climb_name, grade=grade, points=points, user_id=user.id)
        db.session.add(new_climb)
        user.update_points()
        db.session.commit()

    user_climbs = Climb.query.filter_by(user_id=user.id).all()
    return render_template('climb.html', climbs=user_climbs)


def calculate_points_for_grade(grade):
    bouldering_points = {
        'V0': 10, 'V1': 20, 'V2': 30, 'V3': 40, 'V4': 50, 'V5': 60,
        'V6': 70, 'V7': 80, 'V8': 90, 'V9': 100, 'V10': 110,
        'V11': 120, 'V12': 130, 'V13': 140, 'V14': 150, 'V15': 160,
        'V16': 170, 'V17': 180
    }

    climbing_points = {
        '4+': 10, '5': 20, '5+': 30, '6a': 40, '6a+': 50, '6b': 60,
        '6b+': 70, '6c': 80, '6c+': 90, '7a': 100, '7a+': 110,
        '7b': 120, '7b+': 130, '7c': 140, '7c+': 150, '8a': 160,
        '8a+': 170, '8b': 180, '8b+': 190, '8c': 200, '8c+': 210,
        '9a': 220, '9a+': 230, '9b': 240, '9b+': 250, '9c': 260
    }

    if grade in bouldering_points:
        return bouldering_points[grade]
    elif grade in climbing_points:
        return climbing_points[grade]
    else:
        return 0


@app.route('/delete_climb/<int:climb_id>', methods=['POST'])
def delete_climb(climb_id):
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    climb = Climb.query.get(climb_id)
    if not climb or climb.user.username != session.get("username"):
        return redirect(url_for("climb"))

    db.session.delete(climb)
    climb.user.update_points()
    db.session.commit()
    return redirect(url_for("climb"))

@app.route('/profile')
def profile():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    username = session.get("username")
    user = User.query.filter_by(username=username).first()

    if not user:
        return redirect(url_for("home"))

    user_climbs = Climb.query.filter_by(user_id=user.id).all()
    user_exercises = Exercise.query.filter_by(user_id=user.id).all()

    fun_facts = []
    height_per_pushup = 0.5
    total_height = user.pushups * height_per_pushup
    iss_altitude = 408000
    times_to_ISS = total_height / iss_altitude
    fun_facts.append(f"With your {user.pushups} pushups, you've lifted yourself a total of {total_height:.2f} meters high, equivalent to reaching the International Space Station {times_to_ISS:.2f} times!")

    pullup_height = 1
    total_height = user.pullups * pullup_height
    everest_height = 8848
    everest_climbs = total_height / everest_height
    fun_facts.append(f"You've climbed the equivalent of Mount Everest {everest_climbs:.2f} times with your pull-ups!")

    profile_data = {
        "user": user,
        "climbs": user_climbs,
        "exercises": user_exercises,
        "fun_facts": fun_facts
    }

    return render_template('profile.html', **profile_data)


@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        admin_password = request.form.get('admin_password')
        if admin_password == 'R0b1ns0n06*':
            session['is_admin'] = True
            return redirect(url_for('admin'))
        else:
            flash('Incorrect admin password', 'error')

    return render_template('admin_login.html')

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if not session.get("is_admin"):
        return redirect(url_for("admin_login"))

    users = User.query.all()
    return render_template('admin.html', users=users)


@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if not session.get("is_admin"):
        return redirect(url_for("admin_login"))

    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.username = request.form.get('username', user.username)
        user.points = int(request.form.get('points', user.points))
        user.pushups = int(request.form.get('pushups', user.pushups))
        user.pullups = int(request.form.get('pullups', user.pullups))

        if request.form.get('password'):
            user.password = generate_password_hash(request.form.get('password'), method='pbkdf2:sha256')

        db.session.commit()
        return redirect(url_for('admin'))

    return render_template('edit_user.html', user=user)


@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if not session.get("is_admin"):
        return redirect(url_for("admin_login"))

    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for('admin'))


@app.route('/delete_account', methods=['POST'])
def delete_account():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    username = session.get("username")
    user = User.query.filter_by(username=username).first()

    if user:
        db.session.delete(user)
        db.session.commit()
        session.pop("logged_in", None)
        session.pop("username", None)
        return redirect(url_for("register"))
    
    return redirect(url_for("settings"))


@app.route('/send_message_to_all_users', methods=['POST'])
def send_message_to_all_users():
    if not session.get("is_admin"):
        return redirect(url_for("admin_login"))

    message = request.form.get('message')
    users = User.query.all()
    for user in users:
        new_message = Inbox(user_id=user.id, message=message, type_of_message="Admin Message", sender="Admin")
        db.session.add(new_message)

    db.session.commit()

    return redirect(url_for('admin'))


@app.route('/logout_admin')
def logout_admin():
    session.pop('is_admin', None)
    return redirect(url_for('home'))


@app.route('/coach', methods=['GET', 'POST'])
def coach():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    username = session.get("username")
    user = User.query.filter_by(username=username).first()

    if not user:
        return redirect(url_for("home"))

    name = user.username
    age = user.age
    weight = user.weight
    height = user.height
    goal = "Bulk" if user.goal else "Cut"
    activity_level = user.activity_level
    gender = "Male" if user.gender else "Female"
    num_pushups = user.pushups
    num_pullups = user.pullups


    if request.method == 'POST':
        prompt = request.form['prompt']
        response = generate_response(prompt, name, age, weight, height, gender, goal, activity_level, num_pushups, num_pullups)
        return render_template('coach.html', response=response, prompt=prompt)

    return render_template('coach.html')

def generate_response(prompt, name, age, weight, height, gender, goal, activity_level, num_pushups, num_pullups, model="gpt-3.5-turbo", temperature=1, max_tokens=300):
    personality_description = f"""
    You are an AI fitness coach named Max designed to help people with various fitness questions and goals.
    Use this info about the current user to generate responses that are tailored to their needs.
    Name: {name}
    Age: {age}
    Weight: {weight}kg
    Height: {height}cm
    Gender: {gender}
    Fitness Goal: {goal}
    Activity Level: {activity_level}
    Pushup count: {num_pushups}
    Pullup count: {num_pullups}
    This info does not need to be used in every response, but it should be used to generate responses that are relevant to the information.
    If age is empty always reply with telling the user to go to the settings page to fill in more info.
    Please keep your responses brief and to the point.
    """
    
    messages = [
        {"role": "system", "content": personality_description},
        {"role": "user", "content": prompt}
    ]
    response = openai.ChatCompletion.create(
        model=model,
        messages=messages,
        temperature=temperature,
        max_tokens=max_tokens,
        top_p=1.0,
        frequency_penalty=0.0,
        presence_penalty=0.0
    )
    return response['choices'][0]['message']['content'].strip()


def time_since(dt, default="just now"):
    now = datetime.utcnow()
    diff = now - dt

    periods = (
        (diff.days / 365, "year", "years"),
        (diff.days / 30, "month", "months"),
        (diff.days / 7, "week", "weeks"),
        (diff.days, "day", "days"),
        (diff.seconds / 3600, "hour", "hours"),
        (diff.seconds / 60, "minute", "minutes"),
        (diff.seconds, "second", "seconds"),
    )

    for period, singular, plural in periods:
        if int(period) > 0:
            return "%d %s ago" % (period, singular if period == 1 else plural)

    return default


@app.template_filter('time_since')
def time_since_filter(dt):
    return time_since(dt)


@app.route('/inbox')
def inbox():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    username = session.get("username")
    user = User.query.filter_by(username=username).first()

    if not user:
        return redirect(url_for("home"))

    messages = Inbox.query.filter_by(user_id=user.id).order_by(Inbox.timestamp.desc()).all()
    for message in messages:
        message.read = True

    db.session.commit()

    return render_template('inbox.html', messages=messages)


@app.route('/data')
def data():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    username = session.get("username")
    user = User.query.filter_by(username=username).first()

    if not user:
        return redirect(url_for("home"))

    calorie_data = Calories.query.filter_by(user_id=user.id).order_by(Calories.day).all()
    calories = [{'day': c.day.strftime('%Y-%m-%d'), 'calories': c.calories} for c in calorie_data]

    return render_template('data.html', calories=calories)


@app.route('/calorie', methods=['GET', 'POST'])
def calorie():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    username = session.get("username")
    user = User.query.filter_by(username=username).first()

    if not user:
        return redirect(url_for("home"))
    
    if user.age == 0 or user.height == 0 or user.weight == 0:
        return redirect(url_for("settings"))

    if request.method == 'POST':
        calories_consumed = request.form.get('calories')
        description = request.form.get('description')
        if calories_consumed:
            new_calorie_entry = Calories(
                user_id=user.id, 
                calories=int(calories_consumed), 
                description=description, 
                day=date.today()
            )
            db.session.add(new_calorie_entry)
            db.session.commit()
            return redirect(url_for('calorie'))

    user_calories = Calories.query.filter_by(user_id=user.id, day=date.today()).all()
    total_calories = sum([c.calories for c in user_calories])

    daily_calorie_needs = calculate_calories(
        user.age, user.height, user.weight, user.gender, user.activity_level, user.goal
    )

    calories_left = daily_calorie_needs - total_calories

    if calories_left <= 0:
        calories_left = "Goal Achieved"

    return render_template('calorie.html', 
                           user=user, 
                           total_calories=round(total_calories, 2), 
                           daily_calorie_needs=round(daily_calorie_needs, 2), 
                           calories_left=calories_left,
                           user_calories=user_calories)



def calculate_calories(age, height, weight, gender, activity_level, goal):
    def bmr(weight, height, age, gender):
        if gender:
            return 88.362 + (13.397 * weight) + (4.799 * height) - (5.677 * age)
        else:
            return 447.593 + (9.247 * weight) + (3.098 * height) - (4.330 * age)

    activity_multipliers = {
        'sedentary': 1.2,
        'lightly_active': 1.375,
        'moderately_active': 1.55,
        'very_active': 1.725,
        'extra_active': 1.9
    }

    if activity_level not in activity_multipliers:
        raise ValueError("Invalid activity level")

    tdee = bmr(weight, height, age, gender) * activity_multipliers[activity_level]
    if goal:
        return round(tdee + 500)
    else:
        return round(tdee - 500)


@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy_policy.html')


@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password, password):
        session["logged_in"] = True
        session["username"] = username
        return jsonify({'status': 'success', 'message': 'Logged in successfully'})
    else:
        return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401


@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.pop("logged_in", None)
    session.pop("username", None)
    return jsonify({'status': 'success', 'message': 'Logged out successfully'})


@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    existing_user = User.query.filter_by(username=username).first()

    if existing_user:
        return jsonify({'status': 'error', 'message': 'User already exists'}), 400
    else:
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        session["logged_in"] = True
        session["username"] = username
        return jsonify({'status': 'success', 'message': 'User registered successfully'})


@app.route('/api/settings', methods=['GET', 'POST'])
def api_settings():
    if not session.get("logged_in"):
        return jsonify({'error': 'Not logged in'}), 401

    username = session.get("username")
    user = User.query.filter_by(username=username).first()

    if request.method == 'POST':
        data = request.get_json()
        new_username = data.get("new_username")
        new_password = data.get("new_password")
        delete_account = data.get("delete_account")

        if new_username and new_username != username:
            existing_user = User.query.filter_by(username=new_username).first()
            if existing_user:
                return jsonify({'status': 'error', 'message': 'Username already exists'}), 400
            else:
                user.username = new_username
                session["username"] = new_username

        if new_password:
            user.password = generate_password_hash(new_password, method='pbkdf2:sha256')

        if delete_account:
            db.session.delete(user)
            db.session.commit()
            session.pop("logged_in", None)
            session.pop("username", None)
            return jsonify({'status': 'success', 'message': 'Account deleted successfully'})

        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Settings updated successfully'})

    return jsonify({'username': user.username})


@app.route('/api/pushups', methods=['GET', 'POST'])
def api_pushups():
    if not session.get("logged_in"):
        return jsonify({'error': 'Not logged in'}), 401

    username = session.get("username")
    user = User.query.filter_by(username=username).first()

    if request.method == 'POST':
        data = request.get_json()
        change = data.get("change")

        if change == "increase":
            user.pushups += 1
        elif change == "decrease" and user.pushups > 0:
            user.pushups -= 1
        elif change == "increase10":
            user.pushups += 10
        elif change == "decrease10" and user.pushups > 9:
            user.pushups -= 10

        user.update_points()
        db.session.commit()

    return jsonify({'count': user.pushups})


@app.route('/api/pullups', methods=['GET', 'POST'])
def api_pullups():
    if not session.get("logged_in"):
        return jsonify({'error': 'Not logged in'}), 401

    username = session.get("username")
    user = User.query.filter_by(username=username).first()

    if request.method == 'POST':
        data = request.get_json()
        change = data.get("change")

        if change == "increase":
            user.pullups += 1
        elif change == "decrease" and user.pullups > 0:
            user.pullups -= 1
        elif change == "increase10":
            user.pullups += 10
        elif change == "decrease10" and user.pullups > 9:
            user.pullups -= 10

        user.update_points()
        db.session.commit()

    return jsonify({'count': user.pullups})


@app.route('/api/exercises', methods=['GET', 'POST', 'PUT', 'DELETE'])
def api_exercises():
    if not session.get("logged_in"):
        return jsonify({'error': 'Not logged in'}), 401

    username = session.get("username")
    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    if request.method == 'POST':
        data = request.get_json()
        exercise_name = data.get("exercise_name")

        if not exercise_name:
            return jsonify({'error': 'Exercise name is required'}), 400

        new_exercise = Exercise(name=exercise_name, user_id=user.id)
        db.session.add(new_exercise)
        user.update_points()
        db.session.commit()

        return jsonify({'status': 'success', 'message': 'Exercise added successfully'})

    elif request.method == 'PUT':
        data = request.get_json()
        exercise_id = data.get("exercise_id")
        change = data.get("change")

        if not exercise_id or change not in ['increase', 'decrease', 'increase10', 'decrease10']:
            return jsonify({'error': 'Invalid request'}), 400

        exercise = Exercise.query.get(exercise_id)

        if not exercise or exercise.user_id != user.id:
            return jsonify({'error': 'Exercise not found or access denied'}), 404

        if change == "increase":
            exercise.count += 1
        elif change == "decrease" and exercise.count > 0:
            exercise.count -= 1
        elif change == "increase10":
            exercise.count += 10
        elif change == "decrease10" and exercise.count > 9:
            exercise.count -= 10

        user.update_points()
        db.session.commit()

        return jsonify({'status': 'success', 'message': 'Exercise updated successfully', 'count': exercise.count})

    elif request.method == 'DELETE':
        data = request.get_json()
        exercise_id = data.get("exercise_id")

        if not exercise_id:
            return jsonify({'error': 'Exercise ID is required'}), 400

        exercise = Exercise.query.get(exercise_id)

        if not exercise or exercise.user_id != user.id:
            return jsonify({'error': 'Exercise not found or access denied'}), 404

        db.session.delete(exercise)
        user.update_points()
        db.session.commit()

        return jsonify({'status': 'success', 'message': 'Exercise deleted successfully'})

    else:  # GET method
        user_exercises = Exercise.query.filter_by(user_id=user.id).all()
        exercises = [{'id': e.id, 'name': e.name, 'count': e.count} for e in user_exercises]

        return jsonify(exercises)


@app.route('/api/leaderboards', methods=['GET'])
def api_leaderboards():
    users = User.query.order_by(User.points.desc(), User.username).all()
    user_data = [{'username': (user.username if not user.anonymous_mode else "Anonymous"),
                  'pullups': user.pullups, 'pushups': user.pushups, 'points': user.points} for user in users]

    return jsonify(user_data)

@app.route('/api/delete_account', methods=['POST'])
def api_delete_account():
    if not session.get("logged_in"):
        return jsonify({'error': 'Not logged in'}), 401

    username = session.get("username")
    user = User.query.filter_by(username=username).first()

    if user:
        db.session.delete(user)
        db.session.commit()
        session.pop("logged_in", None)
        session.pop("username", None)
        return jsonify({'status': 'success', 'message': 'Account deleted successfully'})

    return jsonify({'error': 'User not found'}), 404


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=81)