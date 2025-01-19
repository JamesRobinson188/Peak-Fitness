from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
import os
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

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

    exercises = db.relationship('Exercise', backref='user', cascade='all, delete-orphan')
    climbs = db.relationship('Climb', backref='user', cascade='all, delete-orphan')
    inbox = db.relationship('Inbox', backref='user', cascade='all, delete-orphan')
    exercise_logs = db.relationship('ExerciseLog', backref='user', cascade='all, delete-orphan')

    def update_points(self):
        self.points = self.pushups + self.pullups * 2
        for exercise in self.exercises:
            self.points += exercise.count
        for climb in self.climbs:
            self.points += climb.points


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


class ExerciseLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    exercise_name = db.Column(db.String(100))
    change = db.Column(db.String(20))     # e.g. "increase", "decrease", "increase10", "decrease10"
    old_count = db.Column(db.Integer)
    new_count = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


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


@app.route("/patch")
def patch():
    return render_template("patch.html")


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
        old_count = user.pushups

        if change == "increase":
            user.pushups += 1
        elif change == "decrease" and user.pushups > 0:
            user.pushups -= 1
        elif change == "increase10":
            user.pushups += 10
        elif change == "decrease10" and user.pushups > 9:
            user.pushups -= 10

        new_count = user.pushups
        # Log the change
        if old_count != new_count:
            log_entry = ExerciseLog(user_id=user.id, exercise_name="pushups", change=change, old_count=old_count, new_count=new_count)
            db.session.add(log_entry)

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
        old_count = user.pullups

        if change == "increase":
            user.pullups += 1
        elif change == "decrease" and user.pullups > 0:
            user.pullups -= 1
        elif change == "increase10":
            user.pullups += 10
        elif change == "decrease10" and user.pullups > 9:
            user.pullups -= 10

        new_count = user.pullups
        # Log the change
        if old_count != new_count:
            log_entry = ExerciseLog(user_id=user.id, exercise_name="pullups", change=change, old_count=old_count, new_count=new_count)
            db.session.add(log_entry)

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

    old_count = user.pushups
    if change == "increase":
        user.pushups += 1
    elif change == "decrease" and user.pushups > 0:
        user.pushups -= 1
    elif change == "increase10":
        user.pushups += 10
    elif change == "decrease10" and user.pushups > 9:
        user.pushups -= 10

    new_count = user.pushups
    if old_count != new_count:
        log_entry = ExerciseLog(user_id=user.id, exercise_name="pushups", change=change, old_count=old_count, new_count=new_count)
        db.session.add(log_entry)

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

    old_count = user.pullups
    if change == "increase":
        user.pullups += 1
    elif change == "decrease" and user.pullups > 0:
        user.pullups -= 1
    elif change == "increase10":
        user.pullups += 10
    elif change == "decrease10" and user.pullups > 9:
        user.pullups -= 10

    new_count = user.pullups
    if old_count != new_count:
        log_entry = ExerciseLog(user_id=user.id, exercise_name="pullups", change=change, old_count=old_count, new_count=new_count)
        db.session.add(log_entry)

    user.update_points()
    db.session.commit()
    return jsonify({'count': user.pullups})


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

        if not error:
            db.session.commit()

    # Removed references to user.gender, user.activity_level, user.goal as they don't exist
    return render_template('settings.html', user=user, error=error)


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

    old_count = exercise.count
    if change == "increase":
        exercise.count += 1
    elif change == "decrease" and exercise.count > 0:
        exercise.count -= 1
    elif change == "increase10":
        exercise.count += 10
    elif change == "decrease10" and exercise.count > 9:
        exercise.count -= 10

    new_count = exercise.count
    exercise.user.update_points()

    if old_count != new_count:
        log_entry = ExerciseLog(user_id=exercise.user_id, exercise_name=exercise.name, change=change, old_count=old_count, new_count=new_count)
        db.session.add(log_entry)

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
    for u in users:
        new_message = Inbox(user_id=u.id, message=message, type_of_message="Admin Message", sender="Admin")
        db.session.add(new_message)

    db.session.commit()

    return redirect(url_for('admin'))


@app.route('/logout_admin')
def logout_admin():
    session.pop('is_admin', None)
    return redirect(url_for('home'))


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

        old_count = user.pushups
        if change == "increase":
            user.pushups += 1
        elif change == "decrease" and user.pushups > 0:
            user.pushups -= 1
        elif change == "increase10":
            user.pushups += 10
        elif change == "decrease10" and user.pushups > 9:
            user.pushups -= 10

        new_count = user.pushups
        if old_count != new_count:
            log_entry = ExerciseLog(user_id=user.id, exercise_name="pushups", change=change, old_count=old_count, new_count=new_count)
            db.session.add(log_entry)

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

        old_count = user.pullups
        if change == "increase":
            user.pullups += 1
        elif change == "decrease" and user.pullups > 0:
            user.pullups -= 1
        elif change == "increase10":
            user.pullups += 10
        elif change == "decrease10" and user.pullups > 9:
            user.pullups -= 10

        new_count = user.pullups
        if old_count != new_count:
            log_entry = ExerciseLog(user_id=user.id, exercise_name="pullups", change=change, old_count=old_count, new_count=new_count)
            db.session.add(log_entry)

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

        old_count = exercise.count
        if change == "increase":
            exercise.count += 1
        elif change == "decrease" and exercise.count > 0:
            exercise.count -= 1
        elif change == "increase10":
            exercise.count += 10
        elif change == "decrease10" and exercise.count > 9:
            exercise.count -= 10

        new_count = exercise.count
        user.update_points()

        if old_count != new_count:
            log_entry = ExerciseLog(user_id=user.id, exercise_name=exercise.name, change=change, old_count=old_count, new_count=new_count)
            db.session.add(log_entry)

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

    else:
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


@app.route('/exercise_logs')
def exercise_logs():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    username = session.get("username")
    user = User.query.filter_by(username=username).first()
    if not user:
        return redirect(url_for("login"))

    logs = ExerciseLog.query.filter_by(user_id=user.id).order_by(ExerciseLog.timestamp.desc()).all()

    # Convert them to JSON-friendly dicts
    logs_data = []
    for log in logs:
        logs_data.append({
            'id': log.id,
            'user_id': log.user_id,
            'exercise_name': log.exercise_name,
            'change': log.change,
            'old_count': log.old_count,
            'new_count': log.new_count,
            'timestamp': log.timestamp.isoformat()  # to avoid the "not JSON serializable" error
        })

    return render_template('exercise_logs.html', logs=logs_data)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=81)
