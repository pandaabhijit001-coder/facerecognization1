import os
import threading
import uuid
import time
from flask import Flask, request, render_template, redirect, url_for, flash, jsonify, send_from_directory
from werkzeug.utils import secure_filename
from pytube import YouTube
import cv2
import face_recognition
import numpy as np

from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secure_secret_key_here'  # Change for production!

UPLOAD_FOLDER = 'uploads'
THUMBS_FOLDER = 'thumbnails'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(THUMBS_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['THUMBS_FOLDER'] = THUMBS_FOLDER

# SQLite DB for user authentication (easy to start)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

limiter = Limiter(app, key_func=get_remote_address, default_limits=["100 per hour"])

ALLOWED_VIDEO_EXTENSIONS = {'mp4', 'avi', 'mov', 'mkv'}
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg'}


# Database User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # required by Flask-Login
    email = db.Column(db.String(150), unique=True)
    password_hash = db.Column(db.String(256))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def allowed_file(filename, allowed_set):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_set


def download_youtube_video(url, output_path):
    yt = YouTube(url)
    stream = yt.streams.filter(progressive=True, file_extension='mp4').order_by('resolution').desc().first()
    stream.download(filename=output_path)
    return output_path


def get_face_encoding(image_path):
    img = face_recognition.load_image_file(image_path)
    encodings = face_recognition.face_encodings(img)
    if encodings:
        return encodings[0]
    return None


def face_recognition_task(task_id, video_path, person_encoding, frame_interval=30):
    video = cv2.VideoCapture(video_path)
    fps = video.get(cv2.CAP_PROP_FPS) or 25
    frame_count = int(video.get(cv2.CAP_PROP_FRAME_COUNT))
    frame_number = 0
    matches = []

    while True:
        ret, frame = video.read()
        if not ret:
            break

        if frame_number % frame_interval == 0:
            rgb_frame = frame[:, :, ::-1]
            face_locations = face_recognition.face_locations(rgb_frame)
            face_encodings = face_recognition.face_encodings(rgb_frame, face_locations)

            for face_encoding, location in zip(face_encodings, face_locations):
                if face_recognition.compare_faces([person_encoding], face_encoding)[0]:
                    timestamp = frame_number / fps
                    matches.append(round(timestamp, 2))

                    top, right, bottom, left = location
                    face_image = frame[top:bottom, left:right]
                    thumb_path = os.path.join(app.config['THUMBS_FOLDER'], f"{task_id}_{frame_number}.jpg")
                    cv2.imwrite(thumb_path, face_image)
                    break

        frame_number += 1
        processing_status[task_id]['progress'] = int((frame_number / frame_count) * 100)

    video.release()
    processing_status[task_id]['matches'] = matches
    processing_status[task_id]['done'] = True


processing_status = {}


@app.before_first_request
def startup_cleanup():
    # Cleanup old files older than 1 day (86400 seconds)
    def cleanup_old_files(folder, max_age_seconds=86400):
        now = time.time()
        for filename in os.listdir(folder):
            file_path = os.path.join(folder, filename)
            if os.path.isfile(file_path):
                file_age = now - os.path.getmtime(file_path)
                if file_age > max_age_seconds:
                    try:
                        os.remove(file_path)
                        app.logger.info(f"Deleted {file_path}")
                    except Exception as e:
                        app.logger.error(f"Error deleting {file_path}: {e}")

    cleanup_old_files(app.config['UPLOAD_FOLDER'])
    cleanup_old_files(app.config['THUMBS_FOLDER'])


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash("Email and password required")
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))

        user = User(email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful. Please log in.")
        return redirect(url_for('login'))

    return render_template('login.html', register=True)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        flash("Invalid credentials or user does not exist")

    return render_template('login.html', register=False)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You logged out successfully")
    return redirect(url_for('login'))


@app.route('/', methods=['GET', 'POST'])
@login_required
@limiter.limit("10/minute")
def index():
    if request.method == 'POST':
        youtube_url = request.form.get('youtube_url')
        video_file = request.files.get('video_file')
        image_file = request.files.get('image_file')

        if not image_file or not allowed_file(image_file.filename, ALLOWED_IMAGE_EXTENSIONS):
            flash('Please upload a valid image file for the person to find (png, jpg, jpeg).')
            return redirect(request.url)
        image_filename = secure_filename(image_file.filename)
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
        image_file.save(image_path)

        person_encoding = get_face_encoding(image_path)
        if person_encoding is None:
            flash('Could not detect a face in the reference image. Please use a clear image.')
            return redirect(request.url)

        if youtube_url:
            try:
                video_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{uuid.uuid4()}.mp4")
                download_youtube_video(youtube_url, video_path)
            except Exception as e:
                flash(f"Failed to download YouTube video: {e}")
                return redirect(request.url)
        elif video_file and allowed_file(video_file.filename, ALLOWED_VIDEO_EXTENSIONS):
            video_filename = secure_filename(video_file.filename)
            video_path = os.path.join(app.config['UPLOAD_FOLDER'], video_filename)
            video_file.save(video_path)
        else:
            flash('Please provide a valid YouTube URL or upload a supported video file.')
            return redirect(request.url)

        task_id = str(uuid.uuid4())
        processing_status[task_id] = {'progress': 0, 'done': False, 'matches': []}

        thread = threading.Thread(target=face_recognition_task, args=(task_id, video_path, person_encoding))
        thread.start()
        return redirect(url_for('status', task_id=task_id))

    return render_template('index.html')


@app.route('/status/<task_id>')
@login_required
@limiter.limit("20/minute")
def status(task_id):
    status = processing_status.get(task_id)
    if not status:
        return "Invalid task ID", 404
    return render_template('status.html', task_id=task_id, status=status)


@app.route('/progress/<task_id>')
@login_required
@limiter.limit("20/minute")
def progress(task_id):
    status = processing_status.get(task_id)
    if not status:
        return jsonify({'error': 'Invalid task ID'}), 404
    return jsonify(status)


@app.route('/thumbnails/<filename>')
@login_required
def thumbnails(filename):
    return send_from_directory(app.config['THUMBS_FOLDER'], filename)


@app.route('/list_thumbnails/<task_id>')
@login_required
def list_thumbnails(task_id):
    files = [f for f in os.listdir(app.config['THUMBS_FOLDER']) if f.startswith(task_id)]
    return jsonify(files)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, host="0.0.0.0", port=5000)
