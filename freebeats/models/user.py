from . import db
from datetime import datetime, timezone


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    profile_image = db.Column(db.String(255), default='default.png')
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    playlists = db.relationship('Playlist', backref='owner', lazy='dynamic')
    liked_songs = db.relationship('Likes', backref='user', lazy='dynamic')
    recently_played = db.relationship('RecentlyPlayed', backref='user', lazy='dynamic')
    play_history = db.relationship('PlayHistory', backref='user', lazy='dynamic')

    def __repr__(self):
        return f'<User {self.username}>'

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)