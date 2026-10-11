from . import db
from datetime import datetime, timezone


class Playlist(db.Model):
    __tablename__ = 'playlists'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    cover_url = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    songs = db.relationship('PlaylistSong', backref='playlist', lazy='dynamic')
    owner = db.relationship('User', backref='playlists', lazy='select')

    def __repr__(self):
        return f'<Playlist {self.name}>'