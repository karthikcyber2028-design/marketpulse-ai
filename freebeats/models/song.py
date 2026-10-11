from . import db
from datetime import datetime, timezone


class Song(db.Model):
    __tablename__ = 'songs'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    artist_id = db.Column(db.Integer, db.ForeignKey('artists.id'), nullable=True)
    album_id = db.Column(db.Integer, db.ForeignKey('albums.id'), nullable=True)
    genre = db.Column(db.String(50), nullable=True)
    language = db.Column(db.String(50), nullable=True)
    audio_url = db.Column(db.String(500), nullable=False)
    cover_url = db.Column(db.String(500), nullable=True)
    duration = db.Column(db.String(20), nullable=True)
    release_year = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    play_count = db.Column(db.Integer, default=0, nullable=False)

    artist = db.relationship('Artist', backref='songs', lazy='select')
    album = db.relationship('Album', backref='songs', lazy='select')
    likes = db.relationship('Likes', backref='song', lazy='select')
    recently_played = db.relationship('RecentlyPlayed', backref='song', lazy='select')
    play_history = db.relationship('PlayHistory', backref='song', lazy='select')

    def __repr__(self):
        return f'<Song {self.title}>'