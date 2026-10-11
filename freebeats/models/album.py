from . import db
from datetime import datetime, timezone


class Album(db.Model):
    __tablename__ = 'albums'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    artist_id = db.Column(db.Integer, db.ForeignKey('artists.id'), nullable=True)
    cover_url = db.Column(db.String(500), nullable=True)
    release_year = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    artist = db.relationship('Artist', backref='albums', lazy='select')
    songs = db.relationship('Song', backref='album', lazy='select')

    def __repr__(self):
        return f'<Album {self.name}>'