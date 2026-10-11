from . import db
from datetime import datetime, timezone


class Artist(db.Model):
    __tablename__ = 'artists'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    bio = db.Column(db.Text, nullable=True)
    image_url = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    songs = db.relationship('Song', backref='artist', lazy='select')

    def __repr__(self):
        return f'<Artist {self.name}>'