from . import db
from datetime import datetime, timezone


class Likes(db.Model):
    __tablename__ = 'likes'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    song_id = db.Column(db.Integer, db.ForeignKey('songs.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__(db.UniqueConstraint('user_id', 'song_id', name='user_song_unique'))

    def __repr__(self):
        return f'<Like user={self.user_id} song={self.song_id}>'