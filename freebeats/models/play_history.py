from . import db
from datetime import datetime, timezone


class PlayHistory(db.Model):
    __tablename__ = 'play_history'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    song_id = db.Column(db.Integer, db.ForeignKey('songs.id'), nullable=False)
    played_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f'<PlayHistory user={self.user_id} song={self.song_id}>'