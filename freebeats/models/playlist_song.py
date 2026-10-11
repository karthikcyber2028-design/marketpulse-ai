from . import db
from datetime import datetime, timezone


class PlaylistSong(db.Model):
    __tablename__ = 'playlist_songs'

    playlist_id = db.Column(db.Integer, db.ForeignKey('playlists.id'), primary_key=True)
    song_id = db.Column(db.Integer, db.ForeignKey('songs.id'), primary_key=True)
    position = db.Column(db.Integer, nullable=False, default=0)

    def __repr__(self):
        return f'<PlaylistSong playlist={self.playlist_id} song={self.song_id}>'