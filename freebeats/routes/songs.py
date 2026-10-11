from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from . import db
from models import Song, Artist, Album
from forms import SongForm
import os

songs_bp = Blueprint('songs', __name__, template_folder='../../templates')


@songs_bp.route('/songs')
def list_songs():
    page = request.args.get('page', 1, type=int)
    per_page = 12
    query = Song.query
    
    # Filter by genre
    genre = request.args.get('genre')
    if genre and genre != 'All':
        query = query.filter_by(genre=genre)
    
    # Filter by language
    language = request.args.get('language')
    if language and language != 'All':
        query = query.filter_by(language=language)
    
    # Search
    search = request.args.get('search')
    if search:
        query = query.filter(
            (Song.title.contains(search)) | 
            (Song.artist.has(name=search)) |
            (Song.album.has(name=search))
        )
    
    songs = query.order_by(Song.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    # Get filters
    genres = db.session.query(Song.genre).distinct().all()
    languages = db.session.query(Song.language).distinct().all()
    genres = [g[0] or 'All' for g in genres]
    languages = [l[0] or 'All' for l in languages]
    
    return render_template('songs.html', songs=songs, 
                         selected_genre=genre, selected_language=language,
                         search_query=search, genres=genres, languages=languages)


@songs_bp.route('/song/<int:song_id')
def song_detail(song_id):
    song = Song.query.get_or_404(song_id)
    # Increment play count
    song.play_count += 1
    db.session.commit()
    
    # Record play history
    if current_user.is_authenticated:
        play = PlayHistory(user_id=current_user.id, song_id=song.id)
        db.session.add(play)
        # Also add to recently played
        recent = RecentlyPlayed.query.filter(
            (RecentlyPlayed.user_id == current_user.id) & 
            (RecentlyPlayed.song_id == song.id)
        ).first()
        if not recent:
            recent = RecentlyPlayed(user_id=current_user.id, song_id=song.id)
            db.session.add(recent)
        else:
            db.session.delete(recent)
            recent = RecentlyPlayed(user_id=current_user.id, song_id=song.id)
            db.session.add(recent)
        # Keep only last 50 recently played
        all_recent = RecentlyPlayed.query.filter_by(user_id=current_user.id)\
            .order_by(RecentlyPlayed.played_at.desc()).all()
        if len(all_recent) > 50:
            for r in all_recent[50:]:
                db.session.delete(r)
        db.session.commit()
    
    # Get related songs (same artist)
    related = Song.query.filter_by(artist_id=song.artist_id)\
        .filter(Song.id != song.id).limit(6).all()
    
    return render_template('song_detail.html', song=song, related=related)


@songs_bp.route('/api/songs')
def api_songs():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    songs = Song.query.order_by(Song.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    return jsonify({
        'songs': [{
            'id': s.id, 'title': s.title, 'artist': s.artist.name if s.artist else 'Unknown',
            'album': s.album.name if s.album else '', 'language': s.language or 'Unknown',
            'genre': s.genre or 'Unknown', 'duration': s.duration or '0:00',
            'cover_url': s.cover_url, 'play_count': s.play_count
        } for s in songs.items],
        'total': songs.total, 'page': songs.page, 'pages': songs.pages
    })


@songs_bp.route('/api/song/<int:song_id>')
def api_song_detail(song_id):
    song = Song.query.get_or_404(song_id)
    return jsonify({
        'id': song.id, 'title': song.title, 'artist': song.artist.name if song.artist else 'Unknown',
        'album': song.album.name if song.album else '', 'language': song.language or 'Unknown',
        'genre': song.genre or 'Unknown', 'duration': song.duration or '0:00',
        'audio_url': song.audio_url, 'cover_url': song.cover_url,
        'release_year': song.release_year, 'play_count': song.play_count
    })