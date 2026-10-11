from flask import Blueprint, render_template, request, jsonify
from . import db
from models import Song, Artist, Album


search_bp = Blueprint('search', __name__, template_folder='../../templates')


@search_bp.route('/search')
def search():
    query = request.args.get('q', '')
    if not query:
        return redirect(url_for('home'))
    
    # Search songs
    songs = Song.query.filter(
        (Song.title.contains(query)) | 
        (Song.artist.has(name.contains(query)))
    ).limit(10).all()
    
    # Search artists
    artists = Artist.query.filter(Artist.name.contains(query)).limit(10).all()
    
    # Search albums
    albums = Album.query.filter(Album.name.contains(query)).limit(10).all()
    
    return jsonify({
        'songs': [{
            'id': s.id, 'title': s.title, 'artist': s.artist.name if s.artist else 'Unknown',
            'album': s.album.name if s.album else '', 'language': s.language or 'Unknown',
            'genre': s.genre or 'Unknown', 'cover_url': s.cover_url
        } for s in songs],
        'artists': [{'id': a.id, 'name': a.name, 'image_url': a.image_url} for a in artists],
        'albums': [{'id': a.id, 'name': a.name, 'artist': a.artist.name if a.artist else '', 'cover_url': a.cover_url} for a in albums]
    })


@search_bp.route('/api/search-suggestions')
def api_search_suggestions():
    query = request.args.get('q', '')
    if not query or len(query) < 2:
        return jsonify([])
    
    songs = Song.query.filter(Song.title.contains(query)).limit(5).all()
    artists = Artist.query.filter(Artist.name.contains(query)).limit(5).all()
    
    return jsonify({
        'songs': [{'id': s.id, 'title': s.title, 'artist': s.artist.name if s.artist else 'Unknown'} for s in songs],
        'artists': [{'id': a.id, 'name': a.name} for a in artists]
    })