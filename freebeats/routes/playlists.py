from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from . import db
from models import Song, Playlist, PlaylistSong
from forms import PlaylistForm

playlists_bp = Blueprint('playlists', __name__, template_folder='../../templates')


@playlists_bp.route('/playlists')
@login_required
def list_playlists():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    playlists = Playlist.query.filter_by(user_id=current_user.id)\
        .order_by(Playlist.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
    return render_template('playlists.html', playlists=playlists)


@playlists_bp.route('/playlist/create', methods=['GET', 'POST'])
@login_required
def create_playlist():
    form = PlaylistForm()
    if form.validate_on_submit():
        playlist = Playlist(
            name=form.name.data,
            description=form.description.data,
            user_id=current_user.id
        )
        if form.cover_url.data:
            playlist.cover_url = form.cover_url.data
        db.session.add(playlist)
        db.session.commit()
        flash('Playlist created successfully!', 'success')
        return redirect(url_for('playlists.list_playlists'))
    return render_template('create_playlist.html', form=form)


@playlists_bp.route('/playlist/<int:playlist_id>')
@login_required
def playlist_detail(playlist_id):
    playlist = Playlist.query.get_or_404(playlist_id)
    
    # Check ownership
    if playlist.user_id != current_user.id:
        flash('You do not have access to this playlist.', 'danger')
        return redirect(url_for('playlists.list_playlists'))
    
    songs = PlaylistSong.query.filter_by(playlist_id=playlist.id)\
        .order_by(PlaylistSong.position.asc()).all()
    
    return render_template('playlist_detail.html', playlist=playlist, songs=songs)


@playlists_bp.route('/playlist/<int:playlist_id>/add', methods=['POST'])
@login_required
def add_to_playlist(playlist_id):
    playlist = Playlist.query.get_or_404(playlist_id)
    
    if playlist.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    song_id = request.form.get('song_id')
    song = Song.query.get(song_id)
    if not song:
        return jsonify({'error': 'Song not found'}), 404
    
    # Check if song already in playlist
    existing = PlaylistSong.query.filter_by(playlist_id=playlist.id, song_id=song_id).first()
    if existing:
        return jsonify({'error': 'Song already in playlist'}), 400
    
    # Get next position
    max_pos = db.session.query(db.func.max(PlaylistSong.position)).filter_by(playlist_id=playlist.id).scalar()
    next_pos = (max_pos or 0) + 1
    
    playlist_song = PlaylistSong(
        playlist_id=playlist.id,
        song_id=song_id,
        position=next_pos
    )
    db.session.add(playlist_song)
    db.session.commit()
    
    return jsonify({'success': True, 'position': next_pos})


@playlists_bp.route('/playlist/<int:playlist_id>/remove', methods=['POST'])
@login_required
def remove_from_playlist(playlist_id):
    playlist = Playlist.query.get_or_404(playlist_id)
    
    if playlist.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    song_id = request.form.get('song_id')
    playlist_song = PlaylistSong.query.filter_by(playlist_id=playlist.id, song_id=song_id).first()
    if playlist_song:
        db.session.delete(playlist_song)
        db.session.commit()
        return jsonify({'success': True})
    
    return jsonify({'error': 'Song not found in playlist'}), 404


@playlists_bp.route('/playlists/api', methods=['GET'])
@login_required
def api_playlists():
    playlists = Playlist.query.filter_by(user_id=current_user.id)\
        .order_by(Playlist.created_at.desc()).all()
    return jsonify({
        'playlists': [{
            'id': p.id, 'name': p.name, 'description': p.description or '',
            'cover_url': p.cover_url, 'created_at': p.created_at.isoformat() if p.created_at else '',
            'song_count': len(p.songs)
        } for p in playlists]
    })