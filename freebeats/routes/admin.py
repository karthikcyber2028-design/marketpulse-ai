from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from . import db
from models import User, Song, Artist, Album, Playlist, Likes, RecentlyPlayed
from forms import SongForm, ArtistForm, AlbumForm

admin_bp = Blueprint('admin', __name__, template_folder='../../templates')


def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Access denied. Admin privileges required.', 'danger')
            return redirect(url_for('auth.login'))
        return wrapped(*args, **kwargs)
    decorated_function.is_wrapped = True
    return decorated_function


@admin_bp.route('/admin')
@login_required
@admin_required
def dashboard():
    stats = {
        'total_users': User.query.count(),
        'total_songs': Song.query.count(),
        'total_artists': Artist.query.count(),
        'total_albums': Album.query.count(),
        'total_playlists': Playlist.query.count(),
        'total_plays': db.session.query(db.func.count(PlayHistory.id)).scalar()
    }
    
    # Recent users
    recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
    
    # Recent songs
    recent_songs = Song.query.order_by(Song.created_at.desc()).limit(5).all()
    
    return render_template('admin/dashboard.html', stats=stats,
                         recent_users=recent_users, recent_songs=recent_songs)


# Song management
@admin_bp.route('/admin/songs')
@login_required
@admin_required
def admin_songs():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    songs = Song.query.order_by(Song.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    return render_template('admin/songs.html', songs=songs)


@admin_bp.route('/admin/song/create', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_song_create():
    form = SongForm()
    if form.validate_on_submit():
        song = Song(
            title=form.title.data,
            artist_id=form.artist_id.data if form.artist_id.data else None,
            album_id=form.album_id.data if form.album_id.data else None,
            genre=form.genre.data,
            language=form.language.data,
            audio_url=form.audio_url.data,
            cover_url=form.cover_url.data,
            duration=form.duration.data,
            release_year=form.release_year.data
        )
        db.session.add(song)
        db.session.commit()
        flash('Song added successfully!', 'success')
        return redirect(url_for('admin.admin_songs'))
    return render_template('admin/song_form.html', form=form, action='Create')


@admin_bp.route('/admin/song/<int:song_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_song_edit(song_id):
    song = Song.query.get_or_404(song_id)
    form = SongForm(obj=song)
    if form.validate_on_submit():
        form.populate_obj(song)
        db.session.commit()
        flash('Song updated successfully!', 'success')
        return redirect(url_for('admin.admin_songs'))
    return render_template('admin/song_form.html', form=form, action='Edit', song=song)


@admin_bp.route('/admin/song/<int:song_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_song_delete(song_id):
    song = Song.query.get_or_404(song_id)
    db.session.delete(song)
    db.session.commit()
    flash('Song deleted successfully!', 'success')
    return redirect(url_for('admin.admin_songs'))


# Artist management
@admin_bp.route('/admin/artists')
@login_required
@admin_required
def admin_artists():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    artists = Artist.query.order_by(Artist.name.asc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    return render_template('admin/artists.html', artists=artists)


@admin_bp.route('/admin/artist/create', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_artist_create():
    form = ArtistForm()
    if form.validate_on_submit():
        artist = Artist(name=form.name.data, bio=form.bio.data, image_url=form.image_url.data)
        db.session.add(artist)
        db.session.commit()
        flash('Artist added successfully!', 'success')
        return redirect(url_for('admin.admin_artists'))
    return render_template('admin/artist_form.html', form=form, action='Create')


@admin_bp.route('/admin/artist/<int:artist_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_artist_edit(artist_id):
    artist = Artist.query.get_or_404(artist_id)
    form = ArtistForm(obj=artist)
    if form.validate_on_submit():
        form.populate_obj(artist)
        db.session.commit()
        flash('Artist updated successfully!', 'success')
        return redirect(url_for('admin.admin_artists'))
    return render_template('admin/artist_form.html', form=form, action='Edit', artist=artist)


@admin_bp.route('/admin/artist/<int:artist_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_artist_delete(artist_id):
    artist = Artist.query.get_or_404(artist_id)
    # Check if artist has songs
    if artist.songs.count() > 0:
        flash('Cannot delete artist with existing songs.', 'danger')
    else:
        db.session.delete(artist)
        db.session.commit()
        flash('Artist deleted successfully!', 'success')
    return redirect(url_for('admin.admin_artists'))


# Album management
@admin_bp.route('/admin/albums')
@login_required
@admin_required
def admin_albums():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    albums = Album.query.order_by(Album.name.asc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    return render_template('admin/albums.html', albums=albums)


@admin_bp.route('/admin/album/create', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_album_create():
    form = AlbumForm()
    if form.validate_on_submit():
        album = Album(
            name=form.name.data,
            artist_id=form.artist_id.data if form.artist_id.data else None,
            cover_url=form.cover_url.data,
            release_year=form.release_year.data
        )
        db.session.add(album)
        db.session.commit()
        flash('Album added successfully!', 'success')
        return redirect(url_for('admin.admin_albums'))
    return render_template('admin/album_form.html', form=form, action='Create')


@admin_bp.route('/admin/album/<int:album_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_album_edit(album_id):
    album = Album.query.get_or_404(album_id)
    form = AlbumForm(obj=album)
    if form.validate_on_submit():
        form.populate_obj(album)
        db.session.commit()
        flash('Album updated successfully!', 'success')
        return redirect(url_for('admin.admin_albums'))
    return render_template('admin/album_form.html', form=form, action='Edit', album=album)


@admin_bp.route('/admin/album/<int:album_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_album_delete(album_id):
    album = Album.query.get_or_404(album_id)
    db.session.delete(album)
    db.session.commit()
    flash('Album deleted successfully!', 'success')
    return redirect(url_for('admin.admin_albums'))


# User management
@admin_bp.route('/admin/users')
@login_required
@admin_required
def admin_users():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    users = User.query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    return render_template('admin/users.html', users=users)


@admin_bp.route('/admin/user/<int:user_id>/toggle', methods=['POST'])
@login_required
@admin_required
def admin_toggle_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('Cannot toggle your own admin status.', 'danger')
    else:
        user.is_admin = not user.is_admin
        db.session.commit()
        flash(f'User {"enabled" if user.is_admin else "disabled"} successfully!', 'success')
    return redirect(url_for('admin.admin_users'))