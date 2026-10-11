from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from . import db
from models import User, Song, Playlist, Likes, RecentlyPlayed
from forms import EditProfileForm

users_bp = Blueprint('users', __name__, template_folder='../../templates')


@users_bp.route('/profile')
@login_required
def profile():
    user = current_user
    playlists = user.playlists.limit(10).all()
    liked_songs = Likes.query.filter_by(user_id=user.id)\
        .join(Song).order_by(Likes.created_at.desc()).limit(10).all()
    recently_played = RecentlyPlayed.query.filter_by(user_id=user.id)\
        .order_by(RecentlyPlayed.played_at.desc()).limit(10).all()
    return render_template('profile.html', user=user,
                         playlists=playlists, liked_songs=liked_songs,
                         recently_played=recently_played)


@users_bp.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.username = form.username.data
        if form.profile_image.data:
            current_user.profile_image = form.profile_image.data
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('users.profile'))
    elif request.method == 'GET':
        form.name.data = current_user.name
        form.username.data = current_user.username
    return render_template('edit_profile.html', form=form)


@users_bp.route('/liked-songs')
@login_required
def liked_songs():
    page = request.args.get('page', 1, type=int)
    per_page = 12
    likes = Likes.query.filter_by(user_id=current_user.id)\
        .join(Song).order_by(Likes.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
    return render_template('liked_songs.html', likes=likes)


@users_bp.route('/recently-played')
@login_required
def recently_played():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    played = RecentlyPlayed.query.filter_by(user_id=current_user.id)\
        .order_by(RecentlyPlayed.played_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
    return render_template('recently_played.html', played=played)


@users_bp.route('/api/profile', methods=['GET', 'PUT'])
@login_required
def api_profile():
    if request.method == 'GET':
        return jsonify({
            'id': current_user.id, 'name': current_user.name,
            'username': current_user.username, 'email': current_user.email,
            'profile_image': current_user.profile_image
        })
    
    if request.method == 'PUT':
        data = request.get_json()
        if data.get('name'):
            current_user.name = data['name']
        if data.get('username'):
            # Check if username is unique
            existing = User.query.filter_by(username=data['username']).first()
            if existing and existing.id != current_user.id:
                return jsonify({'error': 'Username already taken'}), 400
            current_user.username = data['username']
        db.session.commit()
        return jsonify({'success': True})