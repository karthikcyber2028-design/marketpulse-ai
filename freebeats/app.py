import os
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from config import Config
from models import db, User, Song, Artist, Album, Playlist, PlaylistSong, Likes, RecentlyPlayed, PlayHistory
from routes.auth import auth_bp
from routes.songs import songs_bp
from routes.search import search_bp
from routes.playlists import playlists_bp
from routes.users import users_bp
from routes.admin import admin_bp

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)

    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(songs_bp)
    app.register_blueprint(search_bp)
    app.register_blueprint(playlists_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(admin_bp)

    # Context processor for menu data
    @app.context_processor
    def utility_processor():
        return dict(
            zip(['is_authenticated', 'is_admin', 'get_genre_badge', 'get_language_badge'],
                [lambda: current_user.is_authenticated if current_user else False,
                 lambda: current_user.is_admin if current_user else False,
                 lambda genre: f'<span class="badge badge-primary me-1">{genre}</span>' if genre else '',
                 lambda lang: f'<span class="badge badge-secondary me-1">{lang}</span>' if lang else ''
                ])
        )

    # Error handlers
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('error/404.html'), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template('error/500.html'), 500

    @app.errorhandler(403)
    def forbidden_error(error):
        return render_template('error/403.html'), 403

    # Home route
    @app.route('/')
    def index():
        return redirect(url_for('home'))

    @app.route('/home')
    def home():
        if current_user.is_authenticated:
            # Get recently played for user
            recently_played = RecentlyPlayed.query.filter_by(user_id=current_user.id)\
                .order_by(RecentlyPlayed.played_at.desc())\
                .limit(20).all()
            # Get some popular/songs
            songs = Song.query.order_by(Song.play_count.desc() if hasattr(Song, 'play_count') else Song.id.desc()).limit(12).all()
        else:
            recently_played = []
            songs = Song.query.limit(12).all()
        return render_template('index.html', songs=songs, recently_played=recently_played)

    # About page
    @app.route('/about')
    def about():
        return render_template('about.html')

    # Contact page
    @app.route('/contact')
    def contact():
        return render_template('contact.html')

    return app

if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        db.create_all()
    app.run(debug=True)