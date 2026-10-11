from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField, TextAreaField, IntegerField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, Optional
from models import User


def username_exists(form, field):
    user = User.query.filter_by(username=field.data).first()
    if user:
        raise ValidationError('Username already registered. Please choose a different one.')


def email_exists(form, field):
    user = User.query.filter_by(email=field.data).first()
    if user:
        raise ValidationError('Email already registered. Please use a different email.')


class RegistrationForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(message='Name is required')])
    username = StringField('Username', validators=[DataRequired(message='Username is required')])
    email = StringField('Email', validators=[DataRequired(message='Email is required'), Email(message='Valid email required')])
    password = PasswordField('Password', validators=[DataRequired(message='Password is required'), Length(minimum=6, message='Password must be at least 6 characters')])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(message='Please confirm your password'), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Register')

    def validate_username(self, field):
        username_exists(self, field)


class LoginForm(FlaskForm):
    email = StringField('Email or Username', validators=[DataRequired(message='Email/Username is required')])
    password = PasswordField('Password', validators=[DataRequired(message='Password is required')])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class SongForm(FlaskForm):
    title = StringField('Song Title', validators=[DataRequired(message='Title is required')])
    artist_id = SelectField('Artist', coerce=int, validators=[Optional()])
    album_id = SelectField('Album', coerce=int, validators=[Optional()])
    genre = StringField('Genre', validators=[Optional()])
    language = StringField('Language', validators=[Optional()])
    audio_url = StringField('Audio URL', validators=[DataRequired(message='Audio URL is required')])
    cover_url = StringField('Cover Image URL', validators=[Optional()])
    duration = StringField('Duration (mm:ss)', validators=[Optional()])
    release_year = IntegerField('Release Year', validators=[Optional()])
    submit = SubmitField('Submit')


class PlaylistForm(FlaskForm):
    name = StringField('Playlist Name', validators=[DataRequired(message='Name is required')])
    description = TextAreaField('Description', validators=[Optional()])
    cover_url = StringField('Cover Image URL', validators=[Optional()])
    submit = SubmitField('Create Playlist')


class EditProfileForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(message='Name is required')])
    username = StringField('Username', validators=[DataRequired(message='Username is required')])
    profile_image = StringField('Profile Image URL', validators=[Optional()])
    submit = SubmitField('Update Profile')


class ArtistForm(FlaskForm):
    name = StringField('Artist Name', validators=[DataRequired(message='Artist name is required')])
    bio = TextAreaField('Biography', validators=[Optional()])
    image_url = StringField('Image URL', validators=[Optional()])
    submit = SubmitField('Submit')


class AlbumForm(FlaskForm):
    name = StringField('Album Name', validators=[DataRequired(message='Album name is required')])
    artist_id = SelectField('Artist', coerce=int, validators=[Optional()])
    cover_url = StringField('Cover Image URL', validators=[DataRequired(message='Cover URL is required')])
    release_year = IntegerField('Release Year', validators=[Optional()])
    submit = SubmitField('Submit')