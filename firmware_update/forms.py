from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from flask_login import current_user
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectField,IntegerField,RadioField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, InputRequired
from firmware_update.models import User
import random


class LoginForm(FlaskForm):
    email = StringField('Email',validators=[DataRequired(),Email()])
    password = PasswordField('Password',validators=[DataRequired()])
    submit = SubmitField('Sign In')



class RegistrationForm(FlaskForm):

    username = StringField('Username',validators=[DataRequired(),Length(min=2,max=20)])
    email = StringField('Email',validators=[DataRequired(),Email()])
    password = PasswordField('Password',validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',validators=[DataRequired(),EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self,username):

        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a diffrent one.')
            
    def validate_email(self,email):

        user = User.query.filter_by(email=email.data).first()
        check_email_valid = email.data

        if check_email_valid.split('@')[1] != "vxlsoftware.com":

        	raise ValidationError('Please enter your valid vxlsoftware email id.')

        if user:
           raise ValidationError('That email is taken. Please choose a diffrent one.')


class PatchForm(FlaskForm):
    patch_id = IntegerField('PatchId',render_kw={'readonly':True},validators=[DataRequired()])
    patch_name = StringField('Patch Name',validators=[DataRequired()])
    min_img_build = IntegerField('Minimum',validators=[InputRequired("Only Integer values allowed.")])
    max_img_build = IntegerField('Maximum',validators=[DataRequired()])
    os_type = SelectField('OS Architecture',choices=[('32','32-Bit'),('64','64-Bit'),('Multi-Arch','Multi-Arch')])
    patch_description = TextAreaField('Description',validators=[DataRequired()])
    remove = TextAreaField('Remove')
    add = TextAreaField('Add')
    install_script = TextAreaField('install')
    submit = SubmitField('Build')

