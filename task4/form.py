from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, DateField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Regexp


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    birthdate = DateField("Birthdate")
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8), Regexp(regex=r'\d[a-zA-Za-яА-я]')])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(),
                                                                     EqualTo('password')])
    personal_data = BooleanField('Agree?', validators=[DataRequired()])
