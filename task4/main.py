import hashlib

from flask import Flask, request, render_template
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
import binascii
from form import RegistrationForm
from models import db, User

app2 = Flask(__name__)
app2.config['SECRET_KEY'] = 'mysecretkey'
csrf = CSRFProtect(app2)
app2.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///users.db'
db.init_app(app2)


@app2.cli.command("init-db")
def init_db():
    db.create_all()


@app2.route('/register/', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if request.method == 'POST' and form.validate():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        birthdate = form.birthdate.data
        personal_data = form.personal_data.data
        dk = hashlib.pbkdf2_hmac(hash_name='sha256',
                                 password=bytes(password, 'utf-8'),
                                 salt=b'bad_salt',
                                 iterations=100000)

        password = binascii.hexlify(dk)
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        if existing_user:
            error_msg = 'Username or email already exists.'
            form.username.errors.append(error_msg)
            return render_template('register.html', form=form)
        new_user = User(username=username, email=email, birthdate=birthdate, password=password,
                        personal_data=personal_data)
        db.session.add(new_user)
        db.session.commit()

        # Выводим сообщение об успешной регистрации
        success_msg = 'Registration successful!'
        return success_msg

    return render_template('register.html', form=form)