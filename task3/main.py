import os
import random

from flask import Flask, render_template
from models import db, Student, Score, StudentScore

app = Flask(__name__)
app.secret_key = b'5f214cacbd30c2ae4784b520f17912ae0d5d8csdsdde98128e3f549546221265e4'

app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///students.db'
db.init_app(app)


@app.route('/')
def index():
    return "hello"


@app.cli.command("init-db")
def init_db():
    db.create_all()


@app.cli.command("test-data")
def add_test_data():
    COUNT = 10
    for i in range(1, COUNT + 1):
        student = Student(
            firstname=f"name{i}",
            lastname=f"surname{i}",
            group=2,
            email=f"email{i}",
        )
        db.session.add(student)
    for i in range(1, COUNT + 6):
        score = Score(student_id=random.randint(1, COUNT),
                      name=f"name{i}",
                      score=random.randint(1, 5))
        db.session.add(score)
    for i in range(1, COUNT * 2):
        student_score = StudentScore(student_id=random.randint(1, COUNT),
                                     score_id=random.randint(1, COUNT + 5))
        db.session.add(student_score)
    db.session.commit()
    print('Данные добавлены')


@app.route("/students/")
def get_students():
    all_students = Student.query.all()
    context = {'students': all_students}
    return render_template("students.html", **context)