from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()


class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(80), nullable=False)
    lastname = db.Column(db.String(80), nullable=False)
    group = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(80), nullable=False)

    def __repr__(self):
        return f'{self.firstname} {self.lastname} {self.group} {self.email}'


class Score(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    name = db.Column(db.String(80), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    students = db.relationship('Student', secondary='student_score', backref="scores", lazy=True)

    def __repr__(self):
        return f'{self.name} {self.score}'


class StudentScore(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)
    score_id = db.Column(db.Integer, db.ForeignKey('score.id'), nullable=False)