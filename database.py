class Role(db.Model):
    __tablename__ = 'role'
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(64), unique = True)
    # users.relationship('User', backref = 'role')

    def __repr__(self):
        return '<Role %r>' % self.name

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index = True)
    password = db.Column(db.String(64))
    role_id = db.Column(db.Integer, db.ForeignKey('role_id'))

    def __repr__(self):
        return '<Role %r>' % self.username