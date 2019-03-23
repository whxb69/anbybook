from flask import Flask, render_template, session, redirect, url_for, flash, request, send_from_directory
from flask_bootstrap import Bootstrap
from wtforms import StringField, SubmitField, PasswordField, FileField, BooleanField, TextAreaField
from wtforms.validators import Required, Email, EqualTo
from flask_wtf import FlaskForm
from flask_sqlalchemy import SQLAlchemy
from flask_login import login_user, login_required, logout_user, UserMixin, LoginManager,current_user, AnonymousUserMixin
import time
from flask_moment import Moment
from datetime import datetime
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
import os
from threading import Thread
import sys
import hashlib    #models
import urllib

# from . import main
# from .. import db
# from ..models import Permission, Role, User
# from ..decorators import admin_required, permission_required


basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
db = SQLAlchemy(app)
moment =Moment(app)

boostrap = Bootstrap(app)
login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.init_app(app)


app.config.update(dict(
    SECRET_KEY="powerful secretkey",
    WTF_CSRF_SECRET_KEY="a csrf secret key",
    SQLALCHEMY_DATABASE_URI = r'sqlite:///D:\anby\Flask\database\\blog.db',
    # SQLALCHEMY_DATABASE_URI = r'sqlite:///G:\anby\Flask\database\\blog.db',
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True,
    MAIL_SERVER='smtp.office365.com',
    MAIL_PROT=587,
    MAIL_USE_TLS=True,
    MAIL_USE_SSL=False,
    MAIL_DEBUG=True,
    MAIL_USERNAME = 'anbybooks@hotmail.com',
    MAIL_PASSWORD = 'anbydianzi123'
    

))

mail = Mail(app)

class Permission:
    FOLLOW = 1
    COMMENT = 2
    UPLOAD = 4
    MODERATE = 8
    ADMIN = 16

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    password = db.Column(db.String(64))
    email = db.Column(db.String(120), unique=True)
    password_hash = db.Column(db.String(128))
    confirmed = db.Column(db.Boolean, default=False)
    admin = db.Column(db.Integer,default = 0)


    def __init__(self, name, email, password, password_hash, confirmed = False, admin = 0):
        self.name = name
        self.email = email
        self.password = password
        self.password_hash = password_hash
        self.confirmed = confirmed
        self.admin = admin

    def __repr__(self):
        return '<User %r>' % self.name

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self,password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self,password):
        return  check_password_hash(self.password_hash,password)

    def gravatar(self, size=100, default='identicon', rating='g'):
        if request.is_secure:
            url = 'https://secure.gravatar.com/avatar'
        else:
            url = 'https://www.gravatar.com/avatar'
        hash = hashlib.md5(self.email.encode('utf_8')).hexdigest()
        return '{url}/{hash}?s={size}&d={default}&r={rating}'.format(
            url=url, hash=hash, size=size, default=default, rating=rating)

    def generate_confirmation_token(self,expiration = 1800):
        s = Serializer(app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm':self.id})

    def confirm(self,token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        return True

    def can(self, perm):
        return self.role is not None and self.role.has_permission(perm)

    def is_administrator(self):
        return self.can(Permission.ADMIN)



class File(db.Model):
    __tablename__ = 'file'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique = True)
    path = db.Column(db.String(128), unique = True)
    # artist = db.Column(db.String(64))
    # introduction = db.Column(db.String(256))

    def __init__(self, name, path):
        self.name = name
        self.path = path
        # self.artist = artist
        # self.introduction = introduction

    def __repr__(self):
        return '<File %r>' % self.name


class NameForm(FlaskForm):
    username = StringField('用户名', validators=[Required()])
    password = PasswordField('密码', validators=[Required()])
    remember = BooleanField('记住我')
    submit = SubmitField('登录')

class LoginForm(FlaskForm):
    username = StringField('用户名', validators=[Required()])
    password = PasswordField('密码', validators=[Required()])
    password2 = PasswordField('确认密码', validators=[Required(), EqualTo('password', message = '前后密码不一致')])
    email = StringField('邮箱', validators = [Required(), Email()])
    submit = SubmitField('注册')

class EditForm(FlaskForm):
    username = StringField('用户名')
    password = PasswordField('密码')
    password2 = PasswordField('确认密码', validators=[EqualTo('password', message = '前后密码不一致')])
    email = StringField('邮箱', validators = [Email()])
    introduction = StringField('签名')
    submit = SubmitField('修改')

class UploadForm(FlaskForm):
    # artist = StringField('艺术家')
    # introduction = TextAreaField('作品简介')
    file = FileField('文件地址')
    upload = SubmitField('上传作品')



@app.before_first_request
def create_db():
  # Recreate database each time for demo
  db.drop_all()
  db.create_all()
  # try:
  #     logout_user()
  # except:
  #     pass

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/', methods = ['GET', 'POST'])
def index():
    form = NameForm()
    if form.validate_on_submit():
        session['username'] = form.username.data
        session['password'] = form.password.data
        if User.query.filter_by(name=session['username']).all() != []:
            user = User.query.filter_by(name=session['username']).first()
            if user.verify_password(session['password']):
                login_user(user, form.remember.data)
                return redirect(url_for('user', name=session['username']))
            else:
                flash('密码错误')
        else:
            flash('该用户名未注册，已跳转至注册页面')
            time.sleep(3)
            return redirect(url_for('register'))

    return render_template('index.html',
                           logform=form, username=session.get('username'), password=session.get('password'),
                           current_time = datetime.utcnow())

@app.route('/login', methods = ['GET', 'POST'])
def login():
    form = NameForm()
    if form.validate_on_submit():
        fun_login(form)

def fun_login(form):
    session['username'] = form.username.data
    session['password'] = form.password.data
    if User.query.filter_by(name = session['username']).all() != []:
        user = User.query.filter_by(name=session['username']).first()
        if user.verify_password(session['password']):
            login_user(user, form.remember.data)
            return redirect(url_for('user', name = session['username']))
        else:
            flash('密码错误')
    else:
        flash('该用户名未注册，已跳转至注册页面')
        time.sleep(3)
        return redirect(url_for('register'))
    return render_template('login.html',
                           logform = form, username = session.get('username'), password = session.get('password'),
                           current_time = datetime.utcnow())

def send_asyne_email(app,msg):
    with app.app_context():
        print(msg.body)
        mail.send(msg)

def send_email(email,title,template,**kwargs):
    print(app.config['MAIL_USERNAME'])
    msg = Message(title,sender = app.config['MAIL_USERNAME'],recipients=[email])
    msg.body = render_template(template + '.txt',**kwargs)
    # msg.html = render_template(template + '.html',**kwargs)
    thr = Thread(target=send_asyne_email, args=[app, msg])
    thr.start()

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('您已退出')
    return redirect('/')

@app.route('/secret')
@login_required
def secret():
    return '您还未登陆'

@app.route('/register', methods = ['GET', 'POST'])
def register():
    form = LoginForm()
    logform = NameForm()
    if form.validate_on_submit():
        session['username'] = form.username.data
        session['password'] = form.password.data
        session['email'] = form.email.data
        if session['username'] is not None :
            if User.query.filter_by(name = session['username']).all() != []:
                user = User.query.filter_by(name = session['username']).first()
                login_user(user)
                return redirect(url_for('user', name=session['username']))
            else:
                newUser = User(name = session['username'],
                               email = session['email'],
                               password = session['password'],
                               password_hash= generate_password_hash(session['password']))
                db.session.add(newUser)
                db.session.commit()
                token = newUser.generate_confirmation_token()

                # msg = Message("安比图书", sender='anbybooks@hotmail.com', recipients=[session['email']])
                # # msg.body 邮件正文
                # msg.body = render_template('/confirm.txt',user = newUser,token = token)
                # mail.send(msg)

                send_email(session['email'],'安比图书','/confirm',user = newUser,token = token)

                flash('请到注册邮箱对账户进行确认完成注册！')
                return redirect('/')
    return render_template('/register.html', form =form, logform = logform)

@app.route('/upload', methods=['POST', 'GET'])
def upload():
    form = UploadForm()
    logform = NameForm()
    if logform.validate_on_submit():
        fun_login(logform)
    # try:
    if request.method == 'POST':
        # try:
        f = request.files['file']
        basepath = os.path.dirname(__file__)  # 当前文件所在路径
        print(basepath)
        upload_path = os.path.join(basepath,r'upload/')  #注意：没有的文件夹一定要先创建，不然会提示没有该路径
        print(upload_path)
        isExists = os.path.exists(upload_path)
        if not isExists:
            os.makedirs(upload_path)
        path = upload_path + f.filename
        print(path)
        f.save(path)

        session['name'] = f.filename
        session['path'] = path
        # session['artist'] = form.artist.data
        # session['introduction'] = form.introduction.data
        newfile = File(name = session['name'], path = session['path'])#,introduction = session['introduction'],artist = session['artist']
        db.session.add(newfile)
        db.session.commit()
        print(File.query.all())
        flash('上传成功')
        # except:
        #     pass
        return redirect(url_for('upload'))
    # except:
    #     flash('未指定文件')
    #     return redirect(url_for('upload'))

    return render_template('/upload.html', form =form, logform = logform)

@app.route('/books', methods=['POST', 'GET'])
def list():
    logform = NameForm()
    if logform.validate_on_submit():
        fun_login(logform)
    # filedir = r'G:\anby\Flask\app\static\download'
    filedir = r'D:/anby/Flask/app/main/upload/'
    filelist = os.listdir(filedir)
    files = File.query.all()
    for file in filelist:
        filename = os.path.basename(file)

        session['name'] = filename
        session['path'] = filedir + '\\' + filename
        newfile = File(name=session['name'], path=session['path'])
        if newfile not in files:
            try:
                db.session.add(newfile)
                db.session.commit()
            except:
                db.session.rollback()
    files = File.query.all()
    print(files)
    print(filelist)
    files_real = []
    for file in files:
        if file.name in filelist:
            files_real.append(file)
    print(files)
    return render_template('/books.html',files = files_real, logform = logform )

@app.route("/download/<filename>", methods=['GET'])
def download(filename):
    if current_user.confirmed != 1:
        return '请先到注册邮箱中确认账户'
    logform = NameForm()
    file = File.query.filter_by(name = filename).first()
    books = File.query.all()
    filename = os.path.basename(file.name)
    print(filename)
    print(os.path.join('/static/download/', filename))
    if os.path.isfile(os.path.join('D:/anby/Flask/app/main/upload/', filename)):
        return send_from_directory('D:/anby/Flask/app/main/upload/', filename, as_attachment=True)

    return render_template('/books.html', files=books, logform = logform)

@app.route('/user/<name>')
def user(name):
    logform = NameForm()
    return render_template('user.html', name = name,logform = logform)

@app.route('/user-edit/<name>')
def useredit(name):
    logform = NameForm()
    user = User.query.filter_by(name=name).first()
    form = EditForm()
    if form.validate_on_submit():
        session['username'] = form.username.data
        session['password'] = form.password.data
        session['email'] = form.email.data
        session['introduction'] = form.introduction.data

        if session['username'] != '':
            user.name = session['username']
        if session['password'] != '':
            user.name = session['password']
        if session['email'] != '':
            user.name = session['email']

        db.session.add(user)
        db.session.commit()
        flash('修改成功！')
        try:
            logout_user()
        except:
            pass
        return redirect('/')
    return render_template('/user-edit.html', form=form, logform = logform)

@app.route('/confirm/<token>')
@login_required
def confirm(token):
    if current_user.confirmed:
        return redirect(url_for('index'))
    if current_user.confirm(token):
        flash('恭喜您完成注册！')
    else:
        flash('验证链接不可用或已过期')
    return redirect(url_for('index'))

@app.route('/book/chart')
def books_chart():
    return render_template('book_chart.html')

@app.route('/blog/<name>')
def blog(name):
    logform = NameForm()
    return render_template('blog.html',name = name, logform = logform)

@app.errorhandler(404)
def page_not_found(e):
    logform = NameForm()
    return render_template('404.html', logform = logform), 404

@app.errorhandler(500)
def page_not_found(e):
    return render_template('404.html'), 500

if __name__ == '__main__':
    app.run(port = 8080 ,debug=True)