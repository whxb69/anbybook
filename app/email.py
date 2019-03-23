from threading import Thread

def sen_asyne_email(app,msg):
    with app.app_context():
        mail.send(msg)

def send_email(email,title,template,**kwargs):
    msg = Message(title,sender = app.config['MAIL_USERNAME'],recipients=[email])
    msg.body = render_template(template + '.txt',**kwargs)
    msg.html = render_template(template + '.html',**kwargs)
    thr = Thread(target=sen_asyne_email, args=[app, msg])
    thr.start()
    return thr