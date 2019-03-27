import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    """Base config class."""
    SECRET_KEY="powerful secretkey",
    WTF_CSRF_SECRET_KEY="a csrf secret key",
    SQLALCHEMY_DATABASE_URI = r'sqlite:///G:\anby\Flask\database\\blog.db',
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True

    @staticmethod
    def init_app(app):
        pass

class DevelopmentConfig(Config):
    MAIL_SERVER='smtp.office365.com',
    MAIL_PROT=587,
    MAIL_USE_TLS=True,
    MAIL_USE_SSL=False,
    MAIL_DEBUG=True,
    MAIL_USERNAME = 'anbybooks@hotmail.com',
    MAIL_PASSWORD = '**********'

config = {
    'development':DevelopmentConfig
}

