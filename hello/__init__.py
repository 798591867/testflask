from flask import Flask, render_template
from flask.ext.bootstrap import Bootstrap
from flask.ext.mail import Mail
from flask.ext.moment import Moment
from flask.ext.sqlalchemy import SQLAlchemy
from config import config
from flask_login import LoginManager
from flask_pagedown import PageDown

login_manager = LoginManager()
login_manager.session_protection = 'string'
login_manager.login_view = 'auth.login'
bootstrap = Bootstrap()
mail = Mail()
moment = Moment()
db = SQLAlchemy()
pagedown = PageDown()

def create_app(config_name):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)
    bootstrap.init_app(app)
    mail.init_app(app)
    moment.init_app(app)
    db.init_app(app)
    login_manager.init_app(app)
    pagedown.init_app(app)
    # todo 附加路由和自定义的错误页面
    # 跟路由
    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)
    # 用户中心路由
    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/auth')

    from .api_1_0 import api as api_1_0_blueprint
    app.register_blueprint(api_1_0_blueprint, url_prefix='/api/v1.0')
    # TODO 如果用户未登录,跳转到登录界面
    # from flask_login import login_required
    # @app.route('/secret')
    # @login_required
    # def secret():
    #     return 'Only authenticated users are allowed!'



    return app
