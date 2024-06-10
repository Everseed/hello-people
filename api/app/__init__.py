import os
from flask import Config
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_mail import Mail
from celery import Celery

from .api.common.base_definitions import BaseFlask
from .config.config import DevelopmentConfig
from .config.extensions import db, bcrypt, migrate, mail

# flask config
conf = Config(root_path=os.path.dirname(os.path.realpath(__file__)))
conf.from_object(os.getenv('APP_SETTINGS') or "app.config.config.DevelopmentConfig")


def create_app():
    # instantiate the app
    app = BaseFlask(__name__)
    # configure sentry
    # if not app.debug and not app.testing:
    # pass
    #    global sentry
    #    sentry = Sentry(app, dsn=app.config['SENTRY_DSN'])
    # set up extensions
    setup_extensions(app)
    # registrations blueprints
    from .api.v1.auth import auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/v1')
    from .api.common.utils import exceptions
    from .api.common import error_handlers
    app.register_error_handler(exceptions.InvalidPayload, error_handlers.handle_exception)
    app.register_error_handler(exceptions.BusinessException, error_handlers.handle_exception)
    app.register_error_handler(exceptions.UnauthorizedException, error_handlers.handle_exception)
    app.register_error_handler(exceptions.ForbiddenException, error_handlers.handle_exception)
    app.register_error_handler(exceptions.NotFoundException, error_handlers.handle_exception)
    app.register_error_handler(exceptions.ServerErrorException, error_handlers.handle_exception)
    if not app.debug and not app.testing:
        app.register_error_handler(Exception, error_handlers.handle_general_exception)
    return app


def setup_extensions(app):
    db.init_app(app)
    bcrypt.init_app(app)
    migrate.init_app(app, db)
    mail.init_app(app)


# noinspection PyPropertyAccess
def make_celery(app):
    app = app or create_app()
    pass
    # celery = Celery(__name__, broker=app.config['CELERY_BROKER_URL'], include=['project.tasks.mail_tasks', 'project.tasks.push_notification_tasks',
    #                                                                            'project.tasks.twilio_tasks'], backend=app.config['CELERY_RESULT_BACKEND'])
    # celery.conf.update(app.config)
    # TaskBase = celery.Task
    # class ContextTask(TaskBase):
    #     abstract = True
    #     def __call__(self, *args, **kwargs):
    #         with app.app_context():
    #             return TaskBase.__call__(self, *args, **kwargs)
    # celery.Task = ContextTask
    # return celery


app = create_app()
# celery = make_celery(app)
