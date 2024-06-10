from flask import Blueprint, request, current_app, render_template
from sqlalchemy import  or_
from flask_accept import accept
from datetime import datetime

from ...config.extensions import  db, bcrypt
from ..common.utils.constants import  Constants
from ..common.utils.decorators import authenticate, privileges
from ..common.utils.exceptions import InvalidPayload, BusinessException, NotFoundException
from ..common.utils.helpers import session_scope
from ..models.user import User, UserRole
from ..models.device import Device

auth_blueprint = Blueprint('auth', __name__)


@auth_blueprint.route('/auth/register', methods=['POST'])
@accept('application/json')
def register_user():
    # get post data
    post_data = request.get_json()
    if not post_data:
        raise InvalidPayload()
    email = post_data.get('email')
    password = post_data.get('password')
    if not password or not email:
        raise InvalidPayload()
    # check for existing user
    user = User.first(User.email == email)
    if not user:
        # add new user to db
        new_user = User(email=email, password=password)
        with session_scope(db.session) as session:
            session.add(new_user)

        # need another scope if not new_user does not exists yet
        with session_scope(db.session) as session:
            token = new_user.encode_email_token()
            new_user.email_token_hash = bcrypt.generate_password_hash(token, current_app.config.get('BCRYPT_LOG_ROUNDS')).decode()

        if not current_app.testing:
            pass
            #from app.api.common.utils.mails import send_registration_email
            #send_registration_email(new_user, token)

        # save the device
        if all(x in request.headers for x in [Constants.HttpHeaders.DEVICE_ID, Constants.HttpHeaders.DEVICE_TYPE]):
            device_id = request.headers.get(Constants.HttpHeaders.DEVICE_ID)
            device_type = request.headers.get(Constants.HttpHeaders.DEVICE_TYPE)
            with session_scope(db.session):
                Device.create_or_update(device_id=device_id, device_type=device_type, user=user)
        # generate auth token
        auth_token = new_user.encode_auth_token()
        return {
            'status': 'success',
            'message': 'Successfully registered.',
            'auth_token': auth_token,
            'email': new_user.email
        }, 201
    else:
        # user already registered, set False to device.active
        if Constants.HttpHeaders.DEVICE_ID in request.headers:
            device_id = request.headers.get(Constants.HttpHeaders.DEVICE_ID)
            device = Device.first_by(device_id=device_id)
            if device:
                with session_scope(db.session):
                    device.active = False
        raise BusinessException(message='Sorry. That user already exists.')


@auth_blueprint.route('/auth/login', methods=['GET'])
def get_login():
    return render_template('auth/login.html'), {'Content-Type': 'text/html'}


@auth_blueprint.route('/auth/login', methods=['POST'])
@accept('application/json')
def login_user():
    # get post data
    post_data = request.get_json()
    if not post_data:
        raise InvalidPayload()
    email = post_data.get('email')
    password = post_data.get('password')
    if not password:
        raise InvalidPayload()

    user = User.first_by(email=email)
    if user and bcrypt.check_password_hash(user.password, password):
        # register device if needed
        if all(x in request.headers for x in [Constants.HttpHeaders.DEVICE_ID, Constants.HttpHeaders.DEVICE_TYPE]):
            device_id = request.headers.get(Constants.HttpHeaders.DEVICE_ID)
            device_type = request.headers.get(Constants.HttpHeaders.DEVICE_TYPE)
            with session_scope(db.session):
                Device.create_or_update(device_id=device_id, device_type=device_type, user=user)
        auth_token = user.encode_auth_token()
        return {
            'status': 'success',
            'message': 'Successfully logged in.',
            'auth_token': auth_token,
            'email': user.email,
            'username': user.username,
            'given_name': user.given_name,
            'family_name': user.family_name
        }
    else:
        # user is not logged in, set False to device.active
        if Constants.HttpHeaders.DEVICE_ID in request.headers:
            device_id = request.headers.get(Constants.HttpHeaders.DEVICE_ID)
            device = Device.first_by(device_id=device_id)
            if device:
                with session_scope(db.session):
                    device.active = False
        raise NotFoundException(message='User does not exist.')


@auth_blueprint.route('/auth/logout', methods=['GET'])
@accept('application/json')
@authenticate
@privileges(roles=UserRole.USER | UserRole.USER_ADMIN | UserRole.BACKEND_ADMIN)
def logout_user(_):
    if Constants.HttpHeaders.DEVICE_ID in request.headers:
        device_id = request.headers.get(Constants.HttpHeaders.DEVICE_ID)
        device = Device.first_by(device_id=device_id)
        if device:
            with session_scope(db.session):
                device.active = False
    return {
        'status': 'success',
        'message': 'Successfully logged out.'
    }


@auth_blueprint.route('/auth/status', methods=['GET'])
@accept('application/json')
@authenticate
def get_user_status(user_id: int):
    user = User.get(user_id)
    return {
        'status': 'success',
        'data': {
            'id': user.id,
            'email': user.email,
            'username': user.username,
            'given_name': user.given_name,
            'family_name': user.family_name,
            'active': user.active,
            'email_validation_date': user.email_validation_date,
            'cellphone_validation_date': user.cellphone_validation_date,
            'created_at': user.created_at,
        }
    }


@auth_blueprint.route('/auth/password_recovery', methods=['POST'])
@accept('application/json')
def password_recovery():
    ''' creates a password_recovery_hash and sends email to user (assumes login=email)'''
    post_data = request.get_json()
    if not post_data:
        raise InvalidPayload()
    email = post_data.get('email')
    if not email:
        raise InvalidPayload()

    # fetch the user data
    user = User.first_by(email=email)
    if user:
        token = user.encode_password_token()
        with session_scope(db.session):
            user.token_hash = bcrypt.generate_password_hash(token, current_app.config.get('BCRYPT_LOG_ROUNDS')).decode()
        if not current_app.testing:
            pass
            #from project.api.common.utils.mails import send_password_recovery_email
            #send_password_recovery_email(user, token)  # send recovery email
        return {
            'status': 'success',
            'message': 'Successfully sent email with password recovery.',
        }
    else:
        raise NotFoundException(message='Login/email does not exist, please write a valid login/email')


@auth_blueprint.route('/auth/password', methods=['PUT'])
@accept('application/json')
def password_reset():
    ''' reset user password (assumes login=email)'''
    post_data = request.get_json()
    if not post_data:
        raise InvalidPayload()
    token = post_data.get('token')
    pw_new = post_data.get('password')
    if not token or not pw_new:
        raise InvalidPayload()

    # fetch the user data

    user_id = User.decode_password_token(token)
    user = User.get(user_id)
    if not user or not user.token_hash or not bcrypt.check_password_hash(user.token_hash, token):
        raise NotFoundException(message='Invalid reset. Please try again.')

    with session_scope(db.session):
        user.password = bcrypt.generate_password_hash(pw_new, current_app.config.get('BCRYPT_LOG_ROUNDS')).decode()
        user.token_hash = None
    return {
        'status': 'success',
        'message': 'Successfully reset password.',
    }


@auth_blueprint.route('/auth/password_change', methods=['PUT'])
@accept('application/json')
@authenticate
def password_change(user_id: int):
    ''' changes user password when logged in'''
    post_data = request.get_json()
    if not post_data:
        raise InvalidPayload()
    pw_old = post_data.get('old_password')
    pw_new = post_data.get('new_password')
    if not pw_old or not pw_new:
        raise InvalidPayload()

    # fetch the user data
    user = User.get(user_id)
    if not bcrypt.check_password_hash(user.password, pw_old):
        raise BusinessException(message='Invalid password. Please try again.')

    with session_scope(db.session):
        user.password = bcrypt.generate_password_hash(pw_new, current_app.config.get('BCRYPT_LOG_ROUNDS')).decode()
    return {
        'status': 'success',
        'message': 'Successfully changed password.',
    }