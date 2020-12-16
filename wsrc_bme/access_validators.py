import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for, jsonify, current_app
)
from .models import User, Role, Permission
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity,  get_jwt_claims
)


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view


def role_required(user_group, *role):
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
              username = get_jwt_identity()
              user = User(username=username)
              if user.role != user_group:
                return jsonify(msg=f"user {username} doen,t have required role {user_group}")
              return f(*args, **kwargs)
            
        return decorated_function
    return decorator


#permission mapping
def permission_required(permission, *permissions):
  def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
              db = init_db()
              user_role= user["role_id"]
              permission_oid = db.permission.find_one({"name":permission})["_id"]
              role_permission = user_role["permission_id"]
              print(user_role, permission_oid, role_permission)   
              if permission_oid not in role_permission :
                flash("Access Denied: you Dont Have Permission")  
                return redirect(url_for('index'))
              return f(*args, **kwargs)
            
        return decorated_function
  return decorator
