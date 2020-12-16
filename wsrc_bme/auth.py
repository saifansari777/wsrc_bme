import datetime

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for, jsonify, current_app
)

from flask_restful import Resource, Api
from .extensions import jwt
from .models import User, Role, Permission

from werkzeug.security import check_password_hash, generate_password_hash

from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity,  get_jwt_claims
)



bp = Blueprint('auth', __name__, url_prefix='/')

#jwt






@bp.route("/", methods=("Get", "Post"))
def index():
  return jsonify({"msg":"hello world!"}), 200



#JWT
#claims added to jwt
@jwt.user_claims_loader
def add_claims_to_access_token(username):
    user = User.objects(username=username)[0]
    print("this is user" , user,username)
    return {'role': user.role}




#register login and logout

@bp.route("/register/", methods=["POST"])
def register():
  
  if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400
  print(request)

  if request.method == 'POST':
    name = request.json.get("name", None)
    username = request.json.get("username", None)
    email = request.json.get("email", None)
    password = generate_password_hash(request.json.get("password", None))
    mobile = request.json.get("mobile", None)
    address = request.json.get("address", None)
    status = "inactive"
    created_at = datetime.datetime.utcnow()
    updated_at = datetime.datetime.utcnow()
    print("yes")
    user = User(name=name, username=username, email=email, password=password, mobile=mobile, address=address, status=status, created_at=created_at, updated_at=updated_at)
    user.save()
    return jsonify({"msg":f"sucess User {username} created"}), 200

  return jsonfiy({"meg":f"no data passed"}), 401


@bp.route("/login", methods=["POST"])
def login():
  
  if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400
  
  if request.method == "POST":
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    error = None
    
    try:
      user = User.objects(username=username)[0]
    except:
      error = "incorrect username "
      return jsonify({"meg":f"{error}"}), 400


    if not check_password_hash(user['password'], password):
      error = "incorrect password"
      return jsonify({"meg":f"{error}"}), 400
    
    if error is None:
      user["status"] = "active"
      access_token = create_access_token(identity=username)
      return jsonify(access_token=access_token), 200



@bp.route('/logout')
def logout():
    
    pass



#roles and permission decordrator



@bp.route("/create-role", methods=["POST"])
@jwt_required
def create_role():
  if request.is_json:
    name = request.json.get("name", None)
    permission = request.json.get("permission", None)

    role= Role(name=name, permission_array=permission)

    role.save()

    return jsonfiy(msg=f"role {name} created")

@bp.route("/create-permission", methods=["POST"])
@jwt_required
def create_permission():
  if not request.is_json:
        return jsonify({"msg": "Missing JSON in request"}), 400
  print(request)


  if request.method == "POST":
    name = request.json.get("name", None)

    permission = Permission(name=name)

    permission.save()

    return jsonify(msg=f"permission {name} created")