import datetime
import json
from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for, jsonify, current_app
)

from flask_restful import Resource, reqparse
from .extensions import jwt, api, swag
from .models import User, Role, Permission

from werkzeug.security import check_password_hash, generate_password_hash

from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity,  get_jwt_claims
)

bp = Blueprint('api', __name__, url_prefix="/api")

def format_obj(obj):

  obj_dict = obj.to_mongo().to_dict()
  obj_pretty = json.loads(json.dumps(obj_dict, indent=4, default=str))

  return  obj_pretty


def get_object_or_404(klass, *args, **kwargs):
  try:
    obj = klass.objects.get(**kwargs)
    obj_dict = obj.to_mongo().to_dict()
    print(type(obj_dict), obj_dict.items())

    arranged_data = {}

    for key, value in obj_dict.items():
      print(key, value)
      if key != "password":
        arranged_data[key] = value
    
    print(arranged_data, arranged_data.__class__.__name__)
    
    data = json.loads(json.dumps(arranged_data, indent=4, default=str))
    
    response = jsonify(data)
    response.status_code = 200
    return response
  except Exception as e:
    return jsonify(error=f"{e}"), 404

def format_queryset(qs):

  try:
    query_set = qs.objects
    query_set_list = [*query_set]
    query_set_data = []
    print(query_set_list, len(query_set_list))
  
    
    for obj in query_set_list:
      obj_format = obj.to_mongo().to_dict()
      obj_dict = {}
      for key in obj_format:
        if key != "password":
          obj_dict[key] = obj_format[key]

      query_set_data.append(obj_dict)

    print(query_set_data)
    query_set_dict = json.loads(json.dumps(query_set_data, indent=4, default=str))
    return query_set_dict, 200
  except Exception as e:
    return jsonify(error=f"{e}"), 404


parser = reqparse.RequestParser()


class Users(Resource):
  # @swag.operation(
  #     user='Users',
  #     responseClass=User.__name__,
  #     nickname='upload',
  #     parameters=[
  #         {
  #           "name": "body",
  #           "description": "blueprint object that needs to be added. YAML.",
  #           "required": True,
  #           "allowMultiple": False,
  #           "dataType": User.__name__,
  #           "paramType": "body"
  #         }
  #       ],
  #     responseMessages=[
  #         {
  #           "code": 201,
  #           "message": "Created. The URL of the created blueprint should be in the Location header"
  #         },
  #         {
  #           "code": 405,
  #           "message": "Invalid input"
  #         }
  #       ]
  #     )
  def get(self, username):
    user  = get_object_or_404(User, username=username)
    
    return user

  @swag.operation(
    user='delte Users',
    responseClass=User.__name__,
    nickname='delete',
    parameters=[
        {
          "name": "body",
          "description": "blueprint object that needs to be added. YAML.",
          "required": True,
          "allowMultiple": False,
          "dataType": User.__name__,
          "paramType": "body"
        }
      ],
    responseMessages=[
        {
          "code": 201,
          "message": "Created. The URL of the created blueprint should be in the Location header"
        },
        {
          "code": 405,
          "message": "Invalid input"
        }
      ]
    )
  def delete(self, username):
    
    try:
      user  = User.objects(username=username)
      user.delete()
    except Exception as e:
      return jsonify(error=f"{e}"), 404

    return jsonify(msg=f"successfully deleted user {username}"), 204

  def put(self, username):
    user_qs  = User.objects(username=username)
    user = user_qs.get(username=username)
    
    
    args = parser.parse_args()
    print(user)
    name = request.form['name'] or user.name
    address = request.form['address'] or user.address
    mobile = request.form['mobile'] or user.mobile
    email = request.form['email'] or user.email

    user.name = name
    user.address= address
    user.mobile = mobile
    user.email = email
    
    try:
      user.save()
    except Exception as e: 
      return jsonify(error=f"{e}"), 404

    user_pretty = format_obj(user)
    return user_pretty, 201
    

class UserList(Resource):

  def get(self):
    users = format_queryset(User)
    
    return users

  def post(self):
   
    name = request.form['name']
    username = request.form['username']
    password = generate_password_hash(request.form['password']) 
    address = request.form['address'] 
    mobile = request.form['mobile']
    email = request.form['email']

    user = User(name=name,username=username, password=password, email=email, address=address, mobile=mobile, status="inactive")
    
    try:
      user.save()
    except Exception as e: 
      return jsonify(error=f"{e}"), 404

    
    user_pretty = format_obj(user)

    return user_pretty, 201

class Roles(Resource):

  def get(self, rolename):
    try:
      role  = Role.objects.get(name=rolename)
    except Exception as e:
      return jsonify(error=f"{e}"), 404

    role_pretty = format_obj(role)

    return role_pretty, 200

  def put(self, rolename):
    role_qa = Role.objects(name=rolename)
    role = role_qa.get(name=rolename)

    permission_array = request.form['permission_array']

    role.permission_array = permission_array
    
    try:
      role.save()
    except Exception as e:
      return jsonify(error=f"{e}"), 404

    role_pretty = format_obj(role)
    return role_pretty, 200

  def delete(self, rolename):
    
    try:
      role = Role.objects(name=rolename)
    except Exception as e:
      return jsonify(error=f"{e}"), 404

    role.delete()

    return {"msg":"role deleted"}, 200

  


class RoleList(Resource):

  def get(self):
    role = format_queryset(Role)
    return role
  
  def post(self):
    
    name = request.form['name']
    permission_array = request.form.getlist('permission_array[]')
    print(permission_array)
    role = Role(name=name, permission_array=permission_array)

    try:
      role.save()
    except Exception as e:
      return jsonify(error=f"{e}"), 404

    role_pretty = format_obj(role)
    return role_pretty, 201


class Permissions(Resource):

  def get(self, permissionname):
    
    try:
      permission  = Permission.objects.get(name=permissionname)
    except Exception as e:
      return jsonify(error=f"{e}"), 404

    permission_pretty = format_obj(permission)

    return permission_pretty, 200

  def put(self, permissionname):
    permission_qa = Permission.objects(name=permissionname)
    permission = permission_qa.get(name=permissionname)

    name = request.form['name']

    permission.name = name

    try:
      permission.save()
    except Exception as e:
      return jsonify(error=f"{e}"), 404

    permission_pretty = format_obj(permission)
    return permission_pretty, 201

  def delete(self, permissionname):
    
    try:
      permission = Permission.objects.get(name=permissionname)
    except Exception as e:
      return jsonify(error=f"{e}"), 404
    
    permission.delete()

    return {"msg":"permission deleted"}, 200


class PermissionList(Resource):

  def get(self):
    permission = format_queryset(Permission)
    return permission

  def post(self):
    name = request.form['name']
    permission = Permission(name=name)

    try:
      permission.save()
    except Exception as e:
      return jsonify(error=f"{e}"), 404

    permission_pretty = format_obj(permission)
    return permission_pretty, 201
  
api.add_resource(Users, '/user/<username>')
api.add_resource(UserList, '/users')
api.add_resource(Roles, '/role/<rolename>')
api.add_resource(RoleList, '/roles')
api.add_resource(Permissions, '/permission/<permissionname>')
api.add_resource(PermissionList, '/permissions')