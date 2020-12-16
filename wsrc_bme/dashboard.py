from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for, jsonify
)

from .models import User, Role, Permission

from werkzeug.security import check_password_hash, generate_password_hash

from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)

from .access_validators import role_required

bp = Blueprint('dashboard', __name__, url_prefix='/dashboard/')



@bp.route("/", methods=["GET"])
@jwt_required
def dashboard():
  return jsonify({"msg":f"sucessfully logged in as {get_jwt_identity}"})


@bp.route("/admin/", methods=["GET"])
@role_required("admin")
@jwt_required
def admin_dashboard():
  return jsonify({"msg":f"sucessfully logged in as {get_jwt_identity}"})