from flask import Flask, g
from .extensions import jwt , api
import os



def create_app():
    # create and configure the app
  app = Flask(__name__, instance_relative_config=True)
  app.config.from_mapping(
      SECRET_KEY='dev',
  )

  # ensure the instance folder exists
  try:
      os.makedirs(app.instance_path)
  except OSError:
      pass
  
  app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this!

  app.config['JWT_TOKEN_LOCATION'] = ['json']
  app.config['JWT_SECRET_KEY'] = 'super-secret'
  configure_extensions(app)

  # app.register_blueprint(swaggerui_blueprint)
  
  from . import auth
  app.register_blueprint(auth.bp)

  from . import bme_api
  app.register_blueprint(bme_api.bp)

  from . import dashboard
  app.register_blueprint(dashboard.bp)

  from . import models
  

  return app

def configure_extensions(app):
    """configure flask extensions"""
    jwt.__init__(app)
    api.__init__(app)