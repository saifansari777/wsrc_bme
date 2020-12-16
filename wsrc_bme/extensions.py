from flask_jwt_extended import JWTManager
from flask_swagger_ui import get_swaggerui_blueprint
from flask_restful import Api
from flask_restful_swagger import swagger


jwt = JWTManager()
api = swagger.docs(Api(), apiVersion='0.1')
swag =swagger



SWAGGER_URL = '/api/docs'   #URL for exposing Swagger UI (without trailing '/')
API_URL = 'http://petstore.swagger.io/v2/swagger.json' 


swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,  # Swagger UI static files will be mapped to '{SWAGGER_URL}/dist/'
    API_URL,
    config={  # Swagger UI config overrides
        'app_name': "wsrc_bme"
    },
    oauth_config={  # OAuth config. See https://github.com/swagger-api/swagger-ui#oauth2-configuration .
       'clientId': "wsrc_bme",
       'clientSecret': "your-client-secret-if-required",
       'realm': "your-realms",
       'appName': "wsrc",
       'scopeSeparator': " ",
       'additionalQueryStringParams': {'test': "hello"}
    }
)