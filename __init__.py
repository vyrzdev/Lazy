import mongoengine
import schedule
import threading
import time
from flask import Flask
from flask_jwt_extended import JWTManager
from .logger import rootLogger

from . import registrationModels, protectedModels, authentication, access_control, service


class APIServer:
    def __init__(self, appSecretKey):
        self.app = Flask(__name__)
        rootLogger.debug("Flask Instance Created!")
        self.app.config["SECRET_KEY"] = appSecretKey
        mongoengine.connect()
        rootLogger.debug("Mongoengine DB connection established")
        self.jwt = JWTManager(self.app)
        rootLogger.debug("Token Manager Initialised.")
        self.authenticationManager = authentication.manager.AuthenticationManager("authentication", self.jwt)
        rootLogger.debug("Authentication Subsystem Started")
        self.accessControlManager = access_control.manager.AccessControlManager("access_control")
        rootLogger.debug("Access Control Subsystem Started")
        self.app.register_blueprint(self.authenticationManager.blueprint, url_prefix="/authentication")
        self.app.register_blueprint(self.accessControlManager.blueprint, url_prefix="/access_control")
        rootLogger.debug("Auth and Access Ctrl tied to public endpoints!")
        self.serviceManager = service.manager.ServiceManager(self.app, self.accessControlManager)
        rootLogger.debug("Service Manager Initialised.")
        self.app.after_request(self.after_request)

        # Spawn a scheduler thread
        def runPendingJobs():
            while True:
                time.sleep(1)
                schedule.run_pending()
        threading.Thread(target=runPendingJobs, daemon=True).start()
        rootLogger.info("Schedule Thread Started!")

    def loadService(self, serviceClass):
        self.serviceManager.registerService(serviceClass)

    @staticmethod
    def after_request(response):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "*"
        return response

    def run(self, **kwargs):
        self.accessControlManager.initialise_ACL()
        rootLogger.info("Lazy Fully Initialised! Starting!")
        self.app.run(**kwargs)
