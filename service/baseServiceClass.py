from flask import Blueprint
import mongoengine
from ..registrationModels import UserRegistration


class BaseService:
    userDataClass = None
    name = "unconfiguredService"
    pretty_name = "Unconfigured service ~ change me in the service class's class variables!"
    url_prefix = "/unconfigured"
    webappUrl = "example.com"
    persistentUniqueIdentifier = None

    def __init__(self, serviceName, serviceRegistration, serviceResourceRegistration, accessControlManagerInstance):
        self.flaskServiceInstance = Blueprint(serviceName, __name__)
        self.serviceRegistration = serviceRegistration
        self.serviceResourceRegistration = serviceResourceRegistration
        self.accessCtrlInstance = accessControlManagerInstance
        self.loadEndpoints()

    def __init_subclass__(cls, **kwargs):
        cls.ClassInitialise()

    @staticmethod
    def loadEndpoints():
        print("Alert!!! The service's loadEndpoints function hasn't been defined!!!")
        print("Quitting!")
        exit()

    def resourceEndpoint(self, view_func, resource_name, action="access", endpoint=None, methods=None):
        if endpoint is None:
            endpoint = f"/{resource_name}/{action}"
        viewFunc = view_func
        decoratedViewFunction = self.accessCtrlInstance.resource_endpoint(action, resource_name, serviceResourceRegistration=self.serviceResourceRegistration)(viewFunc)
        self.flaskServiceInstance.add_url_rule(endpoint, view_func=decoratedViewFunction, methods=methods)

    @classmethod
    def userDataLoader(cls, userRegistration):
        return cls.userDataClass.objects(userReg=userRegistration).first()

    @classmethod
    def ClassInitialise(cls):
        class BaseUserClass(mongoengine.Document):
            userReg = mongoengine.ReferenceField(UserRegistration, required=True)
            exampleData1 = mongoengine.StringField()

        cls.userDataClass = BaseUserClass
