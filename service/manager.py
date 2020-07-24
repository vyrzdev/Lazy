from ..registrationModels import ServiceRegistration
from ..access_control.models import ResourceRegistration
from ..logger import rootLogger, SubLogger
serviceManagerLogger = SubLogger(
    "Service Manager",
    parent=rootLogger
)
from flask import Blueprint
import os
from importlib import import_module


class ServiceManager:
    def __init__(self, flaskApp, accessControlRegistry):
        self.flaskApp = flaskApp
        self.accessControlRegistry = accessControlRegistry
        self.imported_all = False
        self.activeServices = list()

    # TODO: Write code to recursively delete any permission registrations, user objects, etc from the db.
    def cleanService(self, packageName):
        pass

    def serviceSafetyCheck(self):
        activeServiceIdentifiers = [serviceClass.persistentUniqueIdentifier for serviceClass in self.activeServices]
        serviceIdentifiersDatabased = ServiceRegistration.objects().values_list("persistentUniqueIdentifier")
        for serviceIdentifier in serviceIdentifiersDatabased:
            if serviceIdentifier not in activeServiceIdentifiers:
                serviceReg = ServiceRegistration.objects(persistenUniqueIdentifier=serviceIdentifier).first()
                serviceManagerLogger.error(f"Alert! The service: {serviceReg.name} was not found!")
                serviceManagerLogger.error("When service go missing, dangerous things happen!")
                serviceManagerLogger.error("Their permissions fuck everything up!")
                serviceManagerLogger.error("Press enter to stop the program, type idontcare to continue anyway, type clean to delete the service and all of its related permissions.")
                choice = None
                while choice not in ["", "idontcare", "clean"]:
                    choice = input(": ")
                if choice == "":
                    exit()
                elif choice == "idontcare":
                    pass
                elif choice == "clean":
                    self.cleanService(serviceReg.name)
                    serviceManagerLogger.error('Not Yet Implemented!')
                    exit()
            else:
                pass

    def registerService(self, serviceClass):
        serviceName = serviceClass.name
        servicePrettyName = serviceClass.pretty_name
        serviceManagerLogger.info(f"Started initialising service: {servicePrettyName}")
        url_prefix = serviceClass.url_prefix
        webappUrl = "https://example.com"
        servicePersistentIdentifier = serviceClass.persistentUniqueIdentifier
        if servicePersistentIdentifier is None:
            serviceManagerLogger.error("PANIC! You must configure a persistentUniqueIdentifier in your class variables!")
            serviceManagerLogger.error("No two services should ever have the same identifier!")
            serviceManagerLogger.error("This identifier should NEVER change. The only time it can be allowed to change is in the event of a total server reset.")
            # FIXME: This is a potential vulnerability, what if a big plugin just changed its unique identifier and pushed an update?
            # They could completely destroy the permissions systems of every site using them.
            exit()
        serviceRegistration = ServiceRegistration.objects(persistentIdentifier=servicePersistentIdentifier).first()
        if serviceRegistration is None:
            serviceRegistration = ServiceRegistration(name=serviceName, pretty_name=servicePrettyName, url_prefix=url_prefix, persistentIdentifier=servicePersistentIdentifier, webappUrl=webappUrl)
            serviceRegistration.save()
        serviceResourceRegistration = ResourceRegistration.objects(service=serviceRegistration).first()
        if serviceResourceRegistration is None:
            serviceResourceRegistration = ResourceRegistration(name=f"{servicePersistentIdentifier}", service=serviceRegistration)
            serviceResourceRegistration.save()
        serviceInstance = serviceClass(serviceName, serviceRegistration=serviceRegistration, serviceResourceRegistration=serviceResourceRegistration, accessControlManagerInstance=self.accessControlRegistry)
        self.flaskApp.register_blueprint(serviceInstance.flaskServiceInstance, url_prefix=serviceRegistration.url_prefix)
        self.activeServices.append(serviceInstance)

        serviceManagerLogger.info(f"Finished initialising service: {serviceRegistration.pretty_name}")