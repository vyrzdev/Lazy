import mongoengine

from .. import registrationModels
from ..registrationModels import ServiceRegistration


class RoleRegistration(mongoengine.Document):
    name = mongoengine.StringField()
    pretty_name = mongoengine.StringField()


class ResourceRegistration(mongoengine.Document):
    name = mongoengine.StringField()
    actions = mongoengine.ListField(default=list(["access"]))
    service = mongoengine.ReferenceField(ServiceRegistration, required=False)


class PermissionGrant(mongoengine.Document):
    action = mongoengine.StringField(required=True)
    resource = mongoengine.ReferenceField(ResourceRegistration, required=True)
    role = mongoengine.ReferenceField(RoleRegistration, required=True)


class RoleUserStore(mongoengine.Document):
    user = mongoengine.ReferenceField(registrationModels.UserRegistration)
    role = mongoengine.ReferenceField(RoleRegistration)


