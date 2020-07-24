import mongoengine

from ..registrationModels import UserRegistration


class RefreshTokenRegistration(mongoengine.Document):
    user = mongoengine.ReferenceField(UserRegistration)
    tokenJTI = mongoengine.StringField()
    expireAt = mongoengine.DateTimeField()

    def invalidate(self):
        self.delete()
