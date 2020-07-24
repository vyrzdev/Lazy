import mongoengine


class ProtectedResource(mongoengine.Document):
    name = mongoengine.StringField()
    value = mongoengine.StringField()