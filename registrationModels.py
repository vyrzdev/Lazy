import mongoengine
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime


# A service class | Lets the API load new service easily, and allows service to be pluggable after registraton.
class ServiceRegistration(mongoengine.Document):
    name = mongoengine.StringField()
    pretty_name = mongoengine.StringField()
    url_prefix = mongoengine.StringField()
    webappUrl = mongoengine.URLField()
    persistentIdentifier = mongoengine.StringField(required=True)


# The base user class | Used to reference service specific data, handles authorization to individual service.
class UserRegistration(mongoengine.Document):
    email = mongoengine.EmailField()
    passwordHash = mongoengine.StringField()
    lastPasswordChange = mongoengine.IntField(default=datetime.now().timestamp())

    def checkPassword(self, password):
        return check_password_hash(self.passwordHash, password)

    def setPassword(self, password):
        print("Updated last password change!")
        self.lastPasswordChange = datetime.now().timestamp()
        print(f"To: {self.lastPasswordChange}")
        self.passwordHash = generate_password_hash(password)

