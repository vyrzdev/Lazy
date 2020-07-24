from . import models
from ..logger import rootLogger, SubLogger
accessControlLogger = SubLogger(
    "Access Control",
    parent=rootLogger
)
from ..pagination import paginateMongoQuery
from ..messaging import message, jsonExpected, missingValues, invalidPageNumber
from ..registrationModels import UserRegistration
from ..authentication.manager import AuthenticationManager
from rbac.acl import Registry
from rbac.context import IdentityContext, PermissionDenied
from functools import wraps
from flask import jsonify, Blueprint, request
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity, jwt_required


class AccessControlManager:
    def __init__(self, name):
        self.acl = Registry()
        self.context = None
        self.blueprint = Blueprint(name, __name__)
        self.current_service_resource_registration = None
        self.resource_registration = models.ResourceRegistration.objects(name="access_control").first()
        if self.resource_registration is None:
            self.resource_registration = models.ResourceRegistration(name="access_control")
            self.resource_registration.save()
        self.route_loader()

    @staticmethod
    def role_loader():
        roles = models.RoleUserStore.objects(user=AuthenticationManager.user_loader(get_jwt_identity())).values_list("role")
        return roles

    # Runtime Registrations
    # =======================
    # These functions allow for performing changes to
    # the Access Control List in-memory during application run-time.
    # ---------------------------------------------------------------
    #
    # Register Permission:
    # Adds a permission rule to the ACL based on the PermissionGrant object passed into it.
    def register_permission(self, permissionGrant):
        self.acl.allow(permissionGrant.role, permissionGrant.action, permissionGrant.resource)
        accessControlLogger.info("Registered permission!")

    # Register Role:
    # Adds a role to the ACL based on the RoleRegistration object passed into it.
    def register_role(self, roleRegistration):
        self.acl.add_role(roleRegistration)
        accessControlLogger.info(f"Registered Role: {roleRegistration.name}")

    # Permission System Initialising Functions
    # ==========================================
    # As this is a server platform, load-times are viewed as
    # less important than quick response times after initial load.
    # Thus I have opted to load all permissions into an in memory
    # store instead of doing a database lookup on every request.
    # --------------------------------------------------------------
    #
    # Initialise Access Control List:
    # Uses the below functions to initialise an in-memory permission store and validator.
    def initialise_ACL(self):
        accessControlLogger.info("Initialising the ACL")
        self.load_roles()
        self.load_resources()
        self.load_permissions()
        self.initialise_base_role()
        self.context = IdentityContext(self.acl)
        self.context.set_roles_loader(self.role_loader)
        accessControlLogger.info("Access Control List Initialised!")

    # Load Roles:
    # Loads all RoleRegistration objects from DB, applies them to ACL
    def load_roles(self):
        accessControlLogger.info("Loading Roles into memory...")
        roles = models.RoleRegistration.objects().all()
        for role in roles:
            self.acl.add_role(role)

    # Load Resources:
    # Loads all ResourceRegistration objects from DB, applies them to ACL
    def load_resources(self):
        accessControlLogger.info("Loading Resources into memory...")
        resources = models.ResourceRegistration.objects.all()
        for resource in resources:
            self.acl.add_resource(resource)

    # Load Permissions:
    # Loads all PermissionGrant objects from DB, applies them to ACL
    def load_permissions(self):
        accessControlLogger.info("Loading Permissions into memory...")
        permissions = models.PermissionGrant.objects.all()
        for permission in permissions:
            self.acl.allow(permission.role, permission.action, permission.resource)

    # Initialise Base Role:
    # Creates at run-time a role that is applied to every user, that denies every permission, so that access_control requires an explicit allowance.
    # This is an inefficient way of doing this however, and will not scale.
    # TODO: Improve Efficiency.
    def initialise_base_role(self):
        accessControlLogger.info("Initialising Base Role.")
        roleRegistration = models.RoleRegistration.objects(name="base").first()
        if roleRegistration is None:
            roleRegistration = models.RoleRegistration(name="base", pretty_name="Everyone")
            roleRegistration.save()
        self.register_role(roleRegistration)
        userRegistrations = UserRegistration.objects.all()
        for userRegistration in userRegistrations:
            roleUserStore = models.RoleUserStore.objects(user=userRegistration, role=roleRegistration).first()
            if roleUserStore is None:
                roleUserStore = models.RoleUserStore(user=userRegistration, role=roleRegistration)
                roleUserStore.save()

        # TODO: Use permission grants to make this configurable.
        resourceRegistrations = models.ResourceRegistration.objects().all()
        for resourceRegistration in resourceRegistrations:
            for action in resourceRegistration.actions:
                self.acl.deny(roleRegistration, action, resourceRegistration)

    # Resource Registration
    # =======================
    # When service are loaded, the below decorator is used to register all protected
    # endpoints, it handles authentication_old and access control for those resources.
    # ---------------------------------------------------------------------------
    #
    # Resource Endpoint Decorator:
    # Handles auth.
    def resource_endpoint(self, action, resourceName, serviceResourceRegistration=None):
        if serviceResourceRegistration is None:
            serviceResourceRegistration = self.current_service_resource_registration
        resourceRegistration = self.register_resource(action, resourceName, serviceResourceRegistration=serviceResourceRegistration)

        def decorator(func):
            @wraps(func)
            def decorated_func(*args, **kwargs):
                try:
                    verify_jwt_in_request()
                    self.context.check_permission("access", serviceResourceRegistration).check()
                    self.context.check_permission(action, resourceRegistration).check()
                    return func(*args, **kwargs)
                except PermissionDenied:
                    return jsonify({
                        "msg": "Not Authorised for Access!"
                    })

            return decorated_func

        return decorator

    # Register Resource:
    # Creates/fetches ResourceRegistration object for the resource, adds action to that registration.
    def register_resource(self, action, resourceName, serviceResourceRegistration=None):
        if serviceResourceRegistration is None:
            serviceResourceRegistration = self.current_service_resource_registration
        formattedName = f"{serviceResourceRegistration.name}.{resourceName}"
        resourceRegistration = models.ResourceRegistration.objects(name=formattedName, service=serviceResourceRegistration.service).first()
        if resourceRegistration is None:
            resourceRegistration = models.ResourceRegistration(name=formattedName, service=serviceResourceRegistration.service)
            resourceRegistration.actions.append(action)
        else:
            if action not in resourceRegistration.actions:
                resourceRegistration.actions.append(action)
            else:
                pass
        resourceRegistration.save()
        return resourceRegistration

    # Exposed Web API
    # =================
    # In the interest of organisation, the Access Control
    # manager also hosts its own API on the Flask webservice.
    # --------------------------------------------------------
    #
    # Flask Route Loader:
    # Loads all the flask routes.
    def route_loader(self):

        assign_role = self.resource_endpoint("assign", "role", serviceResourceRegistration=self.resource_registration)(self.assign_role)
        self.blueprint.add_url_rule("/assign_role/<role_name>", view_func=assign_role, methods=["GET", "POST"])
        bootstrap = jwt_required(self.bootstrap_for_testing)
        self.blueprint.add_url_rule("/bootstrap_for_testing", view_func=bootstrap, methods=["GET", "POST"])
        get_my_roles = jwt_required(self.get_my_roles)
        self.blueprint.add_url_rule("/my_roles", view_func=get_my_roles, methods=["GET", "POST"])

        # Production Endpoints.
        # Create Role
        create_role = self.resource_endpoint("create", "role", serviceResourceRegistration=self.resource_registration)(self.create_role)
        self.blueprint.add_url_rule("/create_role", view_func=create_role, methods=["POST"])
        # List Roles
        list_roles = self.resource_endpoint("list", "role", serviceResourceRegistration=self.resource_registration)(self.list_roles)
        self.blueprint.add_url_rule("/role/list", view_func=list_roles, methods=["GET", "POST"])
        # Get Role
        get_role = self.resource_endpoint("view", "role", serviceResourceRegistration=self.resource_registration)(self.get_role)
        self.blueprint.add_url_rule("/role/get/<role_id>", view_func=get_role, methods=["GET", "POST"])

        # Create Permissions
        create_permissions = self.resource_endpoint("create", "permission", serviceResourceRegistration=self.resource_registration)(self.create_permissions)
        self.blueprint.add_url_rule("/permission/create", view_func=create_permissions, methods=["POST"])
        # List Permissions
        list_permissions = self.resource_endpoint("list", "permission", serviceResourceRegistration=self.resource_registration)(self.list_permissions)
        self.blueprint.add_url_rule("/permission/list", view_func=list_permissions, methods=["GET", "POST"])

    @staticmethod
    def list_roles():
        try:
            page_number = request.args.get("page")
            if page_number is None:
                page_number = 1
            else:
                page_number = int(page_number)
        except ValueError:
            return invalidPageNumber(), 400

        roleQuerySet = models.RoleRegistration.objects()
        roleRegistrations = paginateMongoQuery(roleQuerySet, page_number=page_number)
        jsonRoleList = list()
        for roleRegistration in roleRegistrations:
            jsonRoleRepresentation = {
                "id": str(roleRegistration.id),
                "name": roleRegistration.name,
                "pretty_name": roleRegistration.pretty_name
            }
            jsonRoleList.append(jsonRoleRepresentation)
        return jsonify({
            "roles": jsonRoleList
        }), 200

    @staticmethod
    def get_role(role_id):
        roleRegistration = models.RoleRegistration.objects(id=role_id).first()
        if roleRegistration is None:
            return message("Role Not Found"), 400
        else:
            return jsonify({
                "name": roleRegistration.name,
                "pretty_name": roleRegistration.pretty_name
            })

    @staticmethod
    def list_permissions():
        role_id = request.args.get("role_id")
        if role_id is None:
            permissionsQuerySet = models.PermissionGrant.objects()
        else:
            roleRegistration = models.RoleRegistration.objects(id=role_id).first()
            if roleRegistration is None:
                return message("Role Not Found!"), 400
            else:
                permissionsQuerySet = models.PermissionGrant.objects(role=roleRegistration)
        try:
            page_number = request.args.get("page")
            if page_number is None:
                page_number = 1
            else:
                page_number = int(page_number)
        except ValueError:
            return invalidPageNumber(), 400

        permissionGrants = paginateMongoQuery(permissionsQuerySet, page_number=page_number)
        jsonPermissionList = list()
        for permissionGrant in permissionGrants:
            jsonPermissionRep = {
                "id": str(permissionGrant.id),
                "action": permissionGrant.action,
                "resource": {
                    "id": str(permissionGrant.resource.id),
                    "name": permissionGrant.resource.name
                },
            }
            jsonPermissionList.append(jsonPermissionRep)
        return jsonify({
            "permissions": jsonPermissionList
        }), 200

    def create_role(self):
        if not request.is_json:
            return jsonExpected()

        roleName = request.json.get("name")
        rolePrettyName = request.json.get("name", roleName)
        roleRegistration = models.RoleRegistration.objects(name=roleName).first()
        if roleRegistration is not None:
            return message("Role already exists!"), 400
        else:
            roleRegistration = models.RoleRegistration(name=roleName, pretty_name=rolePrettyName)
            roleRegistration.save()
            self.register_role(roleRegistration)
            return jsonify({
                "msg": "Role Created!",
                "role": {
                    "id": str(roleRegistration.id),
                    "name": roleRegistration.name,
                    "pretty_name": roleRegistration.pretty_name
                }
            })

    def create_permissions(self):
        if not request.is_json:
            return jsonExpected()

        permissionGrantList = list()
        permissionsList = request.json.get("permissions")
        for permissionJSON in permissionsList:
            role_id = permissionJSON.get("role_id")
            resource_name = permissionJSON.get("resource_name")
            action = permissionJSON.get("action")
            roleRegistration = models.RoleRegistration.objects(id=role_id).first()
            if roleRegistration is None:
                return message(f"Role ID {role_id} not found!"), 400
            resourceRegistration = models.ResourceRegistration.objects(name=resource_name).first()
            if resourceRegistration is None:
                return message(f"Resource: {resource_name} not found!"), 400
            if action not in resourceRegistration.actions:
                return message(f"Unsupported action: {action} for resource: {resource_name}"), 400
            permissionGrant = models.PermissionGrant.objects(role=roleRegistration, action=action, resource=resourceRegistration).first()
            if permissionGrant is not None:
                pass
            else:
                permissionGrant = models.PermissionGrant(role=roleRegistration, action=action, resource=resourceRegistration)
                permissionGrantList.append(permissionGrant)

        responsePermissionList = list()
        for permissionGrant in permissionGrantList:
            try:
                permissionGrant.save()
                self.register_permission(permissionGrant)
                responsePermissionList.append({
                    "role": {
                        "name": permissionGrant.role.name
                    },
                    "resource": permissionGrant.resource.name,
                    "action": permissionGrant.action
                })
            except:
                pass
        return jsonify({
            "applied_permissions": responsePermissionList
        }), 200

    @staticmethod
    def accessibleServices():
        userRegistration = AuthenticationManager.user_loader(get_jwt_identity())
        pass

    @staticmethod
    def assign_role(role_name):
        userRegistration = AuthenticationManager.user_loader(get_jwt_identity())
        roleRegistration = models.RoleRegistration.objects(name=role_name).first()
        if roleRegistration is None:
            return message("Role doesn't exist!"), 400
        else:
            newRoleUserStore = models.RoleUserStore.objects(user=userRegistration, role=roleRegistration).first()
            if newRoleUserStore is not None:
                return message("You already have this role!"), 200
            else:
                newRoleUserStore = models.RoleUserStore(user=userRegistration, role=roleRegistration)
                newRoleUserStore.save()
                return message("Role given!"), 200























    @staticmethod
    def get_my_roles():
        userRegistration = AuthenticationManager.user_loader(get_jwt_identity())
        roleUserStores = models.RoleUserStore.objects(user=userRegistration).all()
        response = list()
        for roleUserStore in roleUserStores:
            response.append({
                "role_name": roleUserStore.role.name
            })
        return jsonify(response), 200

    def bootstrap_for_testing(self):
        userRegistration = AuthenticationManager.user_loader(get_jwt_identity())
        roleRegistration = models.RoleRegistration.objects(name="admin", pretty_name="Admin").first()
        if roleRegistration is None:
            roleRegistration = models.RoleRegistration(name="admin", pretty_name="Admin")
            roleRegistration.save()
            self.register_role(roleRegistration)
        roleUserStore = models.RoleUserStore.objects(user=userRegistration, role=roleRegistration).first()
        if roleUserStore is None:
            roleUserStore = models.RoleUserStore(user=userRegistration, role=roleRegistration)
            roleUserStore.save()
        serviceResourceRegistration = models.ResourceRegistration.objects(name="access_control").first()
        permissionGrant = models.PermissionGrant.objects(action="access", role=roleRegistration, resource=serviceResourceRegistration).first()
        if permissionGrant is None:
            permissionGrant = models.PermissionGrant(action="access", role=roleRegistration, resource=serviceResourceRegistration)
            permissionGrant.save()
            self.register_permission(permissionGrant)
        resourceRegistration = models.ResourceRegistration.objects(name="access_control.role").first()
        for action in resourceRegistration.actions:
            permissionGrant = models.PermissionGrant.objects(action=action, role=roleRegistration, resource=resourceRegistration).first()
            print(f"Added action {action}")
            if permissionGrant is None:
                permissionGrant = models.PermissionGrant(action=action, role=roleRegistration, resource=resourceRegistration)
                permissionGrant.save()
                self.register_permission(permissionGrant)
        resourceRegistration = models.ResourceRegistration.objects(name="access_control.permission").first()
        for action in resourceRegistration.actions:
            permissionGrant = models.PermissionGrant.objects(action=action, role=roleRegistration, resource=resourceRegistration).first()
            print(f"Added action {action}")
            if permissionGrant is None:
                permissionGrant = models.PermissionGrant(action=action, role=roleRegistration, resource=resourceRegistration)
                permissionGrant.save()
                self.register_permission(permissionGrant)
        return message("Boostrapped!")