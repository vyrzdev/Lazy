from flask import Blueprint, request, jsonify
import requests
from flask_jwt_extended import create_access_token, create_refresh_token, get_jti, get_raw_jwt, jwt_refresh_token_required, get_jwt_identity, jwt_required
from . import models
from ..registrationModels import UserRegistration
from ..protectedModels import ProtectedResource
from ..messaging import message, jsonExpected, missingValues, error
import datetime


class AuthenticationManager:
    def __init__(self, name, jwt):
        self.name = name
        self.jwt = jwt
        self.blueprint = Blueprint(name, __name__)
        self.loadRoutes()

    # Defining utility methods
    @staticmethod
    def generateAccessToken(identity, expiryTimeDelta=None, claimsDict=None):
        return create_access_token(identity=identity, expires_delta=expiryTimeDelta, user_claims=claimsDict)

    @staticmethod
    def generateRefreshToken(identity, expiryTimeDelta=None, claimsDict=None):
        token = create_refresh_token(identity=identity, expires_delta=expiryTimeDelta, user_claims=claimsDict)
        tokenJTI = get_jti(token)
        currentTime = datetime.datetime.now()
        expiryTime = currentTime + expiryTimeDelta
        refreshTokenRegistration = models.RefreshTokenRegistration(user=AuthenticationManager.user_loader(identity), tokenJTI=tokenJTI, expireAt=expiryTime)
        refreshTokenRegistration.save()
        return token

    @staticmethod
    def user_loader(identity):
        userRegistration = UserRegistration.objects(id=identity).first()
        return userRegistration

    @staticmethod
    def getRefreshTokenRegistration(token):
        tokenJTI = get_jti(token)
        refreshTokenRegistration = models.RefreshTokenRegistration.objects(tokenJTI=tokenJTI).first()
        return refreshTokenRegistration

    @staticmethod
    def refresh_token_is_valid(token):
        tokenReg = AuthenticationManager.getRefreshTokenRegistration(token)
        if tokenReg is None:
            return False

        if tokenReg.expireAt < datetime.datetime.now():
            tokenReg.delete()
            return False
        return True

    @staticmethod
    def getUsersTokenRegistrations(userRegistration):
        return models.RefreshTokenRegistration.objects(user=userRegistration).all()

    @staticmethod
    def invalidateUserRefreshTokens(userRegistration):
        tokenRegistrations = AuthenticationManager.getUsersTokenRegistrations(userRegistration)
        for token in tokenRegistrations:
            token.invalidate()

    @staticmethod
    def getUserRegistrationFromCredentials(email, password):
        userRegistration = UserRegistration.objects(email=email).first()
        if userRegistration is None:
            return None

        if userRegistration.checkPassword(password):
            return userRegistration
        else:
            return None

    @staticmethod
    def captchaCodeValid(captchaCode):
        siteKey = ProtectedResource.objects(name="CAPTCHA_SECRET_KEY").first().value
        r = requests.post("https://www.google.com/recaptcha/api/siteverify", json={
            "secret": siteKey,
            "response": captchaCode
        })
        return r.json.get("success")

    # Defining flask route loader
    def loadRoutes(self):
        self.blueprint.add_url_rule("/get_tokens", view_func=self.get_tokens, methods=["POST"])
        self.blueprint.add_url_rule("/refresh_token", view_func=self.get_new_access_token, methods=["GET", "POST"])
        self.blueprint.add_url_rule("/invalidate_all_tokens", view_func=self.invalidate_all_tokens, methods=["GET", "POST"])
        self.blueprint.add_url_rule("/invalidate_token", view_func=self.invalidate_token, methods=["POST"])
        self.blueprint.add_url_rule("/list_tokens", view_func=self.list_tokens, methods=["GET", "POST"])

    # Defining flask routes
    # ---------------------------------------------------------------
    #
    # Get Tokens:
    # A route that provides Access, and Refresh tokens upon submission of valid credentials in the format:
    # {
    #   "credentials": {
    #       "email": "foo@foo.com",
    #       "password": "password123",
    #       "captchaCode": "isofsitbjfpeqsjf32u209094rwklw09u032r"
    #   }
    # }
    def get_tokens(self):
        if not request.is_json:
            return jsonExpected()

        credentials = request.json.get("credentials")
        if not isinstance(credentials, dict):
            return jsonExpected()

        if credentials is None:
            return missingValues("credentials:", "email", "password")

        email = credentials.get("email")
        password = credentials.get("password")
        captchaCode = request.json.get("captchaCode")
        if email is None:
            return missingValues("email")
        if password is None:
            return missingValues("password")
        if captchaCode is None:
            # return missingValues("captchaCode") Captcha disabled for testing.
            pass

        userRegistration = self.getUserRegistrationFromCredentials(email, password)
        if userRegistration is None:
            return error("Email or password invalid.", 103), 400
        # elif not self.captchaCodeValid(captchaCode): Captcha disabled for testing
            # return error("Invalid captcha!", 102), 400
        else:
            accessToken = self.generateAccessToken(str(userRegistration.id), expiryTimeDelta=datetime.timedelta(seconds=50))
            refreshToken = self.generateRefreshToken(str(userRegistration.id), expiryTimeDelta=datetime.timedelta(hours=2))
            return jsonify({
                "access_token": accessToken,
                "refresh_token": refreshToken
            }), 200

    # Refresh Token:
    # A route that provides a new Access token, upon access of the route with a valid Refresh token.
    @jwt_refresh_token_required
    def get_new_access_token(self):
        rawJWT = request.headers.get("Authorization").split(" ")[1]
        if not self.refresh_token_is_valid(rawJWT):
            return error("Invalid Refresh Token!", 101), 400
        else:
            accessToken = self.generateAccessToken(get_jwt_identity(), expiryTimeDelta=datetime.timedelta(seconds=50))
            return jsonify({
                "access_token": accessToken
            }), 200

    # Invalidate Tokens:
    # A route that invalidates all of the user accessing its Refresh tokens.
    @jwt_required
    def invalidate_all_tokens(self):
        userRegistration = self.user_loader(get_jwt_identity())
        print("Got User Reg!")
        self.invalidateUserRefreshTokens(userRegistration)
        print("Failed here!")
        return message("All Refresh tokens have been invalidated"), 200

    # Invalidate Specific Token:
    # A route that invalidates a specific token, based on the token's ID, provided the user actually owns that token of course.
    # Expects a POST request in the format:
    # {
    #   "token_jti": "546782903461254861429649"
    # }
    @jwt_required
    def invalidate_token(self):
        if not request.is_json:
            return jsonExpected()
        elif request.json.get("token_jti") is None:
            return missingValues("token_jti")
        else:
            userRegistration = self.user_loader(get_jwt_identity())
            refreshTokenRegistration = models.RefreshTokenRegistration.objects(tokenJTI=request.json.get("token_jti"), user=userRegistration).first()
            if refreshTokenRegistration is None:
                return error("No token with that JTI found", 104), 400
            else:
                refreshTokenRegistration.invalidate()
                return message("Token invalidated!"), 200

    # List Tokens:
    # A route which lists all the tokens a user has active in the format:
    # {
    #     "tokens": [
    #         {
    #             "tokenJTI": "4356879021428734608139",
    #             "expiresAt": "134567813312"   <---- UTC Timestamp of Expiry
    #         }
    #     ]
    # }
    @jwt_required
    def list_tokens(self):
        userRegistration = self.user_loader(get_jwt_identity())
        refreshTokenRegistrations = self.getUsersTokenRegistrations(userRegistration)
        response = {
            "tokens": list()
        }
        for refreshTokenRegistration in refreshTokenRegistrations:
            response["tokens"].append({
                "tokenJTI": refreshTokenRegistrations.tokenJTI,
                "expiresAt": refreshTokenRegistration.expireAt.timestamp
            })
        return jsonify(response), 200
