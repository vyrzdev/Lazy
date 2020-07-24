from flask import jsonify


def message(messageText):
    return jsonify({
        "msg": messageText,
        "error": False,
    })


def jsonExpected():
    return error("JSON Expected!", 1), 400


def missingValues(*args):
    return message(f"Missing Fields: {','.join(args)}"), 400


def invalidPageNumber():
    return message("Invalid Page Number!")


def error(message, errorCode):
    return jsonify({
        "error": True,
        "msg": message,
        "errorCode": errorCode,
    })
