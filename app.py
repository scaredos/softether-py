# 22/12/2020
# Used for SoftEther JSON-RPC API
#
#
# Functions:
#   Get User
#   Create User
#   Delete User
#   Change Password
#   Set Expiration Date
import json
import base64
import datetime
import requests
import dateutil
from chalice import Chalice
from threading import Thread
from dateutil.relativedelta import relativedelta
from requests.auth import HTTPBasicAuth
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

app = Chalice(app_name="private-auth-api")
# Define information used for requests towards VPN API
s = requests.Session()
apiname = "VPN" #SoftEther Hub Name
apipass = "test"    #SoftEther Hub Password
s.auth = (apiname, apipass)

# Define messages to return
noErrMsg = "success"
errMsg = {"status": "failed", "error": "Incorrect Usage"}


"""
Will write all exceptions to screen and file

Args: e (Exception): The exception thrown by the code
"""


def handleException(e):
    print(e)
    with open('api-error.log', 'a+') as file:
        file.write(f'{e}\n\n\n')


"""
Attempt to recieve user information from VPN server and return it

Args:
    serverip (str): The VPN server IP address
    username (str): The username of the account to retrieve information of

Returns:
    json: User information
"""


def getUser(serverip, username):
    getUserPayload = {
  "jsonrpc": "2.0",
  "id": "rpc_call_id",
  "method": "GetUser",
  "params": {
    "HubName_str": "VPN",
    "Name_str": username
        }
    }
    res = s.post(f"https://{serverip}/api", json=getUserPayload, verify=False)
    return json.loads(res.text)


"""
Attempt to create a user on the VPN server

Args:
    serverip (str): The VPN server IP address
    username (str): The username of the account to create
    password (str): The password of the account of create
"""


def createUser(serverip, username, password, key):
    dateNow = datetime.datetime.now()
    dateNew = datetime.datetime.now() + dateutil.relativedelta.relativedelta(months=1)
    createUserPayload = {
        "jsonrpc": "2.0",
        "id": "rpc_call_id",
        "method": "CreateUser",
        "params": {
            "HubName_str": "VPN",
            "Name_str": username,
            "CreatedTime_dt": dateNow.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "ExpireTime_dt": dateNew.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "AuthType_u32": 1,
            "Auth_Password_str": password,
        },
    }
    _ = s.post(f"https://{serverip}/api", json=createUserPayload, verify=False)


"""
Attempt to delete a user from the VPN server

Args:
    serverip (str): The VPN server IP address
    username (str): The username of the account to delete
"""


def deleteUser(serverip, username):
    deleteUserPayload = {
        "jsonrpc": "2.0",
        "id": "rpc_call_id",
        "method": "DeleteUser",
        "params": {"HubName_str": "VPN", "Name_str": username},
    }
    _ = s.post(f"https://{serverip}/api", json=deleteUserPayload, verify=False)


"""
Attempt to change a user's password

Args:
    serverip (str): The VPN server IP address
    username (str): The username of the account
    password (str): The new password
"""


def changePassword(serverip, username, password):
    response = getUser(serverip, username)
    createdtime = response["result"]["CreatedTime_dt"]
    expiretime = response["result"]["ExpireTime_dt"]
    changePasswordPayload = {
        "jsonrpc": "2.0",
        "id": "rpc_call_id",
        "method": "SetUser",
        "params": {
            "HubName_str": "VPN",
            "Name_str": username,
            "CreatedTime_dt": createdtime,
            "ExpireTime_dt": expiretime,
            "AuthType_u32": 1,
            "Auth_Password_str": password,
        },
    }
    _ = s.post(f"https://{serverip}/api",
               json=changePasswordPayload, verify=False)


"""
Attempt to change the expiration date of an account

Args:
    serverip (str): The VPN server IP address
    username (str): The username of the account to modify
    expdir   (str): The new expiration date
"""


def setExpireDate(serverip, username, expdir):
    response = getUser(serverip, username)
    createdtime = response["result"]["CreatedTime_dt"]
    securehash = response["result"]["NtLmSecureHash_bin"]
    hashedkey = response["result"]["HashedKey_bin"]
    expireDatePayload = {
        "jsonrpc": "2.0",
        "id": "rpc_call_id",
        "method": "SetUser",
        "params": {
            "HubName_str": "VPN",
            "Name_str": username,
            "CreatedTime_dt": createdtime,
            "ExpireTime_dt": expdir,
            "AuthType_u32": 1,
            "NtLmSecureHash_bin": securehash,
            "HashedKey_bin": hashedkey,
        },
    }
    _ = s.post(f"https://{serverip}/api", json=expireDatePayload, verify=False)


"""
Attempt to get a list of all TCP connections on the VPN server

Args:
    serverip (str): The VPN server IP address

Returns:
    json: List of connections
"""


def listConnections(serverip):
    enumConnectionsPayload = {
        "jsonrpc": "2.0",
        "id": "rpc_call_id",
        "method": "EnumConnection",
        "params": {}
    }
    res = s.post(f'https://{serverip}/api',
                 json=enumConnectionsPayload, verify=False)
    return json.loads(res.text)


@app.route('/listConnections', methods=["GET"])  # /listConnections?sip
def listConnection():
    try:
        serverip = app.current_request.query_params["sip"]
        conns = listConnections(serverip)
        jsonObj = {
            'ConnectionNum': conns['result']['NumConnection_u32'],
            'ConnectionList': conns['result']['ConnectionList']
        }
        return jsonObj
    except Exception as e:
        handleException(e)
        return errMsg


@app.route("/createUser", methods=["GET"])  # /createUser?username&password&sip
def createApiUser():
    try:
        username = app.current_request.query_params["username"]
        password = app.current_request.query_params["password"]
        password = base64.b64decode(password).decode('ascii')
        serverip = app.current_request.query_params["sip"]
        token = app.current_request.query_params["key"]
        Thread(target=createUser, args=(serverip, username, password, token)).start()
        #createUser(serverip, username, password, key)
        return noErrMsg
    except Exception as e:
        handleException(e)
        return errMsg


@app.route("/deleteUser", methods=["GET"])  # /deleteUser?username&sip
def deleteApiUser():
    try:
        username = app.current_request.query_params["username"]
        serverip = app.current_request.query_params["sip"]
        Thread(target=deleteUser, args=(serverip, username)).start()
        return noErrMsg
    except Exception as e:
        handleException(e)
        return errMsg


# /changePassword?username&sip&password
@app.route("/changePassword", methods=["GET"])
def changePw():
    try:
        username = app.current_request.query_params["username"]
        serverip = app.current_request.query_params["sip"]
        password = app.current_request.query_params["password"]
        password = base64.b64decode(password).decode('ascii')
        changePassword(serverip, username, password)
        return noErrMsg
    except Exception as e:
        handleException(e)
        return errMsg


@app.route("/setExpDate", methods=["GET"])  # /setExpDate?username&sip&key
def setexpdate():
    try:
        username = app.current_request.query_params["username"]
        serverip = app.current_request.query_params["sip"]
        key = app.current_request.query_params["key"]
        dateNow = datetime.datetime.now()
        dateNew = datetime.datetime.now() + dateutil.relativedelta.relativedelta(months=1)
        setExpireDate(serverip, username, dateNew.strftime("%Y-%m-%dT%H:%M:%S.000"))
        return noErrMsg
    except Exception as e:
        handleException(e)
        return errMsg
