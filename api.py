import json
from datetime import datetime, timedelta
import socket
from threading import Thread

import pymongo
import requests
from fastapi import Depends, FastAPI, HTTPException, status, Request
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
import matplotlib.pyplot as plt
import random

from scriptAgent import Scripts as agentPE
from systems import QRadar, Pagerduty, FortiOS, Wazuh, ReaQta, Sophos
from functions import Check
from mail import Email
from auth import Auth, User as U
from toolCTI import Feeds
from report import Report
import Config

requests.packages.urllib3.disable_warnings()

SECRET_KEY = Config.SECRET_KEY
ALGORITHM = Config.ALGORITHM
ACCESS_TOKEN_EXPIRE_MINUTES = Config.Duration_session  # Durata sessione
client = pymongo.MongoClient(Config.DBAUTHSTR)
db = client["feedsTI"]

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
tags_metadata = [
    {"name": "Auth", "description": "APIs for authentication"},
    {"name": "Management", "description": "APIs for management users and platform"},
    {"name": "Customer", "description": "APIs for management customers"},
    {"name": "CTI", "description": "APIs for cti"},
    {"name": "Health", "description": ""},
    {"name": "Fortinet", "description": "APIs for communicate  with the Fortinet"},
    {"name": "PagerDuty", "description": "APIs for communicate  with PagerDuty"},
    {"name": "SIEM", "description": "APIs for communicate  with the SIEM (QRadar, Splunk and Elasticsearch)"},
    {"name": "QRadar", "description": "APIs for communicate  with the QRadar"},
    {"name": "Firewall", "description": "APIs for communicate  with the Firewall (Fortinet)"},
    {"name": "ReaQta", "description": "APIs for communicate  with the ReaQta"},
    {"name": "Sophos", "description": "APIs for communicate  with the ReaQta"},
    {"name": "Wazuh", "description": "APIs for communicate  with the Wazuh"},
    {"name": "Merge", "description": ""},
    {"name": "Tasks", "description": "APIs for create and management the task"},
    {"name": "Case", "description": ""},
    {"name": "Report", "description": ""},
    {"name": "Engine", "description": "APIs for communicate  with the Engine"},
    {"name": "CHAT", "description": ""},
    {"name": "Notification", "description": ""},
    {"name": "Other", "description": ""}
]

app = FastAPI(openapi_tags=tags_metadata)

"""
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
"""

def normalizer(list):
    newList = []
    for l in list:
        del l["_id"]
        newList.append(l)
    return newList


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = U.TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = Auth.getUser(token_data.username)
    if user is None:
        raise credentials_exception
    del user["_id"]
    del user["pwd"]
    return user


async def get_current_active_user(current_user: U.User = Depends(get_current_user)):  # Aggiugere durata account
    if not current_user["status"]:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


# ----------API-------------------#
@app.get("/health", tags=["Other", "Health"])
async def health():
    return True


# User
@app.post("/token", response_model=U.Token, tags=["Auth"])
@app.post("/api/v1/auth", response_model=U.Token, tags=["Auth"])
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = Auth.loginUser(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(days=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/api/v1/me", tags=["Auth"])
async def read_users_me(current_user: U.User = Depends(get_current_active_user)):
    user = current_user

    customers = db["Customers"]
    tmp = list(customers.find().sort("identify"))

    user["authSection"] = Auth.authSection(current_user, tmp)
    return user


@app.get("/api/v1/users/status", tags=["Management"])
async def statusUsers(user: U.User = Depends(get_current_active_user)):
    if not (Auth.authorizationRole(user["role"], Config.RolesModel["Admin"]) or "ONS" in user["tenant"]):
        return HTTPException(status_code=403, detail="Forbidden")

    usersDB = db["Users"]
    Users = usersDB.find().sort("username")
    users = []
    for user in Users:
        del user["_id"]
        del user["pwd"]
        users.append(user)
    return users


@app.post("/api/v1/me/modify", tags=["Management"])
async def modifyMe(data: Request, user: U.User = Depends(get_current_active_user)):
    json = await data.json()
    if json["username"] != user.get("username"):
        return HTTPException(status_code=404)
    users = db["Users"]
    try:
        del json["authSection"]
    except:
        pass
    json["pwd"] = users.find_one({"username": user.get("username")})["pwd"]
    users.delete_one({"username": json["username"]})
    users.insert_one(json)
    return {"status": "update"}


@app.post("/api/v1/me/modify/password", tags=["Management"])
async def changePwd(data: Request, user: U.User = Depends(get_current_active_user)):
    json = await data.json()
    if not json.get("old-pwd") or not json.get("pwd") or not json.get("r-pwd"):
        return HTTPException(status_code=403)
    users = db["Users"]
    userDB = users.find_one({"username": user.get("username")})
    if userDB["pwd"] != Auth.convertPwd(json.get("old-pwd")):
        return HTTPException(status_code=403)
    if json.get("pwd") != json.get("r-pwd"):
        return HTTPException(status_code=403)
    userDB["pwd"] = Auth.convertPwd(json.get("pwd"))
    users.delete_one({"username": user.get("username")})
    users.insert_one(userDB)
    Email.Mailer().sendMail(user.get("mail"), "CHANGE PASSWORD - " + str(datetime.now().strftime("%d/%m/%Y %H:%M:%S")),
                            "Remote ip: " + str(data.client.host))
    return {"status": "update"}


@app.post("/api/v1/user/modify/ALL", tags=["Management"])
async def modifyUser(m: U.UserModify, user: U.User = Depends(get_current_active_user)):
    if not m.targetUser or not (
            Auth.authorizationRole(user["role"], Config.RolesModel["Admin"]) or "ONS" in user["tenant"]):
        return HTTPException(status_code=403, detail="Forbidden")
    users = db["Users"]
    user = users.find_one({"username": m.targetUser})
    if not user:
        return HTTPException(status_code=404)
    del user["_id"]
    users.delete_one(user)
    try:
        if m.fild == "SIEM":
            user["key"]["SIEM"] = json.loads(m.value.replace("'", "\""))
        elif m.fild == "Firewall":
            user["key"]["Firewall"] = json.loads(m.value.replace("'", "\""))
        elif m.fild == "pagerduty" and m.value:
            user["key"]["pagerduty"] = m.value

        elif m.fild == "tenant" and m.value:
            user["tenant"] = json.loads(m.value.replace("'", "\""))

        elif m.fild == "role" and m.value and m.value in Config.Roles:
            user["role"] = m.value

        elif m.fild == "status":
            user["status"] = m.status
    except:
        users.insert_one(user)
        return HTTPException(status_code=400)

    users.insert_one(user)
    del user["_id"]
    return {"Update": user}


@app.post("/api/v1/user/modify", tags=["Management"])
async def modifyUser(m: U.UserModify, user: U.User = Depends(get_current_active_user)):
    users = db["Users"]
    user = users.find_one({"username": user.username})
    if not user:
        return HTTPException(status_code=404)

    del user["_id"]
    users.delete_one(user)

    if m.fild == "SIEM":
        jsonValue = json.loads(m.value.replace("'", "\""))
        c = jsonValue["customer"]
        del jsonValue["customer"]
        if user.get("key").get("SIEM"):
            user["key"]["SIEM"][c] = jsonValue
        else:
            user["key"]["SIEM"] = {c: jsonValue}
    elif m.fild == "Firewall":
        jsonValue = json.loads(m.value.replace("'", "\""))
        c = jsonValue["customer"]
        del jsonValue["customer"]
        if user.get("key").get("Firewall"):
            user["key"]["Firewall"][c] = jsonValue
        else:
            user["key"]["Firewall"] = {c: jsonValue}
    elif m.fild == "pagerduty":
        user["key"]["pagerduty"] = m.value

    users.insert_one(user)
    del user["_id"]
    return {"Update": user}


@app.post("/api/v1/create/user", tags=["Management"])
async def registerUser(u: U.createUser):
    users = db["Users"]
    if users.find_one({"username": u.username}):
        return {"Error": "Username already exists"}
    users.insert_one(u.json())
    user = u.json()
    del user["pwd"]
    return {"Create": user}


@app.get("/api/v1/cti/cache/drop", tags=["Management"])
async def dropCache(user: U.User = Depends(get_current_active_user)):
    if not user.get("role") == "admin":
        return HTTPException(status_code=403, detail="Forbidden")
    cache = db["Cache"]
    cache.delete_many({})
    return {"cache": "drop"}


@app.get("/api/v1/engine/analyst/drop", tags=["Management"])
async def dropAnalyst(user: U.User = Depends(get_current_active_user)):
    if not user.get("role") == "admin":
        return HTTPException(status_code=403, detail="Forbidden")
    analyst = db["Analyst"]
    analyst.delete_many({})
    return {"analyst": "drop"}


# Fine User

# PagerDuty
@app.get("/api/v1/pagerduty/incidents/number", tags=["PagerDuty"])
async def PagerDuty(user: U.User = Depends(get_current_active_user)):
    if user.get("key").get("pagerduty"):
        pd = Pagerduty.Pargerduty(user.get("key").get("pagerduty"))
    else:
        return {"number": len(list(db["PagerDuty-Alert"].find({"status": "triggered"}))) + len(
            list(db["PagerDuty-Alert"].find({"status": "acknowledged"})))}

    return {"number": pd.getIncidentsTotal()}


@app.get("/api/v1/pagerduty/incidents/{limit}", tags=["PagerDuty"])
async def PagerDuty(limit, user: U.User = Depends(get_current_active_user)):
    if user.get("key").get("pagerduty"):
        pd = Pagerduty.Pargerduty(user.get("key").get("pagerduty"))
    else:
        if int(limit):
            if int(limit) == -1:
                return normalizer(db["PagerDuty-Alert"].find())
            return normalizer(db["PagerDuty-Alert"].find().limit(int(limit)))
        else:
            return normalizer(db["PagerDuty-Alert"].find().limit(5))

    try:
        if int(limit):
            if int(limit) == -1:
                return pd.getAllIncidents()
            return pd.getIncidentsLimit(int(limit))
        else:
            return pd.getIncidentsLimit(5)
    except:
        return HTTPException(status_code=404, detail="Bad request")


@app.get("/api/v1/pagerduty/incidents/id/{incident}", tags=["PagerDuty"])
async def PagerDuty(incident, user: U.User = Depends(get_current_active_user)):
    if user.get("key").get("pagerduty"):
        pd = Pagerduty.Pargerduty(user.get("key").get("pagerduty"))
    else:
        return normalizer(db["PagerDuty-Alert"].find({"id": incident}))
    return pd.getIncident(incident)


@app.get("/api/v1/pagerduty/incidents/{incident}/{status}", tags=["PagerDuty"])
async def PagerDuty(incident, status, user: U.User = Depends(get_current_active_user)):
    if user.get("key").get("pagerduty"):
        pd = Pagerduty.Pargerduty(user.get("key").get("pagerduty"))
    else:
        return HTTPException(status_code=403, detail="Forbidden")

    try:
        return pd.updateIncident(status, user["mail"], incident)
    except:
        return {"status": "ok"}


# Fine PagerDuty

# SIEM QRadar
@app.get("/api/v1/siem/QRadar/{customer}/health", tags=["SIEM", "QRadar", "Health"])
async def siem(customer, user: U.User = Depends(get_current_active_user)):
    if not user.get("key").get("SIEM").get(customer):
        return HTTPException(status_code=404, detail="Bad request")
    siem = user.get("key").get("SIEM").get(customer)

    return QRadar.QRadar(siem["ip"], siem["token"], "12").health()


@app.get("/api/v1/siem/QRadar/myOffenses/number", tags=["SIEM", "QRadar"])
async def siem(user: U.User = Depends(get_current_active_user)):
    if user.get("key").get("SIEM"):
        siem = user.get("key").get("SIEM")
    else:
        return HTTPException(status_code=404, detail="Bad requests")
    n = 0
    if siem:
        for s in siem:
            n += QRadar.QRadar(siem[s]["ip"], siem[s]["token"], "12").getTotalOpenOffenses(user["username"])
    return {"number": n}


@app.get("/api/v1/siem/QRadar/Offenses/{customer}/{index}", tags=["SIEM", "QRadar"])
async def siem(customer, index: int, user: U.User = Depends(get_current_active_user)):
    if not user.get("key").get("SIEM").get(customer):
        return HTTPException(status_code=404, detail="Bad request")
    siem = user.get("key").get("SIEM").get(customer)
    try:
        if int(index) == -1:
            return QRadar.QRadar(siem["ip"], siem["token"], "12").getAllOpenOffenses(customer)
    except:
        return HTTPException(status_code=404, detail="Bad request")
    try:
        return QRadar.QRadar(siem["ip"], siem["token"], "12").getOpenOffenses(int(index))
    except:
        return HTTPException(status_code=404, detail="Bad request")


@app.get("/api/v1/siem/QRadar/Offenses/{customer}/assigned_to/me", tags=["SIEM", "QRadar"])
async def siem(customer, user: U.User = Depends(get_current_active_user)):
    if not user.get("key").get("SIEM").get(customer):
        return HTTPException(status_code=404, detail="Bad request")
    siem = user.get("key").get("SIEM").get(customer)
    return QRadar.QRadar(siem["ip"], siem["token"], "12").getAssignedOffenses(user["username"])


@app.get("/api/v1/siem/QRadar/Offenses/{customer}/assigned", tags=["SIEM", "QRadar"])
async def siem(customer, user: U.User = Depends(get_current_active_user)):
    if not user.get("key").get("SIEM").get(customer):
        return HTTPException(status_code=404, detail="Bad request")
    siem = user.get("key").get("SIEM").get(customer)
    return QRadar.QRadar(siem["ip"], siem["token"], "12").getAssignedOffenses(user["username"])


@app.get("/api/v1/siem/QRadar/Offenses/Offense/{customer}/{offenseID}", tags=["SIEM", "QRadar"])
async def siem(offenseID, customer, user: U.User = Depends(get_current_active_user)):
    if not user.get("key").get("SIEM").get(customer):
        return HTTPException(status_code=404, detail="Bad request")
    siem = user.get("key").get("SIEM").get(customer)
    return QRadar.QRadar(siem["ip"], siem["token"], "12").getOffense(offenseID)


@app.get("/api/v1/siem/QRadar/Offenses/Offense/{customer}/{offenseID}/events/{start}/{end}", tags=["SIEM", "QRadar"])
async def siemEvent(offenseID, customer, start, end, user: U.User = Depends(get_current_active_user)):
    if not user.get("key").get("SIEM").get(customer):
        return HTTPException(status_code=404, detail="Bad request")
    siem = user.get("key").get("SIEM").get(customer)
    return QRadar.QRadar(siem["ip"], siem["token"], "12").getEvents(offenseID, start, end)


@app.get("/api/v1/siem/QRadar/Offenses/Offense/{customer}/{offenseID}/flows/{start}/{end}", tags=["SIEM", "QRadar"])
async def siemFlows(offenseID, customer, start, end, user: U.User = Depends(get_current_active_user)):
    if not user.get("key").get("SIEM").get(customer):
        return HTTPException(status_code=404, detail="Bad request")
    siem = user.get("key").get("SIEM").get(customer)
    return QRadar.QRadar(siem["ip"], siem["token"], "12").getFlows(offenseID, start, end)


@app.get("/api/v1/siem/QRadar/Offenses/Offense/{customer}/{offenseID}/events/{start}/{end}/aggregation/{aggregation}",
         tags=["SIEM", "QRadar"])
async def siemEvent(offenseID, customer, start, end, aggregation, user: U.User = Depends(get_current_active_user)):
    if not user.get("key").get("SIEM").get(customer):
        return HTTPException(status_code=404, detail="Bad request")
    if aggregation not in ["sourceip", "destinationip", "qid", "destinationport", "sourceport", "username",
                           "magnitude"]:
        return HTTPException(status_code=404, detail="Bad request")
    siem = user.get("key").get("SIEM").get(customer)
    return QRadar.QRadar(siem["ip"], siem["token"], "12").getEventsAggregation(offenseID, start, end, aggregation)


@app.get("/api/v1/siem/QRadar/Offenses/Offense/{customer}/{offenseID}/flows/{start}/{end}/aggregation/{aggregation}",
         tags=["SIEM", "QRadar"])
async def siemEvent(offenseID, customer, start, end, aggregation, user: U.User = Depends(get_current_active_user)):
    if not user.get("key").get("SIEM").get(customer):
        return HTTPException(status_code=404, detail="Bad request")
    if aggregation not in ["sourceip", "destinationip", "qid", "destinationport", "sourceport", "username",
                           "magnitude"]:
        return HTTPException(status_code=404, detail="Bad request")
    siem = user.get("key").get("SIEM").get(customer)
    return QRadar.QRadar(siem["ip"], siem["token"], "12").getFlowsAggregation(offenseID, start, end, aggregation)


@app.get("/api/v1/siem/QRadar/Offenses/Offense/{customer}/events/{offenseID}/payload/{start}/{end}",
         tags=["SIEM", "QRadar"])
async def siemEvent(offenseID, customer, start, end, user: U.User = Depends(get_current_active_user)):
    if not user.get("key").get("SIEM").get(customer):
        return HTTPException(status_code=404, detail="Bad request")

    siem = user.get("key").get("SIEM").get(customer)
    return QRadar.QRadar(siem["ip"], siem["token"], "12").getPayloadEvents(offenseID, start, end)


@app.get("/api/v1/siem/QRadar/Offenses/Offense/{customer}/events/{offenseID}/payload/parser/{start}/{end}", tags=["SIEM", "QRadar"])
async def siemEvent(offenseID, customer, start, end, user: U.User = Depends(get_current_active_user)):
    if not user.get("key").get("SIEM").get(customer):
        return HTTPException(status_code=404, detail="Bad request")

    siem = user.get("key").get("SIEM").get(customer)
    return QRadar.QRadar(siem["ip"], siem["token"], "12").getEventsPayloadOffenses(offenseID, start, end)


@app.get("/api/v1/siem/QRadar/Offenses/Offense/{customer}/flows/{offenseID}/payload/{start}/{end}", tags=["SIEM", "QRadar"])
async def siemEvent(offenseID, customer, start, end, user: U.User = Depends(get_current_active_user)):
    if not user.get("key").get("SIEM").get(customer):
        return HTTPException(status_code=404, detail="Bad request")

    siem = user.get("key").get("SIEM").get(customer)
    return QRadar.QRadar(siem["ip"], siem["token"], "12").getPayloadFlows(offenseID, start, end)


@app.get("/api/v1/siem/QRadar/Offenses/close/{customer}/{offenseID}/{closeReason}", tags=["SIEM", "QRadar"])
async def siem(customer, offenseID, closeReason, user: U.User = Depends(get_current_active_user)):
    if not user.get("key").get("SIEM").get(customer):
        return HTTPException(status_code=404, detail="Bad request")

    siem = user.get("key").get("SIEM").get(customer)
    if closeReason not in Config.statusCase.keys():
        return HTTPException(status_code=404, detail="Bad request")

    QRadar.QRadar(siem["ip"], siem["token"], "12").closeOffense(offenseID, Config.statusCase.get(closeReason))
    return {"status": "close"}


@app.get("/api/v1/siem/QRadar/Offenses/{customer}/{offenseID}/assigned_to/{username}", tags=["SIEM", "QRadar"])
async def siem(customer, offenseID, username, user: U.User = Depends(get_current_active_user)):
    if not user.get("key").get("SIEM").get(customer):
        return HTTPException(status_code=404, detail="Bad request")

    siem = user.get("key").get("SIEM").get(customer)
    QRadar.QRadar(siem["ip"], siem["token"], "12").assignedOffense(offenseID, username)
    return {"status": "assigned_to " + username}


@app.get("/api/v1/siem/QRadar/Offenses/{customer}/{offenseID}/note", tags=["SIEM", "QRadar"])
async def siem(customer, offenseID, user: U.User = Depends(get_current_active_user)):
    if not user.get("key").get("SIEM").get(customer):
        return HTTPException(status_code=404, detail="Bad request")
    siem = user.get("key").get("SIEM").get(customer)
    return QRadar.QRadar(siem["ip"], siem["token"], "12").getNote(offenseID)


@app.post("/api/v1/siem/QRadar/Offenses/{customer}/{offenseID}/note", tags=["SIEM", "QRadar"])
async def siem(customer, offenseID, note: U.addNote, user: U.User = Depends(get_current_active_user)):
    if not user.get("key").get("SIEM").get(customer):
        return HTTPException(status_code=404, detail="Bad request")
    siem = user.get("key").get("SIEM").get(customer)
    return QRadar.QRadar(siem["ip"], siem["token"], "12").addNote(offenseID, note.text)


@app.get("/api/v1/siem/QRadar/Offenses/{customer}/{offenseID}/follow_up/{follow_up}/protected/{protected}",
         tags=["SIEM", "QRadar"])
async def siem(customer, offenseID, follow_up: bool, protected: bool, user: U.User = Depends(get_current_active_user)):
    if not user.get("key").get("SIEM").get(customer):
        return HTTPException(status_code=404, detail="Bad request")

    siem = user.get("key").get("SIEM").get(customer)
    QRadar.QRadar(siem["ip"], siem["token"], "12").actionsOffense(offenseID, follow_up, protected)
    return {"status": "follow_up:" + str(follow_up) + " protected:" + str(protected)}


@app.get("/api/v1/siem/QRadar/{customer}/users", tags=["SIEM", "QRadar"])
async def siem(customer, user: U.User = Depends(get_current_active_user)):
    if not user.get("key").get("SIEM").get(customer):
        return HTTPException(status_code=404, detail="Bad request")

    siem = user.get("key").get("SIEM").get(customer)
    return QRadar.QRadar(siem["ip"], siem["token"], "12").getUsers()


@app.get("/api/v1/siem/QRadar/{customer}/assets/events/{ip}/{time}", tags=["SIEM", "QRadar"])
async def siem(customer, ip, time, user: U.User = Depends(get_current_active_user)):
    if not user.get("key").get("SIEM").get(customer):
        return HTTPException(status_code=404, detail="Bad request")

    siem = user.get("key").get("SIEM").get(customer)
    return QRadar.QRadar(siem["ip"], siem["token"], "12").getEventsForUsers_Assets(ip, time)


@app.get("/api/v1/siem/QRadar/{customer}/geolocation/iso_code/{ip}", tags=["SIEM", "QRadar"])
async def siem(customer, ip: str, user: U.User = Depends(get_current_active_user)):
    if not user.get("key").get("SIEM").get(customer):
        return HTTPException(status_code=404, detail="Bad request")
    if not Check.isipv4(ip) and not Check.isipv6(ip):
        return HTTPException(status_code=404, detail="Bad request")

    siem = user.get("key").get("SIEM").get(customer)
    return QRadar.QRadar(siem["ip"], siem["token"], "12").lookupGeolocationIso_code(ip)


@app.get("/api/v1/siem/QRadar/{customer}/assets/{domain}", tags=["SIEM", "QRadar"])
async def siem(customer, domain=None, user: U.User = Depends(get_current_active_user)):
    if not user.get("key").get("SIEM").get(customer):
        return HTTPException(status_code=404, detail="Bad request")

    siem = user.get("key").get("SIEM").get(customer)
    if domain is None or domain.upper() == "NONE":
        return QRadar.QRadar(siem["ip"], siem["token"], "12").getAssets()
    return QRadar.QRadar(siem["ip"], siem["token"], "12").getAssets(domain)


@app.get("/api/v1/siem/QRadar/{customer}/update/OTIF", tags=["SIEM", "QRadar"])
async def siem(customer, user: U.User = Depends(get_current_active_user)):
    if not user.get("key").get("SIEM").get(customer):
        return HTTPException(status_code=404, detail="Bad request")
    ips = requests.get(Config.APIv4 + "/api/v4/download/list/ip").json()
    siem = user.get("key").get("SIEM").get(customer)
    return QRadar.QRadar(siem["ip"], siem["token"], "12").updateReferenceOTIF(ips)


@app.get("/api/v1/siem/QRadar/{customer}/scan/nmap/{ip}", tags=["SIEM", "QRadar"])
async def siem(customer, ip, user: U.User = Depends(get_current_active_user)):
    if not user.get("key").get("SIEM").get(customer):
        return HTTPException(status_code=404, detail="Bad request")
    siem = user.get("key").get("SIEM").get(customer)
    return QRadar.QRadar(siem["ip"], siem["token"], "12").scanNmap(ip)

@app.get("/api/v1/siem/QRadar/{customer}/audit/usersIT/{days}", tags=["SIEM", "QRadar"])
async def siem(customer, days, user: U.User = Depends(get_current_active_user)):
    if not user.get("key").get("SIEM").get(customer):
        return HTTPException(status_code=404, detail="Bad request")
    siem = user.get("key").get("SIEM").get(customer)
    return QRadar.QRadar(siem["ip"], siem["token"], "12").getAuditITAdmins(days)
# Fine SIEM QRadar

# Task
@app.post("/api/v1/task/create", tags=["Tasks"])
async def createTask(t: U.task, user: U.User = Depends(get_current_active_user)):
    tasks = db["Tasks"]
    task = tasks.find_one({"task": t.task, "assigned_to": t.assigned_to, "completed": False})
    if task:
        return {"Task already created": t}
    tasks.insert_one(t.json())
    return {"Task created": t}


@app.get("/api/v1/task", tags=["Tasks"])
async def getTasks(user: U.User = Depends(get_current_active_user)):
    tasks = db["Tasks"]
    tasksDB = tasks.find({"assigned_to": {"$in": [user["username"]]}}).sort("completed")
    tmp = []
    for task in tasksDB:
        del task["_id"]
        tmp.append(task)
    return tmp


@app.get("/api/v1/task/{customer}", tags=["Tasks"])
async def getTasks(customer, user: U.User = Depends(get_current_active_user)):
    tasks = db["Tasks"]

    tasksDB = tasks.find({"assigned_to": {"$in": [user["username"]]}, "customer": customer}).sort("completed")

    tmp = []
    for task in tasksDB:
        del task["_id"]
        tmp.append(task)
    return tmp


@app.get("/api/v1/task/open/count", tags=["Tasks"])
async def task(user: U.User = Depends(get_current_active_user)):
    tasks = db["Tasks"]
    tasksDB = tasks.find({"assigned_to": {"$in": [user["username"]]}, "completed": False})

    tmp = []
    for task in tasksDB:
        del task["_id"]
        tmp.append(task)
    return len(tmp)


# Fine Task

# Customer
@app.get("/api/v1/customers/{tenant}", tags=["Customer"])
async def customers(tenant, user: U.User = Depends(get_current_active_user)):
    if tenant in user["tenant"]:
        customers = db["Customers"]
        tmp = customers.find().sort("identify")
        customer = []

        for i in tmp:
            del i["_id"]

            if i["identify"] in Config.customerAuth[tenant] or "all" in Config.customerAuth[tenant]:
                customer.append(i)
        return customer
    return HTTPException(status_code=403, detail="Forbidden")


@app.get("/api/v1/customers/{tenant}/{identify}", tags=["Customer"])
async def customers(identify, tenant, user: U.User = Depends(get_current_active_user)):
    if tenant in user["tenant"] and ("all" in Config.customerAuth[tenant] or identify in Config.customerAuth[tenant]):
        customers = db["Customers"]
        tmp = customers.find_one({"identify": identify})
        if tmp:
            del tmp["_id"]
            return tmp
        else:
            return HTTPException(status_code=404, detail="Not found")
    return HTTPException(status_code=403, detail="Forbidden")


@app.post("/api/v1/customers/add", tags=["Customer"])
async def customers(customer: U.Customer, user: U.User = Depends(get_current_active_user)):
    if Auth.authorizationRole(user["role"], Config.RolesModel["customersAdd"]):
        customers = db["Customers"]
        tmp = customers.find_one({"identify": customer.identify})
        if tmp:
            customers.delete_one(tmp)
            customers.insert_one(customer.json())
            return {"status": "ok"}
        else:
            customers.insert_one(customer.json())
            return {"status": "ok"}
    return HTTPException(status_code=403, detail="Forbidden")


# Fine Customer

# Fortigate
@app.get("/api/v1/firewall/fortinet/{customer}/vdom", tags=["Firewall", "Fortinet"])
async def getVdom(customer, user: U.User = Depends(get_current_active_user)):
    if not user.get("key") or not user.get("key").get("Firewall") or not user.get("key").get("Firewall").get(customer):
        return HTTPException(status_code=403, detail="Forbidden")
    authFirewall = user["key"]["Firewall"][customer]

    f = FortiOS.fortigate(authFirewall["ip"], authFirewall["token"])
    v = f.getVdom()
    if v.get("results"):
        return v["results"]
    return v


@app.get("/api/v1/firewall/fortinet/{customer}/interfaces", tags=["Firewall", "Fortinet"])
async def getInterfaces(customer, user: U.User = Depends(get_current_active_user)):
    if not user.get("key") or not user.get("key").get("Firewall") or not user.get("key").get("Firewall").get(customer):
        return HTTPException(status_code=403, detail="Forbidden")
    authFirewall = user["key"]["Firewall"][customer]

    f = FortiOS.fortigate(authFirewall["ip"], authFirewall["token"])
    i = f.getInterfaces()
    if i.get("results"):
        return i["results"]
    return i


@app.get("/api/v1/firewall/fortinet/{customer}/{vdom}/address", tags=["Firewall", "Fortinet"])
async def getAddress(customer, vdom, user: U.User = Depends(get_current_active_user)):
    if not user.get("key") or not user.get("key").get("Firewall") or not user.get("key").get("Firewall").get(customer):
        return HTTPException(status_code=403, detail="Forbidden")
    authFirewall = user["key"]["Firewall"][customer]

    f = FortiOS.fortigate(authFirewall["ip"], authFirewall["token"])
    i = f.getAllAddress(vdom)
    if i.get("results"):
        return i["results"]
    return i


@app.post("/api/v1/firewall/fortinet/{customer}/{vdom}/address", tags=["Firewall", "Fortinet"])
async def createAddress(address: U.Firewall, customer, vdom, user: U.User = Depends(get_current_active_user)):
    if not user.get("key") or not user.get("key").get("Firewall") or not user.get("key").get("Firewall").get(customer):
        return HTTPException(status_code=403, detail="Forbidden")
    if not address.subnet or not address.name:
        return HTTPException(status_code=404)
    authFirewall = user["key"]["Firewall"][customer]

    f = FortiOS.fortigate(authFirewall["ip"], authFirewall["token"])
    return f.createAddress(address.name, address.subnet, vdom)


@app.get("/api/v1/firewall/fortinet/{customer}/{vdom}/addrgrp", tags=["Firewall", "Fortinet"])
async def getAddressGroup(customer, vdom, user: U.User = Depends(get_current_active_user)):
    if not user.get("key") or not user.get("key").get("Firewall") or not user.get("key").get("Firewall").get(customer):
        return HTTPException(status_code=403, detail="Forbidden")
    authFirewall = user["key"]["Firewall"][customer]

    f = FortiOS.fortigate(authFirewall["ip"], authFirewall["token"])
    g = f.getAllAddressGroup(vdom)
    if g.get("results"):
        return g["results"]
    return g


@app.post("/api/v1/firewall/fortinet/{customer}/{vdom}/addrgrp", tags=["Firewall", "Fortinet"])
async def createAddressGroup(addrgrp: U.Firewall, customer, vdom, user: U.User = Depends(get_current_active_user)):
    if not user.get("key") or not user.get("key").get("Firewall") or not user.get("key").get("Firewall").get(customer):
        return HTTPException(status_code=403, detail="Forbidden")
    if not addrgrp.address or not addrgrp.name:
        return HTTPException(status_code=404)
    authFirewall = user["key"]["Firewall"][customer]

    f = FortiOS.fortigate(authFirewall["ip"], authFirewall["token"])
    return f.createAddressGroup(addrgrp.name, addrgrp.address, vdom)


@app.put("/api/v1/firewall/fortinet/{customer}/{vdom}/addrgrp", tags=["Firewall", "Fortinet"])
async def updateAddressGroup(addrgrp: U.Firewall, customer, vdom, user: U.User = Depends(get_current_active_user)):
    if not user.get("key") or not user.get("key").get("Firewall") or not user.get("key").get("Firewall").get(customer):
        return HTTPException(status_code=403, detail="Forbidden")
    if not addrgrp.address or not addrgrp.name:
        return HTTPException(status_code=404)
    authFirewall = user["key"]["Firewall"][customer]

    f = FortiOS.fortigate(authFirewall["ip"], authFirewall["token"])
    f.setAddressGroup(addrgrp.name, addrgrp.address, vdom)
    return {"ok": "ok"}


@app.get("/api/v1/firewall/fortinet/{customer}/{vdom}/policies", tags=["Firewall", "Fortinet"])
async def getAllPolicies(customer, vdom, user: U.User = Depends(get_current_active_user)):
    if not user.get("key") or not user.get("key").get("Firewall") or not user.get("key").get("Firewall").get(customer):
        return HTTPException(status_code=403, detail="Forbidden")
    authFirewall = user["key"]["Firewall"][customer]

    f = FortiOS.fortigate(authFirewall["ip"], authFirewall["token"])
    p = f.getPolicies(vdom)
    if p.get("results"):
        return p["results"]
    return p


@app.get("/api/v1/firewall/fortinet/{customer}/{vdom}/policies/status", tags=["Firewall", "Fortinet"])
async def getAllStatusPolicies(customer, vdom, user: U.User = Depends(get_current_active_user)):
    if not user.get("key") or not user.get("key").get("Firewall") or not user.get("key").get("Firewall").get(customer):
        return HTTPException(status_code=403, detail="Forbidden")
    authFirewall = user["key"]["Firewall"][customer]

    f = FortiOS.fortigate(authFirewall["ip"], authFirewall["token"])
    return f.getPoliciesStatus(vdom)


@app.post("/api/v1/firewall/fortinet/{customer}/{vdom}/policy", tags=["Firewall", "Fortinet"])
async def createPolicy(policy: U.Policy, customer, vdom, user: U.User = Depends(get_current_active_user)):
    if not user.get("key") or not user.get("key").get("Firewall") or not user.get("key").get("Firewall").get(customer):
        return HTTPException(status_code=403, detail="Forbidden")
    authFirewall = user["key"]["Firewall"][customer]

    f = FortiOS.fortigate(authFirewall["ip"], authFirewall["token"])
    return f.createPolicy(policy.vdom, policy.name, policy.srcintf, policy.dstintf, policy.srcaddr, policy.dstaddr,
                          policy.service, policy.action, policy.schedule,
                          policy.nat, policy.poolname, policy.ippool, policy.status, policy.comments,
                          policy.traffic_shaper, policy.traffic_shaper_reverse)


@app.get("/api/v1/firewall/fortinet/{customer}/{vdom}/devices", tags=["Firewall", "Fortinet"])
async def getDevices(customer, vdom, user: U.User = Depends(get_current_active_user)):
    if not user.get("key") or not user.get("key").get("Firewall") or not user.get("key").get("Firewall").get(customer):
        return HTTPException(status_code=403, detail="Forbidden")
    authFirewall = user["key"]["Firewall"][customer]

    f = FortiOS.fortigate(authFirewall["ip"], authFirewall["token"])
    return f.getDevices(vdom).get("results")

@app.get("/api/v1/firewall/fortinet/{customer}/{vdom}/dnat", tags=["Firewall", "Fortinet", "Health"])
async def health(customer, vdom="root", user: U.User = Depends(get_current_active_user)):
    if not user.get("key") or not user.get("key").get("Firewall") or not user.get("key").get("Firewall").get(customer):
        return HTTPException(status_code=403, detail="Forbidden")
    authFirewall = user["key"]["Firewall"][customer]

    f = FortiOS.fortigate(authFirewall["ip"], authFirewall["token"])
    return f.getDnat(vdom)


@app.get("/api/v1/firewall/fortinet/{customer}/{vdom}/health", tags=["Firewall", "Fortinet", "Health"])
async def health(customer, vdom, user: U.User = Depends(get_current_active_user)):
    if not user.get("key") or not user.get("key").get("Firewall") or not user.get("key").get("Firewall").get(customer):
        return HTTPException(status_code=403, detail="Forbidden")
    authFirewall = user["key"]["Firewall"][customer]

    f = FortiOS.fortigate(authFirewall["ip"], authFirewall["token"])
    return f.health()

# Fine Fortigate

# Sophos
@app.get("/api/v1/sophos/{customer}/health", tags=["Firewall", "SIEM", "Sophos", "Health"])
async def getDevices(customer, user: U.User = Depends(get_current_active_user)):
    if not user.get("key") or not user.get("key").get("Sophos") or not user.get("key").get("Sophos").get(customer):
        return HTTPException(status_code=403, detail="Forbidden")
    authFirewall = user["key"]["Sophos"][customer]

    return Sophos.SophosCentral(authFirewall["id"], authFirewall["token"]).health()


@app.get("/api/v1/sophos/{customer}/alerts", tags=["Firewall", "SIEM", "Sophos"])
async def getDevices(customer, user: U.User = Depends(get_current_active_user)):
    if not user.get("key") or not user.get("key").get("Sophos") or not user.get("key").get("Sophos").get(customer):
        return HTTPException(status_code=403, detail="Forbidden")
    authFirewall = user["key"]["Sophos"][customer]

    return Sophos.SophosCentral(authFirewall["id"], authFirewall["token"]).getAlerts()


@app.get("/api/v1/sophos/{customer}/alert/{idAlert}", tags=["Firewall", "SIEM", "Sophos"])
async def getDevices(customer, idAlert, user: U.User = Depends(get_current_active_user)):
    if not user.get("key") or not user.get("key").get("Sophos") or not user.get("key").get("Sophos").get(customer):
        return HTTPException(status_code=403, detail="Forbidden")
    authFirewall = user["key"]["Sophos"][customer]

    return Sophos.SophosCentral(authFirewall["id"], authFirewall["token"]).getAlert(idAlert)


@app.get("/api/v1/sophos/{customer}/alert/{idAlert}/close/{reason}", tags=["Firewall", "SIEM", "Sophos"])
async def getDevices(customer, idAlert, reason, user: U.User = Depends(get_current_active_user)):
    if not user.get("key") or not user.get("key").get("Sophos") or not user.get("key").get("Sophos").get(customer):
        return HTTPException(status_code=403, detail="Forbidden")
    authFirewall = user["key"]["Sophos"][customer]

    return Sophos.SophosCentral(authFirewall["id"], authFirewall["token"]).closeAlert(idAlert, reason)


@app.get("/api/v1/sophos/{customer}/assets", tags=["Firewall", "SIEM", "Sophos"])
async def getDevices(customer, user: U.User = Depends(get_current_active_user)):
    if not user.get("key") or not user.get("key").get("Sophos") or not user.get("key").get("Sophos").get(customer):
        return HTTPException(status_code=403, detail="Forbidden")
    authFirewall = user["key"]["Sophos"][customer]

    return Sophos.SophosCentral(authFirewall["id"], authFirewall["token"]).getAllAssets()


@app.get("/api/v1/sophos/{customer}/asset/{idAsset}", tags=["Firewall", "SIEM", "Sophos"])
async def getDevices(customer, idAsset, user: U.User = Depends(get_current_active_user)):
    if not user.get("key") or not user.get("key").get("Sophos") or not user.get("key").get("Sophos").get(customer):
        return HTTPException(status_code=403, detail="Forbidden")
    authFirewall = user["key"]["Sophos"][customer]

    return Sophos.SophosCentral(authFirewall["id"], authFirewall["token"]).getAsset(idAsset)


@app.get("/api/v1/sophos/{customer}/asset/{idAsset}/scan", tags=["Firewall", "SIEM", "Sophos"])
async def getDevices(customer, idAsset, user: U.User = Depends(get_current_active_user)):
    if not user.get("key") or not user.get("key").get("Sophos") or not user.get("key").get("Sophos").get(customer):
        return HTTPException(status_code=403, detail="Forbidden")
    authFirewall = user["key"]["Sophos"][customer]

    return Sophos.SophosCentral(authFirewall["id"], authFirewall["token"]).scanAsset(idAsset)

# Fine Sophos


# Case
@app.get("/api/v1/case/{id}", tags=["Case"])
async def getIncident(id: int, user: U.User = Depends(get_current_active_user)):
    try:
        incidents = db["Incidents"]
        tmp = incidents.find_one({"id": int(id)})
        del tmp["_id"]
        return tmp
    except:
        return HTTPException(status_code=404)


@app.get("/api/v1/case/open/{customer}", tags=["Case"])
async def incidents(customer, user: U.User = Depends(get_current_active_user)):
    incidents = db["Incidents"]

    tmp = incidents.find({"customer": customer, "status": "open"}).sort("creation_date")

    i = []
    for t in tmp:
        del t["_id"]
        i.append(t)
    return i


@app.get("/api/v1/case/all/{customer}", tags=["Case"])
async def incidents(customer, user: U.User = Depends(get_current_active_user)):
    incidents = db["Incidents"]

    tmp = incidents.find({"customer": customer}).sort("creation_date")

    i = []
    for t in tmp:
        del t["_id"]
        i.append(t)
    return i


@app.get("/api/v1/case/tenant/{tenant}/open", tags=["Case"])
async def incidents(tenant, user: U.User = Depends(get_current_active_user)):
    if tenant not in user.get("tenant"):
        return HTTPException(status_code=404)
    incidents = db["Incidents"]

    tmp = incidents.find({"tenant": tenant, "status": "open"}).sort("creation_date")

    i = []
    for t in tmp:
        del t["_id"]
        i.append(t)
    return i


@app.get("/api/v1/case/tenant/{tenant}/all", tags=["Case"])
async def incidents(tenant, user: U.User = Depends(get_current_active_user)):
    if tenant not in user.get("tenant"):
        return HTTPException(status_code=404)
    incidents = db["Incidents"]
    tmp = incidents.find({"tenant": tenant}).sort("creation_date")
    i = []
    for t in tmp:
        del t["_id"]
        i.append(t)
    return i


@app.get("/api/v1/case/assigned_me/all", tags=["Case"])
async def getCase(user: U.User = Depends(get_current_active_user)):
    return {"total-my": db["Incidents"].count_documents({"create_by": user.get("username")}),
            "open-my": db["Incidents"].count_documents({"create_by": user.get("username"), "status": "open"})}


@app.get("/api/v1/template/case", tags=["Case"])
async def getTemplate(user: U.User = Depends(get_current_active_user)):
    incidents = db["Templates"]
    templates = incidents.find()

    tmp = []

    for template in templates:
        del template["_id"]
        tmp.append(template)
    return tmp


@app.post("/api/v1/template/case/{name}", tags=["Case"])
async def updateTemplate(json: Request, name, user: U.User = Depends(get_current_active_user)):
    t = db["Templates"]
    templates = t.find_one({"name": name})
    if not templates:
        return HTTPException(status_code=404)

    json = await json.json()
    if templates.get("description") and json.get("description"):
        templates["description"] = json["description"]
    else:
        if templates.get("introduzione") and json.get("introduzione"):
            templates["introduzione"] = json["introduzione"]
        if templates.get("Case") and json.get("Case"):
            templates["Case"] = json["Case"]
        if templates.get("Firewall") and json.get("Firewall"):
            templates["Firewall"] = json["Firewall"]
        if templates.get("SIEM") and json.get("SIEM"):
            templates["SIEM"] = json["SIEM"]
        if templates.get("Conclusioni") and json.get("Conclusioni"):
            templates["Conclusioni"] = json["Conclusioni"]

    t.delete_one({"name": name})
    t.insert_one(templates)

    return {"status": "ok"}


def searchAssetUser(obj: str):
    assetsAnalysis = db["Assets_Analysis"].find_one({"name": obj.lower()})
    tmp = {"obj": obj, "type": "unknown", "risk_score": "unknown", "confidence": "N/A", "tag": "unknown",
           "action": "unknown"}
    asset = db["Assets"].find_one({"hostnames": obj.lower()})
    if asset:
        if asset.get("id-ReaQta"):
            tmp["id-ReaQta"] = asset["id-ReaQta"]
        tmp["type"] = "asset"
    asset = db["Assets"].find_one({"ip": obj.lower()})
    if asset:
        if asset.get("id-ReaQta"):
            tmp["id-ReaQta"] = asset["id-ReaQta"]
        tmp["type"] = "asset"
    asset = db["Assets"].find_one({"users": obj.lower()})
    if asset:
        if asset.get("id-ReaQta"):
            tmp["id-ReaQta"] = asset["id-ReaQta"]
        tmp["type"] = "user"

    if assetsAnalysis:
        tmp["risk_score"] = assetsAnalysis["score"]
        if tmp["risk_score"] > 15:
            tmp["tag"] = "malicious"
            tmp["action"] = "block"
        elif 5 >= tmp["risk_score"] >= 15:
            tmp["tag"] = "suspicious"
            tmp["action"] = "suspicious"
        else:
            tmp["tag"] = "trusted"
            tmp["action"] = "allow"

    return tmp


def checkReputationIOC(obj: str):
    tmp = searchAssetUser(obj)
    if tmp["type"] != "unknown":
        return tmp
    cache = db["Cache"]
    reputation = cache.find_one({"target": obj})
    if reputation:
        del reputation["_id"]
        return reputation
    reputation = requests.get(Config.APIv4 + "/api/v4/search/user/" + obj, verify=False).json()
    reputation["target"] = reputation["obj"]

    if ((reputation["risk_score"] > 2 and reputation["confidence"] > 2) or reputation["tag"] == "malicious") and \
            reputation["tag"] != "trusted":
        reputation["action"] = "block"
    elif reputation["risk_score"] >= 2:
        reputation["action"] = "suspicious"
    else:
        reputation["action"] = "allow"
    try:
        cache.insert_one(reputation)
    except:
        pass
    try:
        del reputation["ExternalTI"]
        del reputation["_id"]
    except:
        pass
    return reputation


@app.post("/api/v1/case/create", tags=["Case"])
async def createCase(case: U.CaseCreation, user: U.User = Depends(get_current_active_user)):
    caseDB = db["Incidents"]
    case = case.json()
    id = caseDB.count_documents({})
    while caseDB.find_one({"id": id}):
        id += 1
    case["id"] = id
    intelligence = []
    if case.get("observable") and case["observable"].get("intelligence"):
        intelligence += case["observable"].get("intelligence")
        case["observable"]["intelligence"] = []

    if case.get("template"):
        template = db["Templates"].find_one({"id": case["template"]})
        if not template:
            incidents.insert_one(case)
            del case["_id"]
            return case
        ids = ""
        source = "generic"
        analyst = None
        if case.get("observable") and case["observable"].get("offense"):
            source = "QRadar"
            for offenseId in case["observable"].get("offense"):
                analyst = db["Analyst"].find_one({"id": offenseId})
                ids += offenseId + " - "
        if case.get("observable") and case["observable"].get("EDR"):
            source = "EDR"
            for edrId in case["observable"].get("EDR"):
                analyst = db["Analyst"].find_one({"id": edrId})
                ids += edrId + " - "
        if case.get("observable") and case["observable"].get("alert"):
            for alertId in case["observable"].get("offense"):
                ids += alertId + " - "

        if ids != "":
            case["title"] = template["titlePrefix"].replace("<id>", ids[0: len(ids) - 3])
        else:
            case["title"] = template["titlePrefix"].replace("[<id>]", "")

        if analyst and analyst.get("results"):
            for ip in analyst.get("results"):
                intelligence.append(ip["obj"])

        if analyst and analyst.get("report").get("description"):
            case["text"] = analyst.get("report").get("description")
        else:
            case["text"] = template["description"].replace("<data>", datetime.now().strftime("%d/%m/%Y %H:%M:%S"))
            case["text"] = case["text"].replace("<sorgente>", source)

    if not case.get("observable"):
        case["observable"] = {}
    if not case.get("observable").get("intelligence"):
        case["observable"]["intelligence"] = []
    for ip in intelligence:
        try:
            case["observable"]["intelligence"].append(checkReputationIOC(ip))
        except:
            case["observable"]["intelligence"].append({"obj": ip})

    caseDB.insert_one(case)

    try:
        del case["_id"]
    except:
        pass

    return case


@app.put("/api/v1/case/update/{id}/assigned/{username}", tags=["Case"])
async def updateCase(username: str, id: int, user: U.User = Depends(get_current_active_user)):
    casesDB = db["Incidents"]
    caseDB = casesDB.find_one({"id": id})
    if not caseDB:
        return HTTPException(status_code=404, detail="Case not foud")
    if user.get("username") not in caseDB["assigned_to"] or caseDB["tenant"] not in user.get("tenant"):
        return HTTPException(status_code=404)

    caseDB["assigned_to"].append(username)
    caseDB["update_date"] = str(datetime.now())
    casesDB.delete_one({"_id": caseDB["_id"]})
    del caseDB["_id"]
    casesDB.insert_one(caseDB)
    return {"status": "Update"}


@app.post("/api/v1/case/update/{id}", tags=["Case"])
async def updateCase(case: U.CaseUpdate, id: int, user: U.User = Depends(get_current_active_user)):
    casesDB = db["Incidents"]
    caseDB = casesDB.find_one({"id": id})
    if not caseDB:
        return HTTPException(status_code=404, detail="Case not foud")

    if user.get("username") not in caseDB["assigned_to"] or caseDB["tenant"] not in user.get("tenant"):
        return HTTPException(status_code=404)

    if case.field.lower() in ["close", "status"]:
        caseDB["close_date"] = str(datetime.now())
        caseDB["status"] = case.value

    if case.field.lower() in ["text", "info"]:
        caseDB["text"] = case.value

    if case.field.lower() in ["add_user", "assigned_to"]:
        if not caseDB.get("assigned_to"):
            caseDB["assigned_to"] = []
        caseDB["assigned_to"].append(case.value)

    if not caseDB.get("observable"):
        caseDB["observable"] = {}
    if case.field.lower() in ["intelligence", "ioc"]:
        if not caseDB["observable"].get("intelligence"):
            caseDB["observable"]["intelligence"] = []
        if case.value not in caseDB["observable"]["intelligence"]:
            caseDB["observable"]["intelligence"].append({**checkReputationIOC(case.value), "info": case.info})

    if case.field.lower() in ["offense"]:
        if not caseDB["observable"].get("offense"):
            caseDB["observable"]["offense"] = []
        if case.value not in caseDB["observable"]["offense"]:
            caseDB["observable"]["offense"].append(case.value)
    if case.field.lower() in ["edr"]:
        if not caseDB["observable"].get("EDR"):
            caseDB["observable"]["EDR"] = []
        if case.value not in caseDB["observable"]["EDR"]:
            caseDB["observable"]["EDR"].append(case.value)
    if case.field.lower() in ["alert"]:
        if not caseDB["observable"].get("alert"):
            caseDB["observable"]["alert"] = []
        if case.value not in caseDB["observable"]["alert"]:
            caseDB["observable"]["alert"].append(case.value)

    if case.field.lower() in ["send"]:
        if case.value.lower() == "soc":
            caseDB["mail"] = "soc"
        elif case.value.lower() == "customer":
            caseDB["mail"] = "customer"
        email = {}
        if caseDB["mail"] == "customer":
            email = db["Templates"].find_one({"type": "config"})["mail"].get(caseDB["customer"].upper())
        elif caseDB["mail"] == "soc":
            email = db["Templates"].find_one({"type": "config"})["mail"].get("ONS")
        if email and email.get("to"):
            caseDB["mail_status"] = "send"
            caseDB["mail_date_send"] = str(datetime.now())
            Email.Mailer().sendMail(email.get("to"), caseDB["title"], caseDB["text"], email.get("cc"))
        else:
            caseDB["mail_status"] = "send-error"
            email = db["Templates"].find_one({"type": "config"})["mail"].get("ONS")
            Email.Mailer().sendMail(email.get("to"), "SEND ERROR", caseDB["title"] + caseDB["text"], email.get("cc"))

    caseDB["update_date"] = str(datetime.now())
    casesDB.delete_one({"_id": caseDB["_id"]})
    del caseDB["_id"]
    casesDB.insert_one(caseDB)
    return {"status": "Update"}


@app.get("/api/v1/case/update/{id}/delete/{ioc}", tags=["Case"])
async def updateCase(id: int, ioc: str, user: U.User = Depends(get_current_active_user)):
    casesDB = db["Incidents"]
    caseDB = casesDB.find_one({"id": id})
    if not caseDB:
        return HTTPException(status_code=404, detail="Case not foud")

    if user.get("username") not in caseDB["assigned_to"] or caseDB["tenant"] not in user.get("tenant"):
        return HTTPException(status_code=404)

    try:
        for i in range(len(caseDB["observable"]["intelligence"])):
            if caseDB["observable"]["intelligence"][i]["obj"].lower() == ioc.lower():
                del caseDB["observable"]["intelligence"][i]
                break
        caseDB["update_date"] = str(datetime.now())
        casesDB.delete_one({"_id": caseDB["_id"]})
        del caseDB["_id"]
        casesDB.insert_one(caseDB)
    except:
        pass

    return {"status": "Update"}


@app.post("/api/v1/incident/replace", tags=["Case"])
async def replaceText(case: U.replaceText, user: U.User = Depends(get_current_active_user)):
    return case.text.replace(case.field, case.value)


# Fine Case

# CTI
@app.get("/api/v1/cti/reputation/{obj}", tags=["CTI"])
async def reputation(obj, user: U.User = Depends(get_current_active_user)):
    return requests.get(Config.APIv4 + "/api/v4/search/" + obj, verify=False).json()


@app.get("/api/v1/cti/url/scan/{obj}", tags=["CTI"])
async def reputation(obj, user: U.User = Depends(get_current_active_user)):
    if Check.ishash(obj):
        return {"status": "404"}
    cache = db["Cache"]
    reputation = cache.find_one({"url-target": obj})
    if reputation:
        del reputation["_id"]
        return reputation
    urlScan = Feeds.urlScan(obj)
    urlScan["url-target"] = obj
    cache.insert_one(urlScan)
    del urlScan["_id"]
    return urlScan


@app.get("/api/v1/cti/reputation/{obj}/cache", tags=["CTI"])
async def reputation(obj, user: U.User = Depends(get_current_active_user)):
    cache = db["Cache"]
    reputation = cache.find_one({"target": obj})
    if reputation:
        del reputation["_id"]
        return reputation
    reputation = requests.get(Config.APIv4 + "/api/v4/search/user/" + obj, verify=False).json()
    reputation["target"] = reputation["obj"]

    if ((reputation["risk_score"] > 2 and reputation["confidence"] > 2) or reputation["tag"] == "malicious") and \
            reputation["tag"] != "trusted":
        reputation["action"] = "block"
    elif reputation["risk_score"] >= 2:
        reputation["action"] = "suspicious"
    else:
        reputation["action"] = "allow"
    try:
        cache.insert_one(reputation)
    except:
        pass
    try:
        del reputation["_id"]
    except:
        pass
    return reputation


@app.get("/api/v1/cti/add/{obj}/{ZeroFeed}/{tag}", tags=["CTI"])
async def reputation(obj, ZeroFeed: bool, tag: str, user: U.User = Depends(get_current_active_user)):
    if not Auth.authorizationRole(user.get("role"), Config.RolesModel.get("otifBlock")):
        return HTTPException(status_code=403, detail="Forbidden")
    cache = db["Cache"]
    tag = tag.lower()
    if tag not in ["malicious", "mass-scanner", "monitor"]:
        return HTTPException(status_code=404, detail="Tag not found")
    requests.post(Config.APIv4 + "/api/v4/upload/obj",
                  json={"obj": obj, "ZeroFeed": bool(ZeroFeed), "tag": tag, "source": "VSP " + user.get("username")},
                  verify=False)
    cache.delete_one({"target": obj})
    return {"Status": "ok"}


@app.post("/api/v1/cti/color_link/tag/mitre", tags=["CTI"])
async def getColor(dataRow: Request, user: U.User = Depends(get_current_active_user)):
    json = await dataRow.json()
    color = db["Config"].find_one({"type": "color-tags"}).get("color")
    tmp = {}

    for j in json:
        if type(j) is not str:
            continue
        tmp[j] = {"color": "#" + ''.join([random.choice('ABCDEF0123456789') for i in range(6)])}
        for k in color.keys():
            if j.lower().find(k.lower()) != -1:
                tmp[j] = {"color": color[k]}
                break
        if j.find(" - ") != -1 and j.split(" - ")[0].find("TA") != -1:
            tec = j.split(" - ")[0]
            if tec.find("."):
                try:
                    tec = tec.split(".")[0] + "/" + tec.split(".")[1]
                except:
                    tec = tec.split(".")[0]
            tmp[j]["link"] = "https://attack.mitre.org/tactics/" + tec + "/"
        elif j.find(" - ") != -1 and j.split(" - ")[0].find("T") != -1:
            tec = j.split(" - ")[0]
            if tec.find("."):
                try:
                    tec = tec.split(".")[0] + "/" + tec.split(".")[1]
                except:
                    tec = tec.split(".")[0]
            tmp[j]["link"] = "https://attack.mitre.org/techniques/" + tec + "/"
        elif j.find(" - ") != -1 and j.split(" - ")[0].find("M") != -1:
            tec = j.split(" - ")[0]
            if tec.find("."):
                try:
                    tec = tec.split(".")[0] + "/" + tec.split(".")[1]
                except:
                    tec = tec.split(".")[0]
            tmp[j]["link"] = "https://attack.mitre.org/mitigations/" + tec + "/"
        elif j.find(" - ") != -1 and j.split(" - ")[0].find("G") != -1:
            tec = j.split(" - ")[0]
            if tec.find("."):
                try:
                    tec = tec.split(".")[0] + "/" + tec.split(".")[1]
                except:
                    tec = tec.split(".")[0]
            tmp[j]["link"] = "https://attack.mitre.org/groups/" + tec + "/"
        elif j.find(" - ") != -1 and j.split(" - ")[0].find("C") != -1:
            tec = j.split(" - ")[0]
            if tec.find("."):
                try:
                    tec = tec.split(".")[0] + "/" + tec.split(".")[1]
                except:
                    tec = tec.split(".")[0]
            tmp[j]["link"] = "https://attack.mitre.org/campaigns/" + tec + "/"
        elif j.find(" - ") != -1 and j.split(" - ")[0].find("S") != -1:
            tec = j.split(" - ")[0]
            if tec.find("."):
                try:
                    tec = tec.split(".")[0] + "/" + tec.split(".")[1]
                except:
                    tec = tec.split(".")[0]
            tmp[j]["link"] = "https://attack.mitre.org/software/" + tec + "/"
        else:
            tmp[j]["link"] = ""
    return tmp


# Fine CTI

# Mail
@app.post("/api/v1/email", tags=["Other"])
async def mailer(mail: U.Mail, user: U.User = Depends(get_current_active_user)):
    Email.Mailer().sendMail(mail.mail_to, mail.subject, mail.text)
    return {"E-Mail": "send"}


@app.get("/api/v1/email/receive", tags=["Other"])
async def mailer(user: U.User = Depends(get_current_active_user)):
    return Email.Mailer().getAllMails()


@app.get("/api/v1/email/receive/filter/to/{email}", tags=["Other"])
async def mailer(email: str, user: U.User = Depends(get_current_active_user)):
    return Email.Mailer().getAllMails(TO=email)


@app.get("/api/v1/email/receive/filter/from/{email}", tags=["Other"])
async def mailer(email: str, user: U.User = Depends(get_current_active_user)):
    return Email.Mailer().getAllMails(FROM=email)


@app.get("/api/v1/email/receive/filter/body/{body}", tags=["Other"])
async def mailer(body: str, user: U.User = Depends(get_current_active_user)):
    return Email.Mailer().getAllMails(BODY=body)


@app.get("/api/v1/email/receive/filter/subject/{subject}", tags=["Other"])
async def mailer(subject: str, user: U.User = Depends(get_current_active_user)):
    return Email.Mailer().getAllMails(SUBJECT=subject)


@app.post("/api/v1/email/ticket/{customer}", tags=["Other"])
async def mailer(mail: U.MailCustomer, customer: str, user: U.User = Depends(get_current_active_user)):
    mailTo = db["Templates"].find_one({"type": "config"})
    if not customer:
        return HTTPException(status_code=404)
    if not mailTo.get("mail") or not mailTo.get("mail").get(customer.replace(" ", "").upper()):
        return HTTPException(status_code=404)
    mails = mailTo.get("mail").get(customer.replace(" ", "").upper())
    gmail = Email.Mailer()
    gmail.sendMail(mails.get("to"), mail.subject, mail.text, mails.get("cc"))
    return {"E-Mail": "send"}


# Fine Mail
# Chat
@app.get("/api/v1/email/chat/{customer}", tags=["CHAT"])
async def chat(customer: str, user: U.User = Depends(get_current_active_user)):
    customer = customer.replace(" ", "").upper()
    chatDB = db["Chat"].find({"customer": customer})
    tmp = []
    for chat in chatDB:
        del chat["_id"]
        if chat["subject"].find("<") != -1 and chat["subject"].find(">--<") != -1 and chat["subject"].find(">") != -1:
            chat["subject"] = chat["subject"].split(">--<")[1]
        tmp.append(chat)
    return tmp


@app.get("/api/v1/email/chat/{customer}/{id}", tags=["CHAT"])
async def chat(id: int, user: U.User = Depends(get_current_active_user)):
    chatDB = db["Chat"].find_one({"id": id})
    del chatDB["_id"]
    return chatDB


@app.post("/api/v1/email/chat/{customer}/new", tags=["CHAT"])
async def chat(customer: str, msg: U.Chat, user: U.User = Depends(get_current_active_user)):
    customer = customer.replace(" ", "").upper()
    chat = db["Chat"]
    id = chat.count_documents({})
    gmail = Email.Mailer()
    while chat.find_one({"id": id}):
        id += 1
    mailCustomer = db["Templates"].find_one({"type": "config"}).get("mail").get(customer)
    subject = f"<{customer}>--<{msg.subject}>--<{id}>"
    text = msg.text
    gmail.sendMail(mailCustomer.get("to"), subject, text, mailCustomer.get("cc"))
    chat.insert_one({"id": id, "sender": msg.sender, "customer": customer, "subject": subject, "orgin-subject": msg.subject, "msg": [{"by": "CC", "text": text, "time": datetime.now().strftime("%d/%m/%Y %H:%M:%S")}], "mails": mailCustomer, "create_chat": datetime.now(), "update_chat": datetime.now()})
    return {"status": "start chat", "id": id, "customer": customer}


@app.put("/api/v1/email/chat/customer/msg/{id}", tags=["CHAT"])
async def chat(msg: U.ChatMsg, id: int, user: U.User = Depends(get_current_active_user)):
    chat = db["Chat"]
    chatCustomer = chat.find_one({"id": id})
    if not chatCustomer:
        return HTTPException(status_code=400, detail="Chat not foud")
    gmail = Email.Mailer()
    mailCustomer = db["Templates"].find_one({"type": "config"}).get("mail").get(chatCustomer["customer"])
    gmail.sendMail(chatCustomer["sender"], chatCustomer["orgin-subject"], msg.text, mailCustomer.get("cc"))
    chatCustomer["update_chat"] = datetime.now()

    chatCustomer["msg"].append({"by": "CC", "text": msg.text, "time": datetime.now().strftime("%d/%m/%Y %H:%M:%S")})
    chat.delete_one({"_id": chatCustomer["_id"]})
    del chatCustomer["_id"]
    chat.insert_one(chatCustomer)
    return {"status": "send msg", "id": id}


@app.get("/api/v1/email/chat/{customer}/msg/{id}", tags=["CHAT"])
async def chat(customer: str, id: int, user: U.User = Depends(get_current_active_user)):
    customer = customer.replace(" ", "").upper()
    chat = db["Chat"]
    chatCustomer = chat.find_one({"customer": customer, "id": id})
    if not chatCustomer:
        return HTTPException(status_code=400, detail="Chat not foud")
    msgNotRead = []
    gmail = Email.Mailer()
    emails = gmail.getAllMails(SUBJECT=chatCustomer["subject"])
    chatCustomer["update_chat"] = datetime.now()
    for email in emails:
        read = False
        for emailDB in chatCustomer["msg"]:
            if email["body"].lower() == emailDB["text"].lower():
                read = True
                break
        if read is False:
            chatCustomer["msg"].append({"by": "Customer", "text": email["body"], "time": datetime.now().strftime("%d/%m/%Y %H:%M:%S")})
            msgNotRead.append(email["body"])
    chat.delete_one({"_id": chatCustomer["_id"]})
    del chatCustomer["_id"]
    chat.insert_one(chatCustomer)
    return {"status": "receive msg", "id": id, "customer": customer, "msg": msgNotRead}


@app.put("/api/v1/email/chat/{customer}/msg/{id}/customer", tags=["CHAT"])
async def chat(customer: str, msg: U.ChatMsg, id: int, user: U.User = Depends(get_current_active_user)):
    customer = customer.replace(" ", "").upper()
    chat = db["Chat"]
    chatCustomer = chat.find_one({"customer": customer, "id": id})
    if not chatCustomer:
        return HTTPException(status_code=400, detail="Chat not foud")
    #gmail = Email.Mailer()
    #gmail.sendMail(chatCustomer["mails"]["to"], chatCustomer["subject"], msg.text, chatCustomer["mails"]["cc"])
    chatCustomer["update_chat"] = datetime.now()
    chatCustomer["msg"].append({"by": "customer", "text": msg.text, "time": datetime.now().strftime("%d/%m/%Y %H:%M:%S")})
    chat.delete_one({"_id": chatCustomer["_id"]})
    del chatCustomer["_id"]
    chat.insert_one(chatCustomer)
    return {"status": "send msg", "id": id, "customer": customer}


@app.post("/api/v1/email/chat/{customer}/new/customer", tags=["CHAT"])
async def chat(customer: str, msg: U.Chat, user: U.User = Depends(get_current_active_user)):
    customer = customer.replace(" ", "").upper()
    chat = db["Chat"]
    id = chat.count_documents({})
    #gmail = Email.Mailer()
    while chat.find_one({"id": id}):
        id += 1
    mailCustomer = db["Templates"].find_one({"type": "config"}).get("mail").get(customer)
    subject = f"<{customer}>--<{msg.subject}>--<{id}>"
    text = msg.text
    #gmail.sendMail(mailCustomer.get("to"), subject, text, mailCustomer.get("cc"))
    chat.insert_one({"id": id, "sender": msg.sender, "customer": customer, "orgin-subject": msg.subject, "subject": subject, "msg": [{"by": "customer", "text": text, "time": datetime.now().strftime("%d/%m/%Y %H:%M:%S")}], "mails": mailCustomer, "create_chat": datetime.now(), "update_chat": datetime.now()})
    return {"status": "start chat", "id": id, "customer": customer}
# Fine Chat

# Wazuh
@app.get("/api/v1/wazuh/{customer}", tags=["SIEM", "Wazuh"])
async def wazuh(customer: str, user: U.User = Depends(get_current_active_user)):
    customer = db["Customers"].find_one({"identify": customer})
    if not customer or not customer.get("asset") or not customer.get("asset").get("Wazuh") or not customer.get(
            "asset").get("Wazuh").get("ip"):
        return HTTPException(status_code=404)
    wazuh = Wazuh.Wazuh(customer.get("asset").get("Wazuh").get("ip"))
    return wazuh.info()


@app.get("/api/v1/wazuh/{customer}/agents", tags=["SIEM", "Wazuh"])
async def wazuh(customer: str, user: U.User = Depends(get_current_active_user)):
    customer = db["Customers"].find_one({"identify": customer})
    if not customer or not customer.get("asset") or not customer.get("asset").get("Wazuh") or not customer.get(
            "asset").get("Wazuh").get("ip"):
        return HTTPException(status_code=404)
    wazuh = Wazuh.Wazuh(customer.get("asset").get("Wazuh").get("ip"))
    return wazuh.getAgentsList()


@app.get("/api/v1/wazuh/{customer}/agents", tags=["SIEM", "Wazuh"])
async def wazuh(customer: str, user: U.User = Depends(get_current_active_user)):
    customer = db["Customers"].find_one({"identify": customer})
    if not customer or not customer.get("asset") or not customer.get("asset").get("Wazuh") or not customer.get(
            "asset").get("Wazuh").get("ip"):
        return HTTPException(status_code=404)
    wazuh = Wazuh.Wazuh(customer.get("asset").get("Wazuh").get("ip"))
    return wazuh.getAgentsList()


@app.get("/api/v1/wazuh/{customer}/agents/agent/{id}", tags=["SIEM", "Wazuh"])
async def wazuh(customer: str, id: str, user: U.User = Depends(get_current_active_user)):
    customer = db["Customers"].find_one({"identify": customer})
    if not customer or not customer.get("asset") or not customer.get("asset").get("Wazuh") or not customer.get(
            "asset").get("Wazuh").get("ip"):
        return HTTPException(status_code=404)
    wazuh = Wazuh.Wazuh(customer.get("asset").get("Wazuh").get("ip"))
    return wazuh.infoAgent(id)


@app.get("/api/v1/wazuh/{customer}/asset/status", tags=["SIEM", "Wazuh"])
async def wazuh(customer: str, user: U.User = Depends(get_current_active_user)):
    customer = db["Customers"].find_one({"identify": customer})
    if not customer or not customer.get("asset") or not customer.get("asset").get("Wazuh") or not customer.get(
            "asset").get("Wazuh").get("ip"):
        return HTTPException(status_code=404)
    wazuh = Wazuh.Wazuh(customer.get("asset").get("Wazuh").get("ip"))
    return wazuh.statusAsset()


# Fine Wazuh

# Engine
@app.get("/api/v1/engine/analyst/{customer}/config", tags=["SIEM", "Engine"])
async def analystEngine(customer: str, user: U.User = Depends(get_current_active_user)):
    config = db["Config"].find_one({"type": "Analyst-Engine-" + customer.upper()})
    if not config:
        return HTTPException(status_code=400)
    del config["_id"]
    return config


@app.patch("/api/v1/engine/analyst/{customer}/config/enable/{status}", tags=["SIEM", "Engine"])
async def analystEngine(customer: str, status: bool, user: U.User = Depends(get_current_active_user)):
    config = db["Config"].find_one({"type": "Analyst-Engine-" + customer.upper()})
    if not config:
        return HTTPException(status_code=400)
    db["Config"].delete_one({"_id": config["_id"]})
    del config["_id"]
    config["status"] = status
    db["Config"].insert_one(config)
    del config["_id"]
    return config


@app.patch("/api/v1/engine/analyst/{customer}/config/after_time", tags=["SIEM", "Engine"])
async def analystEngine(customer: str, time: U.time, user: U.User = Depends(get_current_active_user)):
    config = db["Config"].find_one({"type": "Analyst-Engine-" + customer.upper()})
    if not config:
        return HTTPException(status_code=400)
    db["Config"].delete_one({"_id": config["_id"]})
    del config["_id"]
    config["after-time"] = time.minutes
    db["Config"].insert_one(config)
    del config["_id"]
    return config


@app.patch("/api/v1/engine/analyst/{customer}/config/level/{level}", tags=["SIEM", "Engine"])
async def analystEngine(customer: str, level: str, user: U.User = Depends(get_current_active_user)):
    config = db["Config"].find_one({"type": "Analyst-Engine-" + customer.upper()})
    if not config:
        return HTTPException(status_code=400)
    if level.lower() not in ["base", "medium", "advanced"]:
        return HTTPException(status_code=404)
    level = level.lower()
    db["Config"].delete_one({"_id": config["_id"]})
    del config["_id"]
    config["level"] = level
    db["Config"].insert_one(config)
    del config["_id"]
    return config


@app.patch("/api/v1/engine/analyst/{customer}/config/note", tags=["SIEM", "Engine"])
async def analystEngine(customer: str, note: U.note, user: U.User = Depends(get_current_active_user)):
    config = db["Config"].find_one({"type": "Analyst-Engine-" + customer.upper()})
    if not config:
        return HTTPException(status_code=400)
    if not config.get("note"):
        config["note"] = {}
    if note.false_positive:
        config["note"]["false_positive"] = note.false_positive
    if note.true_positive:
        config["note"]["true_positive"] = note.true_positive
    if note.non_issue:
        config["note"]["non_issue"] = note.non_issue
    if note.error_note:
        config["note"]["error_note"] = note.error_note
    db["Config"].delete_one({"_id": config["_id"]})
    del config["_id"]
    db["Config"].insert_one(config)
    del config["_id"]
    return config


@app.patch("/api/v1/engine/analyst/{customer}/config/role/{role_name}/blacklist", tags=["SIEM", "Engine"])
async def analystEngine(customer: str, role_name: str, user: U.User = Depends(get_current_active_user)):
    config = db["Config"].find_one({"type": "Analyst-Engine-" + customer.upper()})
    if not config:
        return HTTPException(status_code=400)
    if config.get("roles"):
        db["rules"] = []
    db["Config"].delete_one({"_id": config["_id"]})
    config["rules"].append(role_name.lower())
    del config["_id"]
    db["Config"].insert_one(config)
    del config["_id"]
    return config


@app.delete("/api/v1/engine/analyst/{customer}/config/role/{role_name}/blacklist", tags=["SIEM", "Engine"])
async def analystEngine(customer: str, role_name: str, user: U.User = Depends(get_current_active_user)):
    config = db["Config"].find_one({"type": "Analyst-Engine-" + customer.upper()})
    if not config:
        return HTTPException(status_code=400)
    if config.get("roles"):
        db["roles"] = []
    db["Config"].delete_one({"_id": config["_id"]})
    config["rules"].remove(role_name.lower())
    del config["_id"]
    db["Config"].insert_one(config)
    del config["_id"]
    return config


@app.patch("/api/v1/engine/analyst/{customer}/config/service-window", tags=["SIEM", "Engine"])
async def analystEngine(customer: str, window: U.serviceWindow, user: U.User = Depends(get_current_active_user)):
    config = db["Config"].find_one({"type": "Analyst-Engine-" + customer.upper()})
    if not config:
        return HTTPException(status_code=400)
    if not config.get("service-window"):
        config["service-window"] = {"days": window.days}
    else:
        config["service-window"]["days"] = window.days

    if window.timeType == "h24":
        config["service-window"]["type"] = "h24"
    elif window.timeType == "h12":
        config["service-window"]["type"] = "h12"
    elif window.timeType == "h8":
        config["service-window"]["type"] = "h8"
    elif window.timeType == "custom" and window.timeFrom and window.timeTo:
        config["service-window"]["type"] = "custom"
        config["service-window"]["from"] = window.timeFrom
        config["service-window"]["to"] = window.timeTo

    db["Config"].delete_one({"_id": config["_id"]})
    del config["_id"]
    db["Config"].insert_one(config)
    del config["_id"]
    return config


@app.get("/api/v1/engine/analyst/{customer}/{id}", tags=["SIEM", "Engine"])
async def analystEngine(customer: str, id: str, user: U.User = Depends(get_current_active_user)):
    analystDB = db["Analyst"].find_one({"id": id, "customer": customer})
    if not analystDB:
        return HTTPException(status_code=404)
    del analystDB["_id"]
    return analystDB


@app.post("/api/v1/engine/communication/socket", tags=["Engine"])
async def analystEngine(data: U.Socket, user: U.User = Depends(get_current_active_user)):
    client_socket = socket.socket()
    client_socket.connect((Config.ipSocket, Config.portSocket))

    message = json.dumps(data.json())
    client_socket.send(message.encode())
    s = client_socket.recv(1024).decode()
    analysis = client_socket.recv(1024).decode()
    client_socket.send(json.dumps({"status": "close"}).encode())
    client_socket.close()
    return json.loads(analysis)


@app.get("/api/v1/engine/proactive/create/agent/script/{customer}/{host_identifier}", tags=["Engine"])
async def proactiveEngine(customer, host_identifier, user: U.User = Depends(get_current_active_user)):
    PEDB = pymongo.MongoClient(Config.DBAUTHSTRVSP_PE)["feedsTI"]
    if not PEDB["Proactive"].find_one({"host_identifier": host_identifier, "customer": customer}):
        data = {"host_identifier": host_identifier, "customer": customer, "status": "active", "create": datetime.now(),
                "createBy": user.get("username"), "type": "script"}
        PEDB["Proactive"].insert_one(data)

    token = create_access_token(
        data={"sub": user.get("username")}, expires_delta=timedelta(days=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    script = agentPE.getConnections_Process
    script = script.replace("<token>", token)
    script = script.replace("<identifier>", host_identifier)
    script = script.replace("<customer>", customer)
    fileScript = open(Config.fileAgent + "script.txt", "w")
    fileScript.write(script)
    return FileResponse(path=Config.fileAgent + "script.txt", filename="script.txt")


@app.get("/api/v1/engine/proactive/status/{customer}", tags=["Engine"])
async def proactiveEngine(customer, user: U.User = Depends(get_current_active_user)):
    reports = []
    PEDB = pymongo.MongoClient(Config.DBAUTHSTRVSP_PE)["feedsTI"]
    for report in PEDB["Proactive"].find({"customer": customer}):
        del report["_id"]
        reports.append(report)
    return reports


@app.get("/api/v1/engine/proactive/report/{customer}/{host_identifier}", tags=["Engine"])
async def proactiveEngine(customer, host_identifier, user: U.User = Depends(get_current_active_user)):
    PEDB = pymongo.MongoClient(Config.DBAUTHSTRVSP_PE)["feedsTI"]
    data = PEDB["Proactive"].find_one({"customer": customer, "host_identifier": host_identifier})
    if data:
        del data["_id"]
        return data
    return HTTPException(status_code=404, detail="Agent non found")


@app.get("/api/v1/engine/automations/list", tags=["Engine"])
async def automationsEngine(user: U.User = Depends(get_current_active_user)):
    automations = db["Automations"].find({})
    tmp = []
    for auto in automations:
        del auto["_id"]
        tmp.append(auto)
    return tmp


@app.get("/api/v1/engine/automation/{name}", tags=["Engine"])
async def automationsEngine(name: str, user: U.User = Depends(get_current_active_user)):
    automation = db["Automations"].find_one({"name": name})
    if automation:
        del automation["_id"]
        return automation
    return HTTPException(status_code=404, detail="Automation not found")


@app.post("/api/v1/engine/automations/create", tags=["Engine"])
async def automationsEngine(dataRow: Request, user: U.User = Depends(get_current_active_user)):
    json = await dataRow.json()
    if not json.get("name"):
        return HTTPException(status_code=400)
    automations = db["Automations"]
    if automations.find_one({"name": json["name"]}):
        automations.delete_one({"name": json["name"]})
        json["status"] = True
        automations.insert_one(json)
        return {"status": "automations update"}
    # elaborazione json
    json["status"] = True

    automations.insert_one(json)
    return {"status": "automations create"}


@app.get("/api/v1/engine/analysis/assets/{customer}", tags=["Engine"])
async def usersEngine(customer, user: U.User = Depends(get_current_active_user)):
    tmp = {}
    if customer.upper() == "ALL":
        assets = db["Assets"].find({})
    else:
        assets = db["Assets"].find({"customer": customer.upper()})
    analysis = db["Assets_Analysis"]
    for asset in assets:
        if asset.get("hostnames"):
            type = "hostnames"
        elif asset.get("ip"):
            type = "ip"
        else:
            continue
        for host in asset[type]:
            if host not in tmp.keys():
                t = asset
                try:
                    del t["_id"]
                except:
                    pass
                if customer.upper() == "ALL":
                    findR = analysis.find_one({"name": host, "type": "asset"})
                else:
                    findR = analysis.find_one({"name": host, "type": "asset", "customer": customer.upper()})
                if findR and findR.get("score"):
                    t["score"] = findR.get("score")
                else:
                    t["score"] = 0
                tmp[host] = t
    return tmp


@app.get("/api/v1/engine/analysis/users/{customer}", tags=["Engine"])
async def usersEngine(customer, user: U.User = Depends(get_current_active_user)):
    tmp = {}
    if customer.upper() == "ALL":
        assets = db["Assets"].find({})
    else:
        assets = db["Assets"].find({"customer": customer.upper()})
    analysis = db["Assets_Analysis"]
    for asset in assets:
        if not asset.get("users"):
            continue
        for user in asset["users"]:
            if user not in tmp.keys():
                t = asset
                try:
                    del t["_id"]
                except:
                    pass
                if customer.upper() == "ALL":
                    findR = analysis.find_one({"name": user, "type": "user"})
                else:
                    findR = analysis.find_one({"name": user, "type": "user", "customer": customer.upper()})
                if findR and findR.get("score"):
                    t["score"] = findR.get("score")
                else:
                    t["score"] = 0
                tmp[user] = t
    return tmp


# Fine Engine
# Reaqta

@app.get("/api/v1/ReaQta/{customer}/health", tags=["ReaQta", "Health"])
async def reaqta(customer: str, user: U.User = Depends(get_current_active_user)):
    try:
        customer = customer.upper()
        authReaQta = user["key"]["ReaQta"][customer]
    except:
        return HTTPException(status_code=403, detail="User not found")

    try:
        ReaQta.ReaQta(authReaQta["token"], authReaQta["id"])
        return {"status": "online"}
    except:
        return {"status": "offline"}


@app.get("/api/v1/ReaQta/{customer}/alerts", tags=["ReaQta"])
async def reaqta(customer: str, user: U.User = Depends(get_current_active_user)):
    try:
        customer = customer.upper()
        authReaQta = user["key"]["ReaQta"][customer]
    except:
        return HTTPException(status_code=403, detail="User not found")
    agent = ReaQta.ReaQta(authReaQta["token"], authReaQta["id"])
    tmp = agent.getAlerts()
    if not tmp.get("result"):
        return tmp
    return agent.filterCustomer(tmp["result"], customer)


@app.get("/api/v1/ReaQta/{customer}/alert/{idAlert}", tags=["ReaQta"])
async def reaqta(customer: str, idAlert: str, user: U.User = Depends(get_current_active_user)):
    try:
        customer = customer.upper()
        authReaQta = user["key"]["ReaQta"][customer]
    except:
        return HTTPException(status_code=403, detail="User not found")
    agent = ReaQta.ReaQta(authReaQta["token"], authReaQta["id"])
    return agent.getAlert(idAlert)


@app.get("/api/v1/ReaQta/{customer}/alert/{idAlert}/events", tags=["ReaQta"])
async def reaqta(customer: str, idAlert: str, user: U.User = Depends(get_current_active_user)):
    try:
        customer = customer.upper()
        authReaQta = user["key"]["ReaQta"][customer]
    except:
        return HTTPException(status_code=403, detail="User not found")
    agent = ReaQta.ReaQta(authReaQta["token"], authReaQta["id"])
    return agent.getAlertEvents(idAlert)


@app.get("/api/v1/ReaQta/{customer}/assets", tags=["ReaQta"])
async def reaqta(customer: str, user: U.User = Depends(get_current_active_user)):
    try:
        customer = customer.upper()
        authReaQta = user["key"]["ReaQta"][customer]
    except:
        return HTTPException(status_code=403, detail="User not found")
    agent = ReaQta.ReaQta(authReaQta["token"], authReaQta["id"])
    tmp = agent.getAssets()
    if not tmp.get("result"):
        return tmp
    return agent.filterCustomer(tmp["result"], customer)


@app.get("/api/v1/ReaQta/{customer}/asset/{idAsset}", tags=["ReaQta"])
async def reaqta(customer: str, idAsset: str, user: U.User = Depends(get_current_active_user)):
    try:
        customer = customer.upper()
        authReaQta = user["key"]["ReaQta"][customer]
    except:
        return HTTPException(status_code=403, detail="User not found")
    agent = ReaQta.ReaQta(authReaQta["token"], authReaQta["id"])
    return agent.getAsset(idAsset)


@app.get("/api/v1/ReaQta/{customer}/asset/{idAsset}/ping", tags=["ReaQta"])
async def reaqta(customer: str, idAsset: str, user: U.User = Depends(get_current_active_user)):
    try:
        customer = customer.upper()
        authReaQta = user["key"]["ReaQta"][customer]
    except:
        return HTTPException(status_code=403, detail="User not found")
    agent = ReaQta.ReaQta(authReaQta["token"], authReaQta["id"])
    return agent.pingAsset(idAsset)


@app.get("/api/v1/ReaQta/{customer}/asset/{idAsset}/process/show", tags=["ReaQta"])
async def reaqta(customer: str, idAsset: str, user: U.User = Depends(get_current_active_user)):
    try:
        customer = customer.upper()
        authReaQta = user["key"]["ReaQta"][customer]
    except:
        return HTTPException(status_code=403, detail="User not found")
    agent = ReaQta.ReaQta(authReaQta["token"], authReaQta["id"])
    ping = agent.pingAsset(idAsset)
    if not ping.get("message") or not ping.get("message") == "PONG":
        return ping
    return agent.getProcessesAsset(idAsset)


@app.get("/api/v1/ReaQta/{customer}/asset/{idAsset}/proces/{pid}", tags=["ReaQta"])
async def reaqta(customer: str, idAsset: str, pid: str, user: U.User = Depends(get_current_active_user)):
    try:
        customer = customer.upper()
        authReaQta = user["key"]["ReaQta"][customer]
    except:
        return HTTPException(status_code=403, detail="User not found")
    try:
        pid = int(pid)
    except:
        return HTTPException(status_code=404, detail="error pid")
    agent = ReaQta.ReaQta(authReaQta["token"], authReaQta["id"])
    ping = agent.pingAsset(idAsset)
    if not ping.get("message") or not ping.get("message") == "PONG":
        return ping
    process = agent.getProcessesAsset(idAsset)
    for proces in process:
        if proces["pid"] == pid:
            return {"proces": "Is running"}
    return {"proces": "Isn't running"}


@app.get("/api/v1/ReaQta/{customer}/asset/{idAsset}/isolate", tags=["ReaQta"])
async def reaqta(customer: str, idAsset: str, user: U.User = Depends(get_current_active_user)):
    try:
        customer = customer.upper()
        authReaQta = user["key"]["ReaQta"][customer]
    except:
        return HTTPException(status_code=403, detail="User not found")
    agent = ReaQta.ReaQta(authReaQta["token"], authReaQta["id"])
    return agent.isolateAsset(idAsset)


@app.get("/api/v1/ReaQta/{customer}/asset/{idAsset}/deisolate", tags=["ReaQta"])
async def reaqta(customer: str, idAsset: str, user: U.User = Depends(get_current_active_user)):
    try:
        customer = customer.upper()
        authReaQta = user["key"]["ReaQta"][customer]
    except:
        return HTTPException(status_code=403, detail="User not found")
    agent = ReaQta.ReaQta(authReaQta["token"], authReaQta["id"])
    return agent.deisolateAsset(idAsset)


@app.get("/api/v1/ReaQta/{customer}/asset/{idAsset}/proces/{pid}/kill", tags=["ReaQta"])
async def reaqta(customer: str, idAsset: str, pid: str, user: U.User = Depends(get_current_active_user)):
    try:
        customer = customer.upper()
        authReaQta = user["key"]["ReaQta"][customer]
    except:
        return HTTPException(status_code=403, detail="User not found")
    try:
        pid = int(pid)
    except:
        return HTTPException(status_code=404, detail="error pid")
    agent = ReaQta.ReaQta(authReaQta["token"], authReaQta["id"])
    ping = agent.pingAsset(idAsset)
    if not ping.get("message") or not ping.get("message") == "PONG":
        return ping
    return agent.killProcesseAsset(idAsset, pid, str(datetime.now()))


@app.get("/api/v1/ReaQta/{customer}/asset/{idAsset}/file/download/{path}", tags=["ReaQta"])
async def reaqta(customer: str, idAsset: str, path: str, user: U.User = Depends(get_current_active_user)):
    try:
        customer = customer.upper()
        authReaQta = user["key"]["ReaQta"][customer]
    except:
        return HTTPException(status_code=403, detail="User not found")

    agent = ReaQta.ReaQta(authReaQta["token"], authReaQta["id"])
    ping = agent.pingAsset(idAsset)
    if not ping.get("message") or not ping.get("message") == "PONG":
        return ping
    fileRequest = agent.requestFileAsset(idAsset, path)
    if not fileRequest.get("uploadId"):
        return fileRequest
    fileRequest = fileRequest.get("uploadId")
    status = agent.downloadStatus(fileRequest)
    return status


@app.get("/api/v1/ReaQta/{customer}/query/search/{ip}/events", tags=["ReaQta"])
async def reaqta(customer: str, ip: str, user: U.User = Depends(get_current_active_user)):
    try:
        customer = customer.upper()
        authReaQta = user["key"]["ReaQta"][customer]
    except:
        return HTTPException(status_code=403, detail="User not found")
    if not Check.isipv4(ip) and not Check.isipv6(ip):
        return HTTPException(status_code=400)
    agent = ReaQta.ReaQta(authReaQta["token"], authReaQta["id"])
    events = agent.query("$ip=" + ip)
    tmp = []
    assetId = []
    if not events.get("result"):
        return tmp
    for e in events.get("result"):
        try:
            if e["endpointId"] not in assetId:
                assetId.append(e["endpointId"])
                tmp.append(agent.getAsset(e["endpointId"])["name"])
        except:
            pass
    return tmp


# Fine Reaqta
# Merge
def threadFunction(user, dict, obj, customer):
    if obj == "SIEM":
        if not user.get("key").get("SIEM").get(customer):
            dict[obj] = []
        siem = user.get("key").get("SIEM").get(customer)
        dict[obj] = QRadar.QRadar(siem["ip"], siem["token"], "12").getAllOpenOffenses()
    elif obj == "EDR":
        try:
            customer = customer.upper()
            authReaQta = user["key"]["ReaQta"][customer]
            agent = ReaQta.ReaQta(authReaQta["token"], authReaQta["id"])
            tmp = agent.getAlerts()
            if not tmp.get("result"):
                dict[obj] = []
            dict[obj] = agent.filterCustomer(tmp["result"], customer)
        except:
            dict[obj] = []
    elif obj == "PAGERDUTY":
        if user.get("key").get("pagerduty"):
            pd = Pagerduty.Pargerduty(user.get("key").get("pagerduty"))
            dict[obj] = pd.getAllIncidents()
        else:
            dict[obj] = normalizer(db["PagerDuty-Alert"].find())


@app.get("/api/v1/merge/alerts/{customer}/{filter}", tags=["Merge"])
async def getAllAlerts(customer: str, filter: str, user: U.User = Depends(get_current_active_user)):
    threads = []
    data = {}
    tmp = []
    customerDB = db["Customers"].find_one({"identify": customer})
    if not customerDB or not customerDB.get("asset"):
        return HTTPException(status_code=400)
    if filter.upper() not in ["EDR", "SIEM", "ALL", "PAGERDUTY"]:
        return HTTPException(status_code=400)
    filter = filter.upper()

    for asset in customerDB["asset"].keys():
        if asset == "SIEM" and (filter == "ALL" or filter == "SIEM"):
            t = Thread(target=threadFunction, args=(user, data, "SIEM", customer,))
            t.start()
            threads.append(t)
        if asset == "EDR" and (filter == "ALL" or filter == "EDR"):
            t = Thread(target=threadFunction, args=(user, data, "EDR", customer,))
            t.start()
            threads.append(t)

    if filter == "ALL" or filter == "PAGERDUTY":
        t = Thread(target=threadFunction, args=(user, data, "PAGERDUTY", customer,))
        threads.append(t)
        t.start()

    for thread in threads:
        thread.join()

    for k in data.keys():
        for a in data[k]:
            if k == "PAGERDUTY" and a["service"]["summary"] == customer:
                date = datetime.strptime(a["created_at"], "%Y-%m-%dT%H:%M:%SZ").strftime("%d/%m/%Y %H:%M:%S")
                t = {"date": date, "group": customer, "id": a["id"], "title": a["title"], "status": a["status"],
                     "source": "PagerDuty"}
                tmp.append(t)
            elif k == "SIEM":
                t = {"date": a["start_time"], "group": customer, "id": a["id"], "title": a["description"],
                     "status": a["status"], "source": k}
                tmp.append(t)
            elif k == "EDR":
                date = datetime.strptime(a["happenedAt"], "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%d/%m/%Y %H:%M:%S")
                t = {"date": date, "group": customer, "id": a["id"], "title": a.get("title"),
                     "status": a.get("alertStatus"),
                     "source": k}
                tmp.append(t)

    return sorted(tmp, key=lambda x: x['date'], reverse=False)


@app.get("/api/v1/merge/asset/{customer}", tags=["Merge"])
async def getAllAsset(customer: str, user: U.User = Depends(get_current_active_user)):
    c = customer.upper().replace(" ", "")
    customerDB = db["Customers"].find_one({"identify": c})
    if not customerDB or not customerDB.get("asset"):
        return HTTPException(status_code=404)
    clients = {}
    totalClients = []
    asset = customerDB.get("asset")
    clients["undefined"] = []
    if asset.get("Firewall") and asset.get("Firewall").get("vdom") and user.get("key") and user.get("key").get(
            "Firewall") and user.get("key").get("Firewall").get(c):
        authFirewall = user["key"]["Firewall"][c]
        f = FortiOS.fortigate(authFirewall["ip"], authFirewall["token"])
        totalClients += f.getDevices(asset["Firewall"]["vdom"]).get("results")

    if asset.get("Wazuh") and user.get("key") and user.get("key").get("Wazuh") and user.get("key").get("Wazuh").get(c):
        wazuh = Wazuh.Wazuh(user["key"]["Wazuh"][c]["ip"])
        totalClients += wazuh.getAgentsList()

    if customer != "ONS" and asset.get("SIEM") and user.get("key") and user.get("key").get("SIEM") and user.get(
            "key").get("SIEM").get(c):
        siem = user.get("key").get("SIEM").get(customer)
        totalClients += QRadar.QRadar(siem["ip"], siem["token"], "12").getAssets()

    for a in totalClients:
        tmp = a

        if tmp.get("domain_id") or tmp.get("domain_id") == 0:
            tmp["source"] = "SIEM"
            tmp["status"] = "status-undefined"
        elif tmp.get("id"):
            tmp["source"] = "EDR"
        else:
            tmp["source"] = "Firewall"

        if tmp.get("ipv4_address"):
            tmp["ip"] = tmp.get("ipv4_address")
            del tmp["ipv4_address"]
        if tmp.get("ipv6_address"):
            tmp["ip"] = tmp.get("ipv4_address")
            del tmp["ipv6_address"]
        if tmp.get("os") and tmp.get("os").get("name"):
            tmp["os"] = tmp.get("os").get("name")
        if tmp.get("os_name") and tmp.get("os_version"):
            tmp["os"] = tmp.get("os_name") + " " + tmp.get("os_version")
            del tmp["os_name"]
            del tmp["os_version"]
        elif tmp.get("os_name"):
            tmp["os"] = tmp.get("os_name")
            del tmp["os_name"]
        if tmp.get("is_online") or tmp.get("is_online") == False:
            # disconnected active
            if tmp.get("is_online"):
                tmp["status"] = "active"
            else:
                tmp["status"] = "disconnected"
            del tmp["is_online"]
        if tmp.get("name"):
            tmp["hostname"] = tmp.get("name")
            del tmp["name"]
        if tmp.get("hostnames"):
            hostname = ""
            for h in tmp.get("hostnames"):
                hostname += h.get("name") + " "
            tmp["hostname"] = hostname
        if tmp.get("interfaces"):
            ip = ""
            for inter in tmp.get("interfaces"):
                if inter.get("ip_addresses"):
                    for i in inter.get("ip_addresses"):
                        ip = i.get("value") + " "
            tmp["ip"] = ip

        if tmp.get("hostname"):
            if clients.get(tmp["hostname"]):
                for k in clients[tmp["hostname"]].keys():
                    if k not in tmp.keys():
                        tmp[k] = clients[tmp["hostname"]][k]
            clients[tmp["hostname"]] = tmp
        elif tmp.get("ip"):
            if clients.get(tmp["ip"]):
                for k in clients[tmp["ip"]].keys():
                    if k not in tmp.keys():
                        tmp[k] = clients[tmp["ip"]][k]
            clients[tmp["ip"]] = tmp
        else:
            clients["undefined"].append(tmp)

    return clients


@app.get("/api/v1/merge/asset/{customer}/status", tags=["Merge"])
async def getAllAsset(customer: str, user: U.User = Depends(get_current_active_user)):
    c = customer.upper().replace(" ", "")
    customerDB = db["Customers"].find_one({"identify": c})
    if not customerDB or not customerDB.get("asset"):
        return HTTPException(status_code=404)
    clients = {}
    totalClients = []
    asset = customerDB.get("asset")
    clients["undefined"] = []
    if asset.get("Firewall") and asset.get("Firewall").get("vdom") and user.get("key") and user.get("key").get(
            "Firewall") and user.get("key").get("Firewall").get(c):
        authFirewall = user["key"]["Firewall"][c]
        f = FortiOS.fortigate(authFirewall["ip"], authFirewall["token"])
        totalClients += f.getDevices(asset["Firewall"]["vdom"]).get("results")

    if asset.get("Wazuh") and user.get("key") and user.get("key").get("Wazuh") and user.get("key").get("Wazuh").get(c):
        wazuh = Wazuh.Wazuh(user["key"]["Wazuh"][c]["ip"])
        totalClients += wazuh.getAgentsList()

    if customer != "ONS" and asset.get("SIEM") and user.get("key") and user.get("key").get("SIEM") and user.get(
            "key").get("SIEM").get(c):
        siem = user.get("key").get("SIEM").get(customer)
        totalClients += QRadar.QRadar(siem["ip"], siem["token"], "12").getAssets()

    for a in totalClients:
        tmp = a
        if tmp.get("domain_id") or tmp.get("domain_id") == 0:
            tmp["source"] = "SIEM"
            tmp["status"] = "status-undefined"
        elif tmp.get("id"):
            tmp["source"] = "EDR"
        else:
            tmp["source"] = "Firewall"

        if tmp.get("ipv4_address"):
            tmp["ip"] = tmp.get("ipv4_address")
            del tmp["ipv4_address"]
        if tmp.get("ipv6_address"):
            tmp["ip"] = tmp.get("ipv4_address")
            del tmp["ipv6_address"]
        if tmp.get("os") and tmp.get("os").get("name"):
            tmp["os"] = tmp.get("os").get("name")
        if tmp.get("os_name") and tmp.get("os_version"):
            tmp["os"] = tmp.get("os_name") + " " + tmp.get("os_version")
            del tmp["os_name"]
            del tmp["os_version"]
        elif tmp.get("os_name"):
            tmp["os"] = tmp.get("os_name")
            del tmp["os_name"]
        if tmp.get("is_online") or tmp.get("is_online") == False:
            # disconnected active
            if tmp.get("is_online"):
                tmp["status"] = "active"
            else:
                tmp["status"] = "disconnected"
            del tmp["is_online"]
        if tmp.get("name"):
            tmp["hostname"] = tmp.get("name")
            del tmp["name"]
        if tmp.get("hostnames"):
            hostname = ""
            for h in tmp.get("hostnames"):
                hostname += h.get("name") + " "
            tmp["hostname"] = hostname
        if tmp.get("interfaces"):
            ip = ""
            for inter in tmp.get("interfaces"):
                if inter.get("ip_addresses"):
                    for i in inter.get("ip_addresses"):
                        ip = i.get("value") + " "
            tmp["ip"] = ip

        if tmp.get("hostname"):
            if clients.get(tmp["hostname"]):
                for k in clients[tmp["hostname"]].keys():
                    if k not in tmp.keys():
                        tmp[k] = clients[tmp["hostname"]][k]
            clients[tmp["hostname"]] = tmp
        elif tmp.get("ip"):
            if clients.get(tmp["ip"]):
                for k in clients[tmp["ip"]].keys():
                    if k not in tmp.keys():
                        tmp[k] = clients[tmp["ip"]][k]
            clients[tmp["ip"]] = tmp
        else:
            clients["undefined"].append(tmp)

    status = {"total": 0, "active": 0, "status-undefined": 0, "disconnected": 0, "pending": 0, "never_connected": 0,
              "undefined": len(clients["undefined"])}
    del clients["undefined"]
    for c in clients.values():
        status["total"] += 1
        try:
            status[c["status"]] += 1
        except:
            continue
    return status


# Fine Merge

# Report
@app.get("/api/v1/report/{customer}/create/{day}", tags=["Report"])
def createReport(customer: str, day: int, user: U.User = Depends(get_current_active_user)):
    customer = customer.upper().replace(" ", "")
    customer = db["Customers"].find_one({"identify": customer})
    if not customer:
        return HTTPException(status_code=404, detail="Customer not found")
    try:
        pathImg = Config.logoReport + customer.get("logo-header")
    except:
        pathImg = Config.logoReport + "onstairs.png"
    try:
        logo = Config.logoReport + customer.get("logo")
    except:
        logo = Config.logoReport + "onstairs.png"
    pdf = Report.PDF(pathImg)
    period = (datetime.now() - timedelta(days=day)).strftime("%d/%m/%Y") + " - " + datetime.now().strftime("%d/%m/%Y")
    title = "Weekly Security Report"
    pdf.set_author("Onstairs S.R.L.")
    pdf.coverPage(title, customer.get("customer"), period, logo)
    template = db["Templates"].find_one({"name": "report"})

    # intro
    text = template.get("introduzione").replace("<customer>", customer.get("customer"))
    text = text.replace("<periodo>", period)
    assets = []
    assetsList = ""
    for asset in customer["asset"].keys():
        if asset in ["Firewall", "SIEM"]:
            assets.append(asset.capitalize())
            assetsList += " - " + asset.capitalize() + "\n"
    text = text.replace("<assets>", assetsList)
    file = open(Config.templateReport + "tmp.txt", "w")
    file.write(text)
    file.close()
    cap = 0
    pdf.print_chapter(cap, "Introduzione", Config.templateReport + "tmp.txt")
    # fine intro

    # case
    cases = db["Incidents"].find({"customer": customer["identify"],
                                  "creation_date": {"$lt": period.split("-")[0].replace(" ", ""),
                                                    "$gte": period.split("-")[1].replace(" ", "")}})
    infoCases = {"Totali": 0, "True positive": 0, "False positive": 0}
    for case in cases:
        if case.get("status") and case["status"].find("false") != -1:
            infoCases["False positive"] += 1
        elif case.get("status"):
            infoCases["True positive"] += 1
        infoCases["Totali"] += 1
    text = template.get("Case").replace("<totale>", str(infoCases["Totali"]))
    text = text.replace("<p>", str(infoCases["True positive"]))
    text = text.replace("<n>", str(infoCases["False positive"]))
    file = open(Config.templateReport + "tmp.txt", "w")
    file.write(text)
    file.close()
    cap += 1
    pdf.print_chapter(cap, "Case", Config.templateReport + "tmp.txt",
                      (tuple(infoCases.keys()), tuple(infoCases.values())))
    # case

    for asset in customer["asset"].keys():
        cap += 1
        if asset == "SIEM":
            authSIEM = user["key"]["SIEM"][customer["identify"]]
            devices = QRadar.QRadar(authSIEM["ip"], authSIEM["token"], "12")
            start = int((datetime.now() - timedelta(days=day)).timestamp() * 1000)
            end = int(datetime.now().timestamp() * 1000)
            offenses = devices.getOffensesPeriod(str(start), str(end))
            offenses = [offenses.keys(), offenses.values()]

            text = template.get("SIEM")
            file = open(Config.templateReport + "tmp.txt", "w")
            file.write(text)

            file.close()
            pdf.print_chapter(cap, "Siem", Config.templateReport + "tmp.txt", offenses)
        elif asset == "Firewall":
            authFirewall = user["key"]["Firewall"][customer["identify"]]
            f = FortiOS.fortigate(authFirewall["ip"], authFirewall["token"])

            policies = f.getPoliciesStatus(customer["asset"]["Firewall"]["vdom"])
            x = []
            y = []
            for p in policies:
                x.append(p.get("name"))
                y.append(str(p.get("hit_count")))

            plt.bar(x, y, color="blue", width=0.4)
            plt.xlabel("Policy name")
            plt.ylabel("hit policy")
            plt.savefig(Config.fileReport + "policy.png")
            text = template.get("Firewall")
            file = open(Config.templateReport + "tmp.txt", "w")
            file.write(text)
            file.close()
            pdf.print_chapter(cap, "Firewall", Config.templateReport + "tmp.txt", graph=[Config.fileReport + "policy.png"])

    cap += 1
    text = template.get("Conclusioni")
    file = open(Config.templateReport + "tmp.txt", "w")
    file.write(text)
    file.close()
    pdf.print_chapter(cap, "Conclusioni", Config.templateReport + "tmp.txt")
    pdf.output(Config.fileReport + "report.pdf")
    return FileResponse(path=Config.fileReport + "report.pdf", filename="report.pdf")
# Fine Report


# Notification
@app.post("/api/v1/notification/create", tags=["Notification"])
async def notification(ntf: U.Notification, user: U.User = Depends(get_current_active_user)):
    notificationDB = db["notifications"]
    id = notificationDB.count_documents({})
    while notificationDB.find_one({"id": id}):
        id += 1
    tmp = ntf.json()
    tmp["id"] = id
    tmp["read"] = []
    tmp["read-info"] = []
    tmp["by"] = user.get("username")
    tmp["date"] = datetime.now()
    notificationDB.insert_one(tmp)
    return {"notification": "add"}


@app.get("/api/v1/notification/get", tags=["Notification"])
async def notification(user: U.User = Depends(get_current_active_user)):
    notificationDB = db["notifications"]
    tmp = []
    notif = list(notificationDB.find({"$and": [{"read": {"$nin": [user.get("username")]}}, {"target": {"$in": [user.get("username")]}}]}))
    notif += list(notificationDB.find({"$and": [{"read": {"$nin": [user.get("username")]}}, {"target": {"$in": ["ALL"]}}]}))
    for n in notif:
        #n["date"] = n["date"].strftime("%d/%m/%Y %H:%M:%S")
        del n["_id"]
        tmp.append(n)
    return tmp


@app.put("/api/v1/notification/marked/{id}/read", tags=["Notification"])
async def notification(id: int, user: U.User = Depends(get_current_active_user)):
    notificationDB = db["notifications"]
    tmp = notificationDB.find_one({"id": id})
    if not tmp:
        return HTTPException(status_code=400, detail="Notification not found")
    tmp["read"].append(user.get("username"))
    if not tmp.get("read-info"):
        tmp["read-info"] = []
    tmp["read-info"].append({"user": user.get("username"), "time": datetime.now()})
    notificationDB.replace_one({"_id": tmp["_id"]}, tmp)
    return {"notification": "read"}
# Fine Notification