import os
import flask
from flask import request, jsonify
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
import pyshorteners as sh
import requests
import geocoder
import mysql.connector
import base64
from datetime import datetime, timedelta
import json
import re
from df_response_lib import actions_on_google_response, fulfillment_response

# import urllib.parse
# import googlemaps

# This variable specifies the name of a file that contains the OAuth 2.0
# information for this application, including its client_id and client_secret.
CLIENT_SECRETS_FILE = "./JsonFile/client_secret.json"
Client_Id = "593655075733-0rf9q219r4j7c782qjm4c186vkhr6gsd.apps.googleusercontent.com"
Client_Secret = "Ld3rn119QlhQPruUQI-qhbxu"

# This OAuth 2.0 access scope allows for full read/write access to the
# authenticated user's account and requires requests to use an SSL connection.
SCOPES = [
    "openid", "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/calendar",
    "https://www.googleapis.com/auth/calendar.readonly", "https://www.googleapis.com/auth/calendar.events",
    "https://www.googleapis.com/auth/calendar.events.readonly",
    "https://www.googleapis.com/auth/calendar.settings.readonly",
    "https://www.googleapis.com/auth/calendar.addons.execute"
]
API_SERVICE_NAME = 'calendar'
API_VERSION = 'v3'
redirect_uri = 'https://intelligent-chatbot.herokuapp.com/GoogleCalendar'
# MapsApiKey='AIzaSyABhkZhF323bkUPLjgwfDl2qR7UHRAz9-c'
app = flask.Flask(__name__)


@app.route('/')
def Index():
    return 'Hi'


@app.route('/webhook', methods=['POST'])
def postwebhook():
    if request.method == 'POST':
        res = None
        req = request.get_json(silent=True, force=True)
        aog = actions_on_google_response()
        ful = fulfillment_response()
        # email=req.get('queryText')
        query_result = req.get('queryResult')

        if query_result.get('action') == 'google_calendar_email':

            email = query_result.get('queryText')
            # check if user data exist in db
            con = mysql.connector.connect(host='db4free.net', port=3306, user='cigniti', password='Ctl@1234',
                                          database='chatbotdbdemo')
            cursor = con.cursor()
            cursor.execute(f"SELECT * FROM GoogleCred where email='{email}'")
            row = cursor.fetchone()
            con.close()

            if row is None:
                flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
                    CLIENT_SECRETS_FILE, scopes=SCOPES)
                flow.redirect_uri = redirect_uri
                authorization_url, state = flow.authorization_url(access_type='offline',
                                                                  include_granted_scopes='true')
                s = sh.Shortener()
                res = {
                    "fulfillmentText": s.tinyurl.short(authorization_url),
                    "displayText": 5,
                    "source": "webhookdata"
                }
                globals()['res'] = res

            else:
                # print('This is else block')
                present_time = datetime.utcnow()
                present_time.strftime("%Y-%m-%d %H:%M:%S")
                # last_updated_time = datetime.strptime(row[3], '%Y-%m-%d %H:%M:%S')
                # last_updated_time=row[3]
                time_delta = (present_time - row[3])
                tt = divmod(time_delta.total_seconds(), 60)
                if tt[0] > 60:  # data.web.client_id#data.web.client_secret
                    fulfilment = []
                    refreshed_toks = refreshToken(Client_Id, Client_Secret, base64decode(row[2]))
                    print(refreshed_toks[0])
                    updateGooglecredtokens(row[0], refreshed_toks[0], refreshed_toks[1])
                    calendar_cred = {
                        "token": f"{refreshed_toks[0]}",
                        "refresh_token": f"{base64decode(row[2])}",
                        "token_uri": "https://oauth2.googleapis.com/token",
                        "client_id": f"{Client_Id}",
                        "client_secret": f"{Client_Secret}",
                        "scopes": SCOPES,
                        # "id_token":f"{base64decode(row[5])}",
                    }
                    try:
                        cred = google.oauth2.credentials.Credentials(**calendar_cred)
                        service = googleapiclient.discovery.build(API_SERVICE_NAME, API_VERSION, cache_discovery=False,
                                                                  credentials=cred)
                    except Exception as e:
                        print(str(e))
                    cal_event = None
                    page_token = None
                    # while True:
                    request_time = datetime.utcnow() - timedelta(hours=6, minutes=00)
                    strdate = request_time.strftime("%Y-%m-%d")
                    req_min = strdate + 'T00:01:01-06:00'
                    req_max = strdate + 'T23:59:59-06:00'
                    eventsservice = service.events().list(calendarId='primary', pageToken=page_token, timeMax=req_max,
                                                          timeMin=req_min).execute()
                    events = eventsservice.get('items', [])
                    if not events:
                        res = ful.main_response(ful.fulfillment_text("No upcoming events found"),
                                                fulfillment_messages=None, output_contexts=None,
                                                followup_event_input=None)
                        for event in events:
                            start_date = event['start'].get('dateTime', event['start'].get('date'))
                            end_date = event['end'].get('dateTime', event['end'].get('date'))
                            calevents = event[
                                            'summary'] + "\n\nStarts at:" + start_date + ",ends at:" + end_date + "\n\n Location:" + \
                                        event['location']
                            '''calevents = {"text": {"text": [
                            event['summary'] + "\n\nStarts at:" + start_date['dateTime'] + ",ends at:" + end_date[
                            'dateTime']+"\n\n Location:"+event['location']]
                            }}'''
                            fulfilment.append(calevents)
                            res = ful.main_response(ful.fulfillment_text("Test"),
                                                    fulfillment_messages=ful.fulfillment_messages(
                                                        [aog.suggestion_chips(fulfilment)]), output_contexts=None,
                                                    followup_event_input=None)
                            # res = {"fulfillmentMessages": fulfilment, "source": "webhook"}
                            globals()['res'] = res

                else:
                    print('second else block')
                    fulfilment = []
                    calendar_cred = {
                        "token": f"{base64decode(row[1])}",
                        "refresh_token": f"{base64decode(row[2])}",
                        "token_uri": "https://oauth2.googleapis.com/token",
                        "client_id": f"{Client_Id}",
                        "client_secret": f"{Client_Secret}",
                        "scopes": SCOPES,
                        # "id_token": f"{base64decode(row[5])}",
                    }

                    try:
                        cred = google.oauth2.credentials.Credentials(**calendar_cred)
                        service = googleapiclient.discovery.build(API_SERVICE_NAME, API_VERSION, cache_discovery=False,
                                                                  credentials=cred)
                    except Exception as e:
                        print(str(e))
                    # service=google_auth(row,credentials_to_dict(calendar_cred))
                    cal_event = None
                    page_token = None
                    # while True:
                    request_time = datetime.utcnow() - timedelta(hours=6, minutes=00)
                    strdate = request_time.strftime("%Y-%m-%d")
                    req_min = strdate + 'T00:01:01-06:00'
                    req_max = strdate + 'T23:59:59-06:00'
                    eventsservice = service.events().list(calendarId='primary', pageToken=page_token, timeMax=req_max,
                                                          timeMin=req_min).execute()
                    events = eventsservice.get('items', [])
                    if not events:
                        res = ful.main_response(ful.fulfillment_text("No upcoming events found"),
                                                fulfillment_messages=None, output_contexts=None,
                                                followup_event_input=None)
                    for event in events:
                        start_date = event['start'].get('dateTime', event['start'].get('date'))
                        end_date = event['end'].get('dateTime', event['end'].get('date'))
                        calevents = event[
                                        'summary'] + "\n\nStarts at:" + start_date + ",ends at:" + end_date + "\n\n Location:" + \
                                    event['location']
                        '''calevents = {"text": {"text": [
                            event['summary'] + "\n\nStarts at:" + start_date['dateTime'] + ",ends at:" + end_date[
                                'dateTime']+"\n\n Location:"+event['location']]
                        }}'''
                        fulfilment.append(calevents)
                    # res="test success"#cal_event
                    res = ful.main_response(ful.fulfillment_text("Test"), fulfillment_messages=ful.fulfillment_messages(
                        [aog.suggestion_chips(fulfilment)]), output_contexts=None, followup_event_input=None)
                    # res = {"fulfillmentMessages": fulfilment, "source": "webhook"}
                    globals()['res'] = res
                    # print(res)
        elif query_result.get('action') == 'Mymeetings_Google_emailid_Location-UserLocation':
            query_result.get('parameters')
            params = query_result.get('parameters')
            userlocation = geocoder.bing(params['present_location'],
                                         key='Av8kGlFn5a12aa2Y735ol8r6cYv4Mmf_HnOUQry1SZmSpVUHWzMWpUSi9ytac59t')
            pcords = userlocation.latlng
            meetingloc = re.findall('Location:*(.+)', params['meeting_location'], re.IGNORECASE)
            print(meetingloc[0])
            meetinglocation = geocoder.bing(meetingloc[0],
                                            key='Av8kGlFn5a12aa2Y735ol8r6cYv4Mmf_HnOUQry1SZmSpVUHWzMWpUSi9ytac59t')
            mcords = meetinglocation.latlng
            r = requests.get(
                f'https://dev.virtualearth.net/REST/v1/Routes/DistanceMatrix?origins={pcords[0]},{pcords[1]}&destinations={mcords[0]},{mcords[1]}&travelMode=driving&timeUnit=minute&distanceUnit=km&key=Av8kGlFn5a12aa2Y735ol8r6cYv4Mmf_HnOUQry1SZmSpVUHWzMWpUSi9ytac59t')
            # print(r.text)
            distresult = json.loads(r.text)
            resourcesets = distresult['resourceSets'][0]
            resources = resourcesets['resources'][0]
            distresults = resources['results'][0]
            print(distresults['travelDuration'])
            timedurationdelta = '{:02d}:{:02d}'.format(*divmod(int(distresults['travelDuration']), 60))
            print(timedurationdelta)
            # {:.2f}".format(distresults['travelDuration'])

            str_startdate = params['Startdate']
            print(str_startdate)
            sttime = re.findall('Starts at:*(.+),ends at', str_startdate, re.IGNORECASE)
            # rrt=sttime[20:].split(':')

            uncondat1 = sttime[0]
            # uncondat2=sttime[0]
            # print(uncondat[0:19])
            meetingtime = datetime.strptime(listToString(uncondat1[0:19]).replace('T', ' '), "%Y-%m-%d %H:%M:%S")
            if uncondat1[19] == '+':
                print(timedurationdelta[0:2])
                old_time = datetime.utcnow() + timedelta(hours=int(str(uncondat1[20]) + str(uncondat1[21])),
                                                         minutes=int(str(uncondat1[23]) + str(uncondat1[24])))
                presenttime = old_time + timedelta(hours=int(str(timedurationdelta[0]) + str(timedurationdelta[1])),
                                                   minutes=int(str(timedurationdelta[3]) + str(timedurationdelta[4])))
                if presenttime > meetingtime:
                    print(presenttime)
                    print(meetingtime)
                    tt = presenttime - meetingtime
                    res_message = aog.simple_response([["Distance from your location is" + "{:.2f}".format(
                        distresults['travelDistance']) + " kms,You are late by" + strfdelta(tt,
                                                                                            "{hours}hr:{minutes}min"),
                                                        "Distance from your location is" + "{:.2f}".format(distresults[
                                                                                                               'travelDistance']) + " kms,You are late by" + strfdelta(
                                                            tt, "{hours}hours:{minutes}minutes"), False]])

                    print("You are late " + strfdelta(tt, "{hours}:{minutes}"))
                    # res=ful.main_response(ful.fulfillment_text("Distance from your location is"+"{:.2f}".format(distresults['travelDistance'])+" kms,You are late by"+strfdelta(tt, "{hours}hr:{minutes}min")),fulfillment_messages=[res_message],output_contexts=None,followup_event_input=None)
                    res = ful.main_response(ful.fulfillment_text('response'), fulfillment_messages=res_message,
                                            output_contexts=None, followup_event_input=None)
                    globals()['res'] = res
                    # print("you are late")
                elif meetingtime > presenttime:
                    tt = meetingtime - presenttime
                    print("you are early" + strfdelta(tt, "{hours}:{minutes}"))
                    res_message = aog.simple_response([["Distance from your location is" + "{:.2f}".format(
                        distresults['travelDistance']) + " kms,You are early by" + strfdelta(tt, "{hours}:{minutes}"),
                                                        "Distance from your location is" + "{:.2f}".format(distresults[
                                                                                                               'travelDistance']) + " kms,You are early by" + strfdelta(
                                                            tt, "{hours}hours:{minutes}minutes"), False]])
                    # res=ful.main_response(ful.fulfillment_text("Distance from your location is"+"{:.2f}".format(distresults['travelDistance'])+" kms,You are early by"+strfdelta(tt, "{hours}:{minutes}")),fulfillment_messages=None,output_contexts=None,followup_event_input=None)
                    res = res_message
                    # ful.main_response(ful.fulfillment_text('response'),fulfillment_messages=res_message,output_contexts=None,followup_event_input=None)
                    globals()['res'] = res

            else:
                old_time = datetime.utcnow() - timedelta(hours=int(str(uncondat1[20]) + str(uncondat1[21])),
                                                         minutes=int(str(uncondat1[23]) + str(uncondat1[24])))
                presenttime = old_time + timedelta(hours=int(str(timedurationdelta[0]) + str(timedurationdelta[1])),
                                                   minutes=int(str(timedurationdelta[3]) + str(timedurationdelta[4])))
                if presenttime > meetingtime:
                    tt = presenttime - meetingtime
                    print("You are late " + strfdelta(tt, "{hours}:{minutes}"))
                    res_message = aog.simple_response([["Distance from your location is" + "{:.2f}".format(
                        distresults['travelDistance']) + " kms,You are late by" + strfdelta(tt, "{hours}:{minutes}"),
                                                        "Distance from your location is" + "{:.2f}".format(distresults[
                                                                                                               'travelDistance']) + " kms,You are late by" + strfdelta(
                                                            tt, "{hours}:{minutes}"), False]])
                    # res=ful.main_response(ful.fulfillment_text("Distance from your location is"+"{:.2f}".format(distresults['travelDistance'])+" kms,You are late by"+strfdelta(tt, "{hours}:{minutes}")),fulfillment_messages=None,output_contexts=None,followup_event_input=None)
                    res = res_message
                    # ful.main_response(ful.fulfillment_text('response'),fulfillment_messages=[res_message],output_contexts=None,followup_event_input=None)
                    globals()['res'] = res
                    # print("you are late")
                elif meetingtime > presenttime:
                    tt = meetingtime - presenttime
                    print("you are early" + strfdelta(tt, "{hours}:{minutes}"))
                    res_message = aog.simple_response([["Distance from your location is" + "{:.2f}".format(
                        distresults['travelDistance']) + " kms,You are early by" + strfdelta(tt, "{hours}:{minutes}"),
                                                        "Distance from your location is" + "{:.2f}".format(distresults[
                                                                                                               'travelDistance']) + " kms,You are early by" + strfdelta(
                                                            tt, "{hours}:{minutes}"), False]])
                    # res=ful.main_response(ful.fulfillment_text("Distance from your location is"+"{:.2f}".format(distresults['travelDistance'])+" kms,You are early by"+strfdelta(tt, "{hours}:{minutes}")),fulfillment_messages=None,output_contexts=None,followup_event_input=None)
                    res = ful.main_response(ful.fulfillment_text('response'), fulfillment_messages=[res_message],
                                            output_contexts=None, followup_event_input=None)
                    globals()['res'] = res

                    # print(results['travelDistance'],results['travelDuration'])
            # res=ful.main_response(ful.fulfillment_text("Distance from your location is"+"{:.2f}".format(distresults['travelDistance'])+" kms,you will reach to your destination in"+"{:.2f}".format(distresults['travelDuration'])+" mins"),fulfillment_messages=None,output_contexts=None,followup_event_input=None)
            # globals()['res'] = res
        print(res)
        return jsonify(res)


def google_auth(row, calendar_cred):
    try:
        cred = google.oauth2.credentials.Credentials(**calendar_cred)
        service = googleapiclient.discovery.build(API_SERVICE_NAME, API_VERSION, cache_discovery=False,
                                                  credentials=cred)
    except Exception as e:
        print(str(e))
    '''page_token = None   
    if not row[6]:
      calendar_list = service.calendarList().list(pageToken=page_token).execute()
      if not calendar_list:
        calendars=calendar_list['items']
        user_timezone=calendars[0].get('timeZone')
        update_timezone(user_timezone,row[0])
        print("timezone updated")'''
    return service


# update user timezone
def update_timezone(user_timezone, id):
    con = mysql.connector.connect(host='db4free.net', port=3306, user='cigniti', password='Ctl@1234',
                                  database='chatbotdbdemo')
    # Creating a cursor object using the cursor() method
    cursor = con.cursor()
    sql = f'UPDATE GoogleCred SET timezone="{user_timezone}" WHERE Id ={id}'
    print(sql)
    try:
        # Execute the SQL command
        ret = cursor.execute(sql)
        print(ret)
        # globals()['ret']=ret
        # Commit your changes in the database
        con.commit()
        '''if ret.rowcount is not None:
            validator = True'''
    except TypeError as e:
        print(e)
        # Rollback in case there is any error
        con.rollback()
        validator = False
    print(validator)
    return validator


def strfdelta(tdelta, fmt):
    d = {}
    d["hours"], rem = divmod(tdelta.seconds, 3600)
    d["minutes"], d["seconds"] = divmod(rem, 60)
    return fmt.format(**d)


@app.route('/GoogleCalendar', methods=['GET'])
def GoogleCalendar():
    # return authorization_url
    if request.method == 'GET':
        res = dict(request.args)
        # state = res['state']
        # flask.session['state']
        # flask.url_for('oauth2callback', _external=True)
        authorization_response = flask.request.url
        flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES)
        flow.redirect_uri = redirect_uri
        # flask.url_for('oauth2callback',_schema='https',_external=True)
        flow.fetch_token(authorization_response=authorization_response)
        credentials = flow.credentials
        # flask.session['credentials'] = credentials_to_dict(credentials) --modified here
        # calendar = googleapiclient.discovery.build(API_SERVICE_NAME,API_VERSION,       credentials=credentials)
        # calendars = calendar.calendarList().list().execute()
        # return flask.jsonify(**credentials)''' credentials_to_dict(credentials)+
        session = flow.authorized_session()
        profile_info = session.get(
            'https://www.googleapis.com/userinfo/v2/me').json()
        con = mysql.connector.connect(host='db4free.net', port=3306, user='cigniti', password='Ctl@1234',
                                      database='chatbotdbdemo')

        now = datetime.utcnow()
        encode_accesstoken = base64encode(credentials.token)
        encode_refreshtoken = base64encode(credentials.refresh_token)
        encode_idtoken = base64encode(credentials.id_token)
        # encodedstrings= base64encode([credentials.token,credentials.refresh_token])
        cursor = con.cursor(prepared=True)
        cursor.execute(f"SELECT * FROM GoogleCred where email='{profile_info['email']}'")
        row = cursor.fetchone()
        if not row:
            sql = "INSERT INTO GoogleCred(access_token,refresh_token,updated_date,email,id_token) VALUES(%s,%s,%s,%s,%s)"
            val = (encode_accesstoken, encode_refreshtoken, now.strftime("%Y-%m-%d %H:%M:%S"), profile_info['email'],
                   encode_idtoken)
            try:
                print(con)
                cursor.execute(sql, val)

                # Commit your changes in the database
                con.commit()
            except TypeError as e:
                print(e)
                # Rolling back in case of error
            con.rollback()
        else:
            sql = f'UPDATE GoogleCred SET access_token="{encode_accesstoken}",refresh_token="{encode_refreshtoken}"updated_date="{now.strftime("%Y-%m-%d %H:%M:%S")},id_token="{encode_idtoken}"  WHERE Id ={row[0]}'
        con.close()

        # return credentials_to_dict(credentials)  # profile_info
        return "Thanks for authorizing the chatbot,please return to the chatbot"


def updateGooglecredtokens(id, accesstoken, id_token):
    print("entered")
    validator = False
    # ret=None
    now = datetime.utcnow()
    con = mysql.connector.connect(host='db4free.net', port=3306, user='cigniti', password='Ctl@1234',
                                  database='chatbotdbdemo')
    # Creating a cursor object using the cursor() method
    cursor = con.cursor()
    enco_acess = base64encode(accesstoken)
    enco_idtoken = base64encode(id_token)
    sql = f'UPDATE GoogleCred SET access_token ="{enco_acess}",id_token="{enco_idtoken}",updated_date="{now.strftime("%Y-%m-%d %H:%M:%S")}" WHERE Id ={id}'
    print(sql)
    try:
        # Execute the SQL command
        ret = cursor.execute(sql)
        print(ret)
        # globals()['ret']=ret
        # Commit your changes in the database
        con.commit()
        '''if ret.rowcount is not None:
            validator = True'''
    except TypeError as e:
        print(e)
        # Rollback in case there is any error
        con.rollback()
        validator = False
    print(validator)
    return validator


def base64encode(googletokens):
    # EncodedTokens=[]
    # for token in googletokens:
    sample_string = googletokens
    sample_string_bytes = sample_string.encode("ascii")
    base64_bytes = base64.b64encode(sample_string_bytes)
    base64_string = base64_bytes.decode("ascii")
    # EncodedTokens.append(base64_string)
    return base64_string


def base64decode(googletokens):
    # DecodedTokens=[]
    # for token in googletokens:
    base64_string = googletokens
    base64_bytes = base64_string.encode("ascii")
    sample_string_bytes = base64.b64decode(base64_bytes)
    sample_string = sample_string_bytes.decode("ascii")
    # DecodedTokens.append()
    return sample_string


def refreshToken(client_id, client_secret, refresh_token):
    print(refresh_token)
    params = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token
    }

    authorization_url = "https://www.googleapis.com/oauth2/v4/token"

    r = requests.post(authorization_url, data=params)
    # print(r.content)

    if r.ok:
        refreshtoks = [r.json()['access_token'], r.json()['id_token']]
        return refreshtoks
    else:
        print("Unable to fetch access_token")


# list to string
def listToString(s):
    # initialize an empty string
    strg = ""

    # traverse in the string
    for ele in s:
        strg += ele

        # return string
    return strg


def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }


if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    app.run(host='0.0.0.0', port=5075, debug=True)
