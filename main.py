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
import threading
import queue
from df_response_lib import actions_on_google_response, fulfillment_response
import pytz
import operator

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


ops = { "+": operator.add, "-": operator.sub }

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
            row = get_user_details(email)

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
                fulfilment = []
                # print('This is else block')
                page_token = None
                # while True:
                request_time = datetime.utcnow() - timedelta(hours=6, minutes=00)
                strdate = request_time.strftime("%Y-%m-%d")
                req_min = strdate + 'T00:01:01'
                req_max = strdate + 'T23:59:59'
                events = google_auth(row, req_min, req_max)
                '''events_service = service.events().list(calendarId='primary', pageToken=page_token, timeMax=req_max,
                                                       timeMin=req_min).execute()'''
                #events = events_service.get('items', [])
                if events is None:
                    res = ful.main_response(ful.fulfillment_text("No upcoming events found"),
                                            fulfillment_messages=None, output_contexts=None,
                                            followup_event_input=None)
                else:
                    for event in events:
                        start_date = event['start'].get('dateTime', event['start'].get('date'))
                        end_date = event['end'].get('dateTime', event['end'].get('date'))
                        cal_events = event['summary'] + "\n\n Starts at:" + start_date + ",ends at:" + end_date + " Location:" + \
                                    event['location']
                        fulfilment.append(cal_events)
                        res = ful.main_response(fulfillment_text=None, fulfillment_messages=ful.fulfillment_messages(
                                                    [aog.suggestion_chips(fulfilment)]), output_contexts=None,
                                                followup_event_input=None)
                        globals()['res'] = res

        elif query_result.get('action') == 'Mymeetings_Google_emailid_Location-UserLocation':
            query_result.get('parameters')
            params = query_result.get('parameters')
            #outputcontext=req.get('outputContexts')
            meeting_loc = re.findall('Location:*(.+)', params['meeting_location'], re.IGNORECASE)
            str_start_date = params['Startdate']
            #print(str_start_date)
            st_time = re.findall('Starts at:*(.+),ends at', str_start_date, re.IGNORECASE)
            que1 = queue.Queue()
            dt = ops[st_time[0][19:20]](datetime.utcnow(),
                                        timedelta(hours=int(str(st_time[0][20]) + str(st_time[0][21])),
                                                  minutes=int(str(st_time[0][23]) + str(st_time[0][24]))))
            distance_result = get_distance_and_duration([params['present_location'], meeting_loc[0]], dt.strftime("%Y-%m-%d %H:%M:%S"), st_time[0])

            #print(distance_result)
            next_result = fetch_next_location_details(params['email'], st_time[0])
            #print(next_result)
            res = ful.main_response(fulfillment_text=None,
                                    fulfillment_messages=ful.fulfillment_messages([distance_result, next_result]),
                                    output_contexts=None, followup_event_input=None)
            globals()['res'] = res
            '''t1 = threading.Thread(target=get_distance_and_duration, args=([params['present_location'], meeting_loc[0]],
                                                                          dt.strftime("%Y-%m-%d %H:%M:%S"), st_time[0]))
            t1.start()
            t1.join()
            distanceresult = que1.get()
            print(distanceresult)'''

            '''que = queue.Queue()
            t = threading.Thread(target=fetch_next_location_details, args=(params['email'], meeting_loc[0], st_time[0]))
            t.start()
            t.join()
            result = que.get()
            print(result)
            #ful.main_response(fulfillment_text=None, fulfillment_messages=ful.fulfillment_messages([distanceresult, result]), output_contexts=None, followup_event_input=None)
            globals()['res'] = res'''
        elif query_result.get('action') == 'GetUserLocation-GetGoogleCalendarNextLocation':
            query_result.get('parameters')
            params = query_result.get('parameters')
            str_start_date = params['Startdate']
            st_time = re.findall('Starts at:*(.+),ends at', str_start_date, re.IGNORECASE)

            next_result = fetch_next_location_details(params['email'], st_time[0])
            res = ful.main_response(fulfillment_text=None,
                                    fulfillment_messages=ful.fulfillment_messages([next_result]),
                                    output_contexts=None, followup_event_input=None)
            globals()['res'] = res

        print(res)
        return jsonify(res)


def fetch_next_location_details(email, start_date_time):
    fulfilment = []
    res=None
    aog = actions_on_google_response()
    row = get_user_details(email)
    st = start_date_time.split('T')
    end_date_time = st[0]+"T23:59:59"
    #stt=start_date_time.replace('T', ' ')
    events = google_auth(row, listToString(start_date_time[0:19]), end_date_time)
    #print(events)
    cal_events = None
    if events[1] is None:
        res = aog.simple_response(["No events found further", "No events found further", False])
        globals()['res'] = res
    else:
        present_endtime = events[0]['end'].get('dateTime', events[1]['end'].get('date'))

        start_date = events[1]['start'].get('dateTime', events[1]['start'].get('date'))
        end_date = events[1]['end'].get('dateTime', events[1]['end'].get('date'))
        cal_events = "Upcoming Event:"+events[1]['summary'] + "\n\nStarts at:" + start_date + ",ends at:" + end_date + "\n\n Location:"\
                         + events[1]['location']
        globals()['cal_events'] = cal_events
        pt = present_endtime.replace('T', ' ')
        st = start_date.replace('T', ' ')
        distance_matrix = get_distance_and_duration_for_next_location([events[0]['location'], events[1]['location']], listToString(pt[0:19]), listToString(st[0:19]))
        #print(distance_matrix)
        cal_events = cal_events+"\n\n"+distance_matrix
        fulfilment.append(cal_events)
        res = aog.suggestion_chips(fulfilment)
        globals()['res'] = res
    #print(res)
    return res


def get_user_details(email):
    con = mysql.connector.connect(host='db4free.net', port=3306, user='intelli_bot', password='ctl@1234',
                                  database='intelligentbot')#chatbotdbdemo
    cursor = con.cursor()
    cursor.execute(f"SELECT * FROM GoogleCredentials where email='{email}'")
    row = cursor.fetchone()
    con.close()
    return row


# pass locations list present location and destination
def get_distance_and_duration(locations, presenttime, nexttime):
    aog = actions_on_google_response()
    ful = fulfillment_response()
    #print(presenttime)
    coords=[]
    res = None
    for location in locations:
        meeting_location = geocoder.bing(location,
                                         key='Av8kGlFn5a12aa2Y735ol8r6cYv4Mmf_HnOUQry1SZmSpVUHWzMWpUSi9ytac59t')
        m_coords = meeting_location.latlng

        coords.append(m_coords[0])
        coords.append(m_coords[1])
    r = requests.get(
        f'https://dev.virtualearth.net/REST/v1/Routes/DistanceMatrix?origins={coords[0]},{coords[1]}&destinations={coords[2]},{coords[3]}&travelMode=driving&timeUnit=minute&distanceUnit=km&key=Av8kGlFn5a12aa2Y735ol8r6cYv4Mmf_HnOUQry1SZmSpVUHWzMWpUSi9ytac59t')
    # print(r.text)
    dist_result = json.loads(r.text)
    resource_sets = dist_result['resourceSets'][0]
    resources = resource_sets['resources'][0]
    dist_results = resources['results'][0]
    time_duration_delta = '{:02d}:{:02d}'.format(*divmod(int(dist_results['travelDuration']), 60))
    uncondat1 = nexttime
    meeting_time = datetime.strptime(listToString(uncondat1[0:19].replace('T', ' ')), "%Y-%m-%d %H:%M:%S")
    present_time = datetime.strptime(presenttime, '%Y-%m-%d %H:%M:%S') + timedelta(hours=int(str(time_duration_delta[0]) + str(time_duration_delta[1])),
                                           minutes=int(str(time_duration_delta[3])
                                                       + str(time_duration_delta[4])))

    if present_time > meeting_time:
        tt = present_time - meeting_time
        res_message = aog.simple_response([["Distance from your location is " + "{:.2f}".format(
                dist_results['travelDistance']) + " kms,You will be late by " + strfdelta(tt, "{hours}hr:{minutes}min"),
                                                "Distance from your location is " + "{:.2f}".format(
                                                    dist_results['travelDistance']) +
                                                " kms,You will be late by " + strfdelta(tt, "{hours} hr:{minutes}min"),
                                                False]])

        '''res = ful.main_response(fulfillment_messages=ful.fulfillment_messages([res_message]),
                                fulfillment_text=None, output_contexts=None, followup_event_input=None)'''
        res = res_message
        globals()['res'] = res

    elif meeting_time > present_time:
        tt = meeting_time - present_time
        # print("you are early" + strfdelta(tt, "{hours}:{minutes}"))
        res_message = aog.simple_response([["Distance from your location is " + "{:.2f}".format(
                dist_results['travelDistance']) + " kms,You will be early by " + strfdelta(tt, "{hours} hr:{minutes} min"),
                                                "Distance from your location is " + "{:.2f}".format(dist_results[
                                                                                                        'travelDistance']) + " kms,You will be early by " + strfdelta(
                                                    tt, "{hours}hr:{minutes} min"), False]])
        '''res = ful.main_response(fulfillment_messages=ful.fulfillment_messages([res_message]),
                                fulfillment_text=None, output_contexts=None, followup_event_input=None)'''
        res = res_message

        globals()['res'] = res
    return res


def get_distance_and_duration_for_next_location(locations, presenttime, nexttime):
    aog = actions_on_google_response()
    ful = fulfillment_response()
    res = None
    coords=[]
    for location in locations:
        meeting_location = geocoder.bing(location,
                                         key='Av8kGlFn5a12aa2Y735ol8r6cYv4Mmf_HnOUQry1SZmSpVUHWzMWpUSi9ytac59t')
        m_coords = meeting_location.latlng

        coords.append(m_coords[0])
        coords.append(m_coords[1])
    #print(coords)
    r = requests.get(
        f'https://dev.virtualearth.net/REST/v1/Routes/DistanceMatrix?origins={coords[0]},{coords[1]}&destinations={coords[2]},{coords[3]}&travelMode=driving&timeUnit=minute&distanceUnit=km&key=Av8kGlFn5a12aa2Y735ol8r6cYv4Mmf_HnOUQry1SZmSpVUHWzMWpUSi9ytac59t')
    # print(r.text)
    dist_result = json.loads(r.text)
    resource_sets = dist_result['resourceSets'][0]
    resources = resource_sets['resources'][0]
    dist_results = resources['results'][0]
    time_duration_delta = '{:02d}:{:02d}'.format(*divmod(int(dist_results['travelDuration']), 60))
    uncondat1 = nexttime
    meeting_time = datetime.strptime(listToString(uncondat1[0:19].replace('T', ' ')), "%Y-%m-%d %H:%M:%S")
    present_time = datetime.strptime(presenttime, '%Y-%m-%d %H:%M:%S') + timedelta(hours=int(str(time_duration_delta[0]) + str(time_duration_delta[1])),
                                                                                   minutes=int(str(time_duration_delta[3])
                                                                                               + str(time_duration_delta[4])))
    if present_time > meeting_time:
        tt = present_time - meeting_time
        '''res_message = aog.simple_response([["Distance from your location is " + "{:.2f}".format(
                dist_results['travelDistance']) + " kms,You will be late by " + strfdelta(tt, "{hours}hr:{minutes}min"),
                                                "Distance from your location is " + "{:.2f}".format(
                                                    dist_results['travelDistance']) +
                                                " kms,You will be late by " + strfdelta(tt, "{hours} hr:{minutes}min"),
                                                False]])'''
        res_message = "Distance from your location is " + "{:.2f}".format(
                dist_results['travelDistance']) + " kms,\n\n You will be late by " + strfdelta(tt, "{hours}hr:{minutes}min")

        res = res_message
        globals()['res'] = res
    elif meeting_time > present_time:
        tt = meeting_time - present_time
        # print("you are early" + strfdelta(tt, "{hours}:{minutes}"))
        '''res_message = aog.simple_response([["Distance from your location is " + "{:.2f}".format(
                dist_results['travelDistance']) + " kms,You will be early by " + strfdelta(tt,"{hours} hr:{minutes} min"),
                                                "Distance from your location is " + "{:.2f}".format(dist_results[
                                                                                                        'travelDistance']) + " kms,You will be early by " + strfdelta(
                                                    tt, "{hours}hr:{minutes} min"), False]])'''
        res_message = "Distance from your location is " + "{:.2f}".format(
                dist_results['travelDistance']) + " kms,\n\nYou will be early by " + strfdelta(tt, "{hours} hr:{minutes} min")
        res = res_message
        globals()['res'] = res
    return res


def google_auth(row, req_min, req_max):
    present_time = datetime.utcnow()
    present_time.strftime("%Y-%m-%d %H:%M:%S")
    # last_updated_time = datetime.strptime(row[3], '%Y-%m-%d %H:%M:%S')
    # last_updated_time=row[3]
    time_delta = (present_time - row[6])
    events = []
    tt = divmod(time_delta.total_seconds(), 60)
    if tt[0] > 60:  # data.web.client_id#data.web.client_secret
        #fulfilment = []
        refreshed_tokens = refreshToken(Client_Id, Client_Secret, base64decode(row[5]))
        # print(refreshed_tokens[0])
        t = threading.Thread(target=updateGooglecredtokens,args=(row[0], refreshed_tokens))
        t.start()
        calendar_cred = {
            "token": f"{refreshed_tokens}",
            "refresh_token": f"{base64decode(row[5])}",
            "token_uri": "https://oauth2.googleapis.com/token",
            "client_id": f"{Client_Id}",
            "client_secret": f"{Client_Secret}",
            "scopes": SCOPES,
        }
    else:
        calendar_cred = {
            "token": f"{base64decode(row[4])}",
            "refresh_token": f"{base64decode(row[5])}",
            "token_uri": "https://oauth2.googleapis.com/token",
            "client_id": f"{Client_Id}",
            "client_secret": f"{Client_Secret}",
            "scopes": SCOPES,
        }
    page_token = None
    try:

        timz = datetime.now(pytz.timezone(row[3])).strftime('%z')
        offset = timz[:3] + ':' + timz[3:]

        cred = google.oauth2.credentials.Credentials(**calendar_cred)
        service = googleapiclient.discovery.build(API_SERVICE_NAME, API_VERSION, cache_discovery=False,
                                                  credentials=cred)
        events_service = service.events().list(calendarId='primary', pageToken=page_token, timeMax=req_max+offset,
                                               timeMin=req_min+offset).execute()

        #events.extend()
        events = events_service.get('items', [])
        globals()['events']=events
    except Exception as e:
        print(str(e))
    return events


# update user timezone
def update_timezone(user_timezone, id):
    con = mysql.connector.connect(host='db4free.net', port=3306, user='cigniti', password='Ctl@1234',
                                  database='chatbotdbdemo')
    # Creating a cursor object using the cursor() method
    cursor = con.cursor()
    sql = f'UPDATE GoogleCredentials SET timezone="{user_timezone}" WHERE Id ={id}'
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
        session = flow.authorized_session()
        profile_info = session.get('https://www.googleapis.com/userinfo/v2/me').json()
        con = mysql.connector.connect(host='db4free.net', port=3306, user='intelli_bot', password='ctl@1234', database='intelligentbot')
        encode_accesstoken = base64encode(credentials.token)
        encode_refreshtoken = base64encode(credentials.refresh_token)
        # encodedstrings= base64encode([credentials.token,credentials.refresh_token])
        calendar_cred = {
            "token": f"{credentials.token}",
            "refresh_token": f"{credentials.refresh_token}",
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
            page_token = None
            calendar_list = service.calendarList().list(pageToken=page_token).execute()
            events = calendar_list.get('items', [])
            if events:
                print(events[0].get('timeZone'))

        except Exception as e:
            print(str(e))
        now = datetime.utcnow()
        cursor = con.cursor(prepared=True)
        cursor.execute(f"SELECT * FROM GoogleCredentials where email='{profile_info['email']}'")
        row = cursor.fetchone()
        if not row:
            sql = "INSERT INTO GoogleCredentials(name,email,timezone,access_token,refresh_token,updated_date) VALUES(%s,%s,%s,%s,%s,%s)"
            val = (profile_info['given_name'], profile_info['email'], events[0].get('timeZone'), encode_accesstoken, encode_refreshtoken, now.strftime("%Y-%m-%d %H:%M:%S"))
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
            sql = f'UPDATE GoogleCredentials SET access_token="{encode_accesstoken}",refresh_token="{encode_refreshtoken}"updated_date="{now.strftime("%Y-%m-%d %H:%M:%S")}  WHERE Id ={row[0]}'
        con.close()



        # return credentials_to_dict(credentials)  # profile_info
        return "Thanks for authorizing the chatbot,please return to the chatbot"


def updateGooglecredtokens(id, accesstoken):
    #print("entered")
    validator = False
    # ret=None
    now = datetime.utcnow()
    con = mysql.connector.connect(host='db4free.net', port=3306, user='intelli_bot', password='ctl@1234',
                                  database='intelligentbot')
    # Creating a cursor object using the cursor() method
    cursor = con.cursor()
    enco_acess = base64encode(accesstoken)
    sql = f'UPDATE GoogleCredentials SET access_token ="{enco_acess}",updated_date="{now.strftime("%Y-%m-%d %H:%M:%S")}" WHERE Id ={id}'
    try:
        # Execute the SQL command
        cursor.execute(sql)
        #print(ret)
        # globals()['ret']=ret
        # Commit your changes in the database
        con.commit()
        if cursor.rowcount is not None:
            validator = True
            globals()['validator'] = validator
            #print(validator)
    except TypeError as e:
        print(e)
        # Rollback in case there is any error
        con.rollback()
        validator = False

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
    #print(refresh_token)
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
        refresh_toks = r.json()['access_token']
        return refresh_toks
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
        'client_secret': credentials.client_ssecret,
        'scopes': credentials.scopes
    }


if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    app.run(host='0.0.0.0', port=5000, debug=True)
