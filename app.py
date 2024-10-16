from cs50 import SQL
from flask import Flask, redirect, render_template, request, session, jsonify, url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import timedelta
import json
import os
from authlib.integrations.flask_client import OAuth, OAuthError
from helpers import login_required, dateHasPassed, validateNewEventInfo, generate_unique_event_id, getListName, getListContacts, validateUpdateEventInfo, isValidAvailability, isValidFullAvailability, stripIndexesFromIntervals, is_valid_email
from dotenv import load_dotenv

load_dotenv()

# global helper variables
default_availability = '{"mon": [["9:00", "17:00"]],"tue": [["9:00", "17:00"]],"wed": [["9:00", "17:00"]],"thu": [["9:00", "17:00"]],"fri": [["9:00", "17:00"]],"sat": [["9:00", "17:00"]],"sun": [["9:00", "17:00"]]}'
default_availability_indexed = {"mon": [[0, "9:00", "17:00"]],"tue": [[0, "9:00", "17:00"]],"wed": [[0, "9:00", "17:00"]],"thu": [[0, "9:00", "17:00"]],"fri": [[0, "9:00", "17:00"]],"sat": [[0, "9:00", "17:00"]],"sun": [[0, "9:00", "17:00"]]}

months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']



# Configure application
app = Flask(__name__)

app.secret_key = os.getenv('SECRET_KEY')
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_FILE_DIR"] = os.path.join(app.instance_path, 'flask_session')
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_USE_SIGNER"] = True  # Sign the session ID
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)
app.config['HOST'] = os.getenv('HOST')
app.config['PORT'] = os.getenv('PORT')
app.config['DEBUG'] = True

Session(app)

# no caching
@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Configure CS50 Library to use SQLite database
db = SQL(os.getenv('DB_URL'))



################################################
################## OAUTH
app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID') 
app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')
app.config['GOOGLE_REDIRECT_URI'] = os.getenv('GOOGLE_REDIRECT_URI')

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=app.config['GOOGLE_CLIENT_ID'],
    client_secret=app.config['GOOGLE_CLIENT_SECRET'],
    access_token_params=None,
    authorize_params=None,
    redirect_uri=app.config['GOOGLE_REDIRECT_URI'],
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    client_kwargs={'scope': 'openid profile email'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    jwks_uri = "https://www.googleapis.com/oauth2/v3/certs"
)


@app.route('/oauth/login')
def oauthLogin():
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route('/oauth/login/callback')
def authorize():
    try: 
        token = google.authorize_access_token()
        user_info = google.get('userinfo').json()

        # Check if the user exists in the database
        user_id = get_user_by_google_id(user_info['id'])

        # If the user doesn't exist, register them to the database
        if not user_id:
            user_id = save_user_to_database(
                google_id=user_info['id'],
                name=user_info['name'],
                email=user_info['email']
            )


        # Store the user information in the session for logged-in status
        session['user_id'] = user_id

        return redirect('/')
    
    except OAuthError as error:
        return redirect('/login')


def get_user_by_google_id(google_id):
    user = db.execute('SELECT id FROM users WHERE google_id = ?', google_id)
    if len(user) > 0:
        user_id = user[0]['id']
    else :
        user_id = None

    return user_id


def save_user_to_database(google_id, name, email):
    new_id = db.execute(
        "INSERT INTO users (fullname, email, google_id, default_availability) VALUES(?, ?, ?, ?)",
        name, email, google_id, default_availability
    )
    return new_id


################################################
################## REGISTER AND LOGIN
@app.route("/login", methods=["GET", "POST"])
def login():
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("email"):
            return render_template('login.html', message="Please enter an email.")

        # Ensure password was submitted
        elif not request.form.get("password"):
            return render_template('login.html', message="Please enter a password.")

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE email = ?", request.form.get("email")
        )

        # Ensure username exists 
        if len(rows) < 1:
            return render_template('login.html' ,message="Invalid username and/or password")

        # Ensure password is correct (if account not a google account)
        if not rows[0]['hash'] or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return render_template('login.html' ,message="Invalid username and/or password")


        # Forget any user_id
        session.clear()
        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    elif request.method == 'GET':
        return render_template("login.html", message="")

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":
        data = request.form
        
        # Check if the passwords is not empty
        if not data["password"]:
            return render_template('register.html', message="Please enter a password")

        # Check if the passwords match
        if data["password"] != data["confirm-password"]:
            return render_template("register.html", message="Password and Confirmation must match")

        # Check if the email is not empty
        if not data["email"]:
            return render_template("register.html", message="Please enter an email")
        
        # Check if email is valid
        if not is_valid_email(data['email']):
            return render_template("register.html", message="Please enter a valid email")

        # Check if the full name is not empty
        if not data["fullname"]:
            return render_template("register.html", message="Please enter your full name")

        # Register user and make sure username is not already taken
        try:
            new_id = db.execute(
                "INSERT INTO users (fullname, email, hash, default_availability) VALUES(?, ?, ?, ?)",
                data['fullname'], 
                data["email"], 
                generate_password_hash(data["password"]),
                default_availability
            )
        except ValueError:
            return render_template("register.html", message="This email has already been used, please try a different one.")

        # Login user and redirect to homepage
        session.clear()
        session["user_id"] = new_id
        return redirect("/")

    elif request.method == 'GET':
        return render_template("register.html", message="")

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')




################################################
################## HOMEPAGE
@app.route('/')
@login_required
def index():
    return render_template('index.html')


@app.route('/events/invitations')
def invitation():
    user_id = session.get("user_id")
    if user_id is None:
        return jsonify({"success": False, "message": "User unauthorized", "status": 401})

    query = """
    SELECT event_users.event_id, events.hashed_id, events.title, users.fullname, events.deadline, 
            events.privacy, event_users.invitation_status
    FROM event_users
    JOIN events ON event_users.event_id = events.id
    JOIN users ON events.creator_id = users.id
    WHERE event_users.user_id = ? AND event_users.user_type = 'invitee' AND event_users.invitation_status IN ('pending', 'accepted');
    """

    data = db.execute(query, user_id)
    data = [
        {**event, 'id': event.pop('event_id')} 
        for event in data 
        if not dateHasPassed(event['deadline'])
    ]

    return jsonify({'success': True, 'events': data})


@app.route('/events/my-events')
def myEvents():
    user_id = session.get("user_id")
    if user_id is None:
        return jsonify({"success": False, "message": "User unauthorized", "status": 401})

    query = "SELECT id, hashed_id, title, end_date, privacy FROM events WHERE creator_id = ?"

    data = db.execute(query, user_id)

    data = [event for event in data if not dateHasPassed(event['end_date'])]

    return jsonify({'success': True, 'events': data})


@app.route('/events/past-events')
def pastEvents():
    user_id = session.get("user_id")
    if user_id is None:
        return jsonify({"success": False, "message": "User unauthorized", "status": 401})
    

    ## created by me
    query1 = "SELECT id, title, end_date, privacy FROM events WHERE creator_id = ?"
    data1 = db.execute(query1, user_id)
    data1 = [event for event in data1 if dateHasPassed(event['end_date'])]


    ## i got invited to
    query2 = """
    SELECT event_users.event_id, events.title, users.fullname, events.deadline, 
            events.privacy
    FROM event_users
    JOIN events ON event_users.event_id = events.id
    JOIN users ON events.creator_id = users.id
    WHERE event_users.user_id = ? AND event_users.user_type = 'invitee';
    """
    data2 = db.execute(query2, user_id)
    data2 = [
        {**event, 'id': event.pop('event_id')} 
        for event in data2 
        if dateHasPassed(event['deadline'])
    ]


    return jsonify({'success': True, 'events': data1 + data2})


     
################################################
################## EVENTS
################## EVENT INFO
# get single event info - update event info - delete event
@app.route('/event/<string:req_id>', methods = ['GET', 'PATCH', 'DELETE'])
def event(req_id):

    user_id = session.get("user_id")
    if user_id is None:
        return jsonify({"success": False, "message": "User unauthorized", "status": 401})
    
    if request.method == 'GET':
        event_id = req_id
        if not event_id:
            return jsonify({'success': False, "message": "No event id provided.", "status": 400})
        
        query = """
            SELECT title, description, location, duration, start_date, end_date, deadline, privacy, fullname
            FROM events
            JOIN users ON events.creator_id = users.id
            WHERE events.id = ?
        """
        event_details = db.execute(query, event_id)

        if len(event_details) <= 0 :
            return jsonify({"success": False, "message": "Event not found", "status": 404})
        event_details = event_details[0]


        # if event is private make sure user is invited and authorized
        if event_details['privacy'] == 'private':
            authorized = db.execute('SELECT * FROM event_users WHERE event_id = ? AND user_id = ?', event_id, user_id)
            if len(authorized) <= 0 :
                return jsonify({"success": False, "message": "Forbidden. You can't access this event.", "status": 403})
            
        return jsonify({"success": True, "details": event_details})


    elif request.method == 'PATCH':
        req = request.get_json()

        event_hash = req_id
        event_id = event_hash.split('o')
        event_id = event_id[len(event_id) - 1]

        # make sure that the event exists and the user is the creator
        event = db.execute('SELECT * FROM events WHERE id = ?', event_id)
        if len(event) <= 0 or event[0]['hashed_id'] != event_hash or event[0]['creator_id'] != user_id:
            return redirect('/not-found')
        event = event[0]

        # validate the new info
        valid = validateUpdateEventInfo(req, event)
        if not valid['success']:
            return jsonify(valid)


        # update the event
        if req['privacy'] == 'public': 
            req['password'] = ''
            req['added_users'] = []
            req['added_lists'] = []

        rowsUpdated = db.execute(
            """ UPDATE events SET
            title = ?, description = ?, location = ?, deadline = ?, privacy = ?, password = ? 
            WHERE id = ?
            """, 
            req['title'], req['description'], req['location'], req['deadline'], req['privacy'], req['password'], event_id
        )
        if rowsUpdated <= 0 :
            return jsonify({"success": False, "message": "Counldn't update event."})


        # if the event is public remove user links and broadcast lists links
        if req['privacy'] == 'public':
            db.execute("DELETE FROM event_users WHERE event_id = ? AND user_type = 'invitee' ", event_id)
            db.execute("DELETE FROM event_broadcast_lists WHERE event_id = ?", event_id)
        
        # if the event is private update user links and broadcast lists links
        if req['privacy'] == 'private':
            # get old and new broadcast lists
            old_lists = db.execute('SELECT broadcast_list_id FROM event_broadcast_lists WHERE event_id = ?', event_id)
            old_lists = [l['broadcast_list_id'] for l in old_lists]
            old_lists = list(set(old_lists))
            new_lists = req['added_lists']

            new_lists = [int(l) for l in new_lists]
            removed_lists = [l for l in old_lists if l not in new_lists ]
            added_lists = [l for l in new_lists if l not in old_lists]

            # remove removed lists
            for bc_list in removed_lists:
                db.execute('DELETE FROM event_broadcast_lists WHERE event_id = ? AND broadcast_list_id = ?', event_id, bc_list)

            # add newly added lists
            for bc_list in added_lists:
                db.execute('INSERT INTO event_broadcast_lists (event_id, broadcast_list_id) VALUES (?, ?)', event_id, bc_list)
               


            # get old individually invited users
            old_individuals = db.execute("SELECT user_id FROM event_users WHERE event_id = ? AND user_type = 'invitee' AND invitation_type = 'individual'", event_id)
            old_individuals = [usr['user_id'] for usr in old_individuals]
            old_individuals = list(set(old_individuals))


            # get old broadcast list linked users
            old_list_linked = db.execute("SELECT user_id FROM event_users WHERE event_id = ? AND user_type = 'invitee' AND invitation_type = 'broadcast_list'", event_id)
            old_list_linked = [usr['user_id'] for usr in old_list_linked]
            old_list_linked = list(set(old_list_linked))


            # get new individually invited users
            new_individuals = req['added_users']
            new_individuals = [int(usr['id']) for usr in new_individuals]
            new_individuals = list(set(new_individuals))
        
            # get new broadcast list linked users
            new_list_linked = []
            for bc_list in new_lists:
                list_contacts = db.execute("SELECT contact_id FROM broadcast_list_contacts WHERE broadcast_list_id = ?", bc_list)
                list_contacts = [usr['contact_id'] for usr in list_contacts]
                new_list_linked += list_contacts

            new_list_linked = list(set(new_list_linked))


            # determine added and removed individuals
            removed_individuals = [usr for usr in old_individuals if usr not in new_individuals]
            added_individuals = [usr for usr in new_individuals if usr not in old_individuals]


            # determine added and removed list linked users
            removed_list_linked = [usr for usr in old_list_linked if usr not in new_list_linked]
            added_list_linked = [usr for usr in new_list_linked if usr not in old_list_linked]

            
            # add/update individually invited users
            for user in added_individuals:
                # if the user exists update invitation type
                changedRows = db.execute("UPDATE event_users SET invitation_type = 'individual' WHERE event_id = ? AND user_id = ?", event_id, user)
                # if the user doesn't exist add new user
                if changedRows <= 0:
                    db.execute('INSERT INTO event_users (event_id, user_id, user_type, invitation_status, invitation_type) VALUES (?, ?, ?, ?, ?)', event_id, user, 'invitee', 'pending', 'individual')
            

            #filter added list linked users for users that are not in new individuals
            added_list_linked = [usr for usr in added_list_linked if usr not in added_individuals]

            # add/update list linked users
            for user in added_list_linked:
                # if the user exists update invitation type
                changedRows = db.execute("UPDATE event_users SET invitation_type = 'broadcast_list' WHERE event_id = ? AND user_id = ?", event_id, user)
                # if the user doesn't exist add new user
                if changedRows <= 0:
                    db.execute('INSERT INTO event_users (event_id, user_id, user_type, invitation_status, invitation_type) VALUES (?, ?, ?, ?, ?)', event_id, user, 'invitee', 'pending', 'broadcast_list')

            # remove removed users
            removed_users = ([usr for usr in removed_individuals if usr not in new_list_linked] + 
                             [usr for usr in removed_list_linked if usr not in new_individuals])
            for user in removed_users:
                db.execute('DELETE FROM event_users WHERE event_id = ? AND user_id = ?', event_id, user)


        return {"success": True}
        
    elif request.method == 'DELETE':
        event_id = req_id
        
        # make sure the event exists and user owns this event
        event = db.execute('SELECT id FROM events WHERE id = ? AND creator_id = ?', event_id, user_id)
        if len(event) <= 0:
            return ({"success": False, "message": "Event not found", "status": 404})
        
        # delete secondary keys
        db.execute('DELETE FROM event_users WHERE event_id = ?', event_id)
        db.execute("DELETE FROM event_broadcast_lists WHERE event_id = ?", event_id)

        # delete primary key
        db.execute("DELETE FROM events WHERE id = ?", event_id)

        return({"success": True})


# render create event page - create new event 
@app.route('/create-event', methods=['GET', 'POST'])
def createEvent(): 
    user_id = session.get('user_id')

    if request.method == 'GET':
        if user_id is None:
            return redirect('/login')
        
        user_broadcast_lists = db.execute("SELECT id, broadcast_list_name FROM broadcast_lists WHERE creator_id = ?", user_id)
    
        return render_template('create-event.html', lists = user_broadcast_lists)
    

    elif request.method == 'POST':
        if user_id is None:
            return jsonify({"success": False, "message": "User unauthorized", "status": 401})

        req = request.get_json()
        validation = validateNewEventInfo(req)

        if not validation['success']:
            return jsonify(validation)
        
        # add new event
        duration = req['duration']['hours'] + ':' + req['duration']['mins']
        new_event_id = db.execute(
            """ INSERT INTO events
            (hashed_id, creator_id, title, description, location, duration, start_date, end_date, deadline, privacy, password)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) """, 
            generate_unique_event_id("0"), user_id, req['title'], req['description'], req['location'], duration, req['start_date'], req['end_date'], req['deadline'], req['privacy'], req['password']
        )

        new_hashed_id = generate_unique_event_id(new_event_id)
        db.execute('UPDATE events SET hashed_id = ? WHERE id = ?', new_hashed_id, new_event_id)


        # Link Creator
        creator_availability = db.execute('SELECT default_availability FROM users WHERE id = ?', user_id)
        if len(creator_availability) > 0:
            creator_availability = creator_availability[0]['default_availability']
        else: 
            creator_availability = default_availability
        
        creator_availability = json.loads(creator_availability)
        creator_availability = [creator_availability]

        db.execute('INSERT INTO event_users (event_id, user_id, user_type, user_availability, invitation_status, invitation_type) VALUES (?, ?, ?, ?, ?, ?)', new_event_id, user_id, 'creator', json.dumps(creator_availability), 'accepted', 'self')

        if req['privacy'] == 'private':
            # Link individual users
            added_users = [usr['id'] for usr in req['added_users']]
            added_users = list(set(added_users))
            for user in added_users:
                db.execute('INSERT INTO event_users (event_id, user_id, user_type, invitation_status, invitation_type) VALUES (?, ?, ?, ?, ?)', new_event_id, user, 'invitee', 'pending', 'individual')

            # Link Broadcast lists
            added_lists = list(set(req['added_lists']))
            added_contacts = []
            for bc_list in added_lists:
                db.execute('INSERT INTO event_broadcast_lists (event_id, broadcast_list_id) VALUES (?, ?)', new_event_id, bc_list)
                list_contacts = db.execute("SELECT contact_id FROM broadcast_list_contacts WHERE broadcast_list_id = ?", bc_list)
                list_contacts = [usr['contact_id'] for usr in list_contacts]
                added_contacts += list_contacts

            # Link contacts of the broadcast lists
            added_contacts = list(set(added_contacts))
            added_contacts = [usr for usr in added_contacts if usr not in added_users]
            for user in added_contacts:
                db.execute('INSERT INTO event_users (event_id, user_id, user_type, invitation_status, invitation_type) VALUES (?, ?, ?, ?, ?)', new_event_id, user, 'invitee', 'pending', 'broadcast_list')


        return {"success": True}

    
# render setings page
@app.route('/settings/<string:event_hash>')
@login_required
def editSetting(event_hash): 
    event_id = event_hash.split('o')
    event_id = event_id[len(event_id) - 1]
    user_id = session.get('user_id')

    event = db.execute("SELECT * FROM events WHERE id = ?", event_id)
    if len(event) <= 0 or event[0]['hashed_id'] != event_hash or event[0]['creator_id'] != user_id:
        return redirect('/not-found')
    event = event[0]

    all_lists = db.execute('SELECT id, broadcast_list_name FROM broadcast_lists WHERE creator_id = ?', user_id)
    all_lists = [
        {"id": l['id'], "name": l['broadcast_list_name']}
        for l in all_lists
    ]
    added_lists = db.execute('SELECT broadcast_lists.id, broadcast_list_name FROM event_broadcast_lists JOIN broadcast_lists ON id = broadcast_list_id WHERE event_id = ?', event_id)
    added_lists = [
        {"id": l['id'], "name": l['broadcast_list_name']}
        for l in added_lists
    ]
    added_users = db.execute("SELECT users.id, users.email FROM users JOIN event_users ON users.id = event_users.user_id WHERE event_users.event_id = ? AND user_type = 'invitee' AND invitation_type = 'individual'", event_id)

    data = {   
        "name": event['title'],
        "deadline": event['deadline'],
        "privacy": event['privacy'],
        "duration": {
            "hours": event['duration'].split(':')[0],
            "mins": event['duration'].split(':')[1]
        },
        "description": event['description'],
        "location": event['location'],
        "startDateHtmlFormat": event['start_date'],
        "endDateHtmlFormat": event["end_date"],
        "startDate": " ".join([event['start_date'].split('-')[2], months[int(event['start_date'].split('-')[1])-1], event['start_date'].split('-')[0]]),
        "endDate": " ".join([event['end_date'].split('-')[2], months[int(event['end_date'].split('-')[1])-1], event['end_date'].split('-')[0]]),
        "password": event['password'],
        "addedUsers" : added_users,
        "addedLists": added_lists,
        "allLists": all_lists
    }


    return render_template('settings.html', data=data)


################# EVENTS AND USER INTERACTIONS/SUBMISSIONS
## Decline Invitation
@app.route('/decline-invitation/<string:event_id>', methods = ['PATCH'])
def declineInvitation(event_id):
    if not event_id:
        return jsonify({"success": False, "message": "Event id not provided", "status": 400})
    
    user_id = session.get("user_id")
    if user_id is None:
        return jsonify({"success": False, "message": "User unauthorized.", "status": 401})

    changedRows = db.execute("UPDATE event_users SET invitation_status = 'declined' WHERE event_id = ? AND user_id = ?", event_id, user_id)

    if changedRows <= 0:
        return jsonify({"success": False, "message": "Update unsuccessfull.", "status": 404})

    return jsonify({"success": True})
    

## Accept invitation / submit availability
@app.route('/events/<string:event_hash>', methods = ['GET', 'PATCH', 'POST'])
def events(event_hash): 
    if request.method == 'GET':
        # check if user is logged in    
        user_id = session.get('user_id')
        if user_id is None: loggedin = False
        else: loggedin = True

        if not event_hash:
            return render_template('error.html', data={
                'code': '404',
                'message': "Couldn't find the page your were looking for.",
                'loggedin': loggedin
            })

        event_id = event_hash.split('o')
        event_id = event_id[len(event_id) - 1]

        ## check if event exists
        query = """
            SELECT hashed_id, title, description, location, duration, start_date, end_date, deadline, privacy, users.fullname
            FROM events
            JOIN users ON events.creator_id = users.id
            WHERE events.id = ?
        """
        event = db.execute(query, event_id)

        if len(event) <= 0 or event[0]['hashed_id'] != event_hash:
            return render_template('error.html', data={
                'code':'404', 
                'message':"Couldn't find the event you were looking for.",
                'loggedin': loggedin
            })
        event = event[0]

        # check if event deadline has passed
        if dateHasPassed(event['deadline']):
            return render_template('error.html', data={
                'code': '400',
                'message': "The deadline for this event has passed.",
                'loggedin': loggedin
            })


        # check if user has already submitted
        if session.get('submitted_events') and event_id in session.get('submitted_events'):
            return render_template('error.html', data={
                'code': "409",
                'message': "You have already submitted your availability for this event.",
                'loggedin': loggedin,
                'eventHash': event_hash
            })


        


        # check if event is pubilc
        if event['privacy'] == 'public':
            if loggedin: # check if already submitted
                submitted = db.execute("SELECT user_id FROM event_users WHERE user_id = ? AND event_id = ? AND invitation_status = 'accepted' ", user_id, event_id)
                if len(submitted) > 0:
                    return render_template('error.html', data={
                        'code': "409",
                        'message': "You have already submitted your availability for this event.",
                        'loggedin': loggedin,
                        'eventHash': event_hash
                    })
                
                # get user's defaul availability
                user_availability = db.execute('SELECT default_availability FROM users WHERE id = ?', user_id)

                if len(user_availability) <= 0 : user_availability = default_availability
                else : user_availability = user_availability[0]['default_availability']

                user_availability = json.loads(user_availability)

                for day in user_availability:
                    i = 0
                    for interval in user_availability[day]:
                        interval.insert(0, i)
                        i += 1

                return render_template('submit-availability.html', availability=[user_availability], event=event)

            if not loggedin: # check if fullname is provided
                if not session.get('fullname'):
                    return render_template('event-password.html', fields=['fullname'])

                return render_template('submit-availability.html', availability=[default_availability_indexed], event=event)




        # if not logged in render password page
        if not loggedin:
            if session.get('accessed_events') and event_id in session.get('accessed_events'): ## if user has already entered the correct password
                return render_template('submit-availability.html', availability=[default_availability_indexed], event=event)

            if not session.get('fullname'):
                return render_template('event-password.html', fields=['fullname', 'password'])
            
            return render_template('event-password.html', fields=['password'])



        # if logged in check if they have direct access 
        access = db.execute('SELECT invitation_status FROM event_users WHERE event_id = ? AND user_id = ?', event_id, user_id)


        # if they don't have access or have declined the invitation display password page
        if len(access) <= 0 or access[0]['invitation_status'] == 'declined':     
            return render_template('event-password.html', fields=['password'])


        access = access[0]

        ## if they have access but already submitted
        if access['invitation_status'] == 'accepted' :
            return render_template('error.html', data={
                'code': "409",
                'message': "You have already submitted your availability for this event.",
                'loggedin': loggedin,
                'eventHash': event_hash
            })


        ## render page
        user_availability = db.execute('SELECT default_availability FROM users WHERE id = ?', user_id)

        if len(user_availability) <= 0 :
            user_availability = default_availability
        else :
            user_availability = user_availability[0]['default_availability']

        user_availability = json.loads(user_availability)

        for day in user_availability:
            i = 0
            for interval in user_availability[day]:
                interval.insert(0, i)
                i += 1

        return render_template('submit-availability.html', availability=[user_availability], event=event)

    elif request.method == 'PATCH':
        # check if user is logged in
        user_id = session.get('user_id')
        if user_id is None: loggedin = False
        else: loggedin = True

        # check if event hash is valid
        if not event_hash:
            return jsonify({'success': False, 'message':"Event id not provided.", 'status': 400})

        event_id = event_hash.split('o')
        event_id = event_id[len(event_id) - 1]

        ## check if event exists
        event = db.execute("SELECT hashed_id, deadline, privacy FROM events WHERE id = ?", event_id)

        if len(event) <= 0 or event[0]['hashed_id'] != event_hash:
            return jsonify({'success': False, 'message':"Event not found.", 'status': 404})
        event = event[0]

        ## ensure deadline hasn't passed
        if dateHasPassed(event['deadline']):
            return jsonify({'success': False, 'message':"Event deadline has passed.", 'status': 400})




        # if not logged in check if they entered the password & check if they already submitted
        if not loggedin:
            if event['privacy'] == 'private' and (not session.get('accessed_events') or not event_id in session.get('accessed_events') or not session.get("fullname")):
                return jsonify({'success': False, 'message':"Forbidden. You can't access this event.", 'status': 403})
            
            elif event['privacy'] == 'public' and not session.get('fullname'):
                return jsonify({'success': False, 'message':"Please referesh the page and enter you fullname first.", 'status': 400})
            
            elif session.get('submitted_events') and event_id in session.get('submitted_events'):
                return jsonify({'success': False, 'message':"You already submitted your availability.", 'status': 409})

            else:

                ## validate submitted data
                availability = request.get_json()
                if not availability or len(availability) <= 0:
                    return jsonify({"success": False, "message": "No availability provided", "status": 400})
                    
                for day in availability[0]:
                    if 'unavailable' in availability[0][day]:
                        availability[0][day] = []

                if not isValidFullAvailability(availability):
                    return jsonify({"success": False, "message": "Please fix all errors before submitting", "status": 400})

                # remove the indexes from the intervals
                availability = stripIndexesFromIntervals(availability)
                availability = json.dumps(availability)
                # submit data to a new table
                submission_id = db.execute('INSERT INTO unknown_submissions (event_id, fullname, user_availability) VALUES (?, ?, ?)', event_id, session.get('fullname'), availability)

                if not submission_id:
                    return jsonify({"success": False, "message": "Server error. Could not submit your availability.", "status": 500})


                if session.get('submitted_events') is None:
                    session['submitted_events'] = {}
                session['submitted_events'][event_id] = submission_id
                
                return jsonify({'success': True})

        


        # if logged in  
        
        # make sure user hasn't already submitted
        user_submitted = db.execute("SELECT user_id FROM event_users WHERE user_id = ? AND event_id = ? AND invitation_status = 'accepted'", user_id, event_id)
        if len(user_submitted) > 0:
            return jsonify({"success": False, "message": "You already submitted you availability.", "status": 409})    
          

        ## validate submitted data
        availability = request.get_json()
        if not availability or len(availability) <= 0:
            return jsonify({"success": False, "message": "No availability provided", "status": 400})
            
        for day in availability[0]:
            if 'unavailable' in availability[0][day]:
                availability[0][day] = []

        if not isValidFullAvailability(availability):
            return jsonify({"success": False, "message": "Please fix all errors before submitting", "status": 400})

        # remove the indexes from the intervals
        availability = stripIndexesFromIntervals(availability)
        availability = json.dumps(availability)


        
        # submit && check access at the same time
        if event['privacy'] == 'private':
            changed_rows = db.execute("""
                UPDATE event_users 
                SET user_availability = ?, invitation_status = 'accepted' 
                WHERE user_id = ? AND event_id = ?
            """, 
                availability, user_id, event_id
            )
            if changed_rows <= 0 :
                return jsonify({"success": False, "message": "Forbidden. You can't access this event.", "status": 403})
            
        else:
            db.execute("""
                INSERT INTO event_users (event_id, user_id, user_type, invitation_type, invitation_status, user_availability) 
                VALUES (?, ?, 'invitee', 'public', 'accepted', ?)
            """, event_id, user_id, availability)

        return jsonify({"success": True})

    elif request.method == 'POST':
        req = request.get_json()
        # check if event hash is valid
        if not event_hash:
            return jsonify({'success': False, 'message':"Event id not provided.", 'status': 400})

        event_id = event_hash.split('o')
        event_id = event_id[len(event_id) - 1]

        ## check if event exists
        event = db.execute("SELECT hashed_id, deadline, password, privacy FROM events WHERE id = ?", event_id)

        if len(event) <= 0 or event[0]['hashed_id'] != event_hash:
            return jsonify({'success': False, 'message':"Event not found.", 'status': 404})
        event = event[0]

        ## ensure deadline hasn't passed
        if dateHasPassed(event['deadline']):
            return jsonify({'success': False, 'message':"Event deadline has passed.", 'status': 400})


        if event['privacy'] == 'private':
            # check if password is provided
            if not req['password']:
                return jsonify({'success': False, 'message':"Password was not provided.", 'status': 400})

            # check if password is correct
            if not req['password'].upper() == event['password'].upper():
                return jsonify({'success': False, 'message':"Password is incorrect.", 'status': 400})
        
        
        user_id = session.get('user_id')

        ## if user not logged in
        if user_id is None:

            # check if fullname is provided
            if not session.get('fullname') and not req['fullname']:
                return jsonify({'success': False, 'message':"Fullname was not provided.", 'status': 400})
            elif not session.get('fullname') and req['fullname']:
                session['fullname'] = req['fullname']

            # give user access to the event
            if not session.get('accessed_events'):
                session['accessed_events'] = []
            session['accessed_events'].append(event_id)
            return jsonify({'success': True})

        
        if event['privacy'] == 'private':
            # if user logged in make sure they don't already have access then give access
            access = db.execute('SELECT invitation_status FROM event_users WHERE user_id = ? AND event_id = ?', user_id, event_id)
            if len(access) <= 0 :
                db.execute("""
                    INSERT INTO event_users
                    (event_id, user_id, user_type, invitation_type, invitation_status)
                    VALUES (?, ?, 'invitee', 'password', 'pending')
                """, event_id, user_id
                )
            # if the user previously declined the invitation change it to 'pending'
            elif access[0]['invitation_status'] == 'declined':
                db.execute("UPDATE event_users SET invitation_status = 'pending' WHERE user_id = ? AND event_id = ?", user_id, event_id)
        

        return jsonify({'success': True})
                

## Change Availabiilty
@app.route('/change-availability/<string:event_hash>', methods = ['GET', 'PATCH'])
def changeAvailability(event_hash):

    if request.method == 'GET':
        # check if user is logged in    
        user_id = session.get('user_id')
        if user_id is None: loggedin = False
        else: loggedin = True

        if not event_hash:
            return render_template('error.html', data={
                'code': '404',
                'message': "Couldn't find the page your were looking for.",
                'loggedin': loggedin
            })

        event_id = event_hash.split('o')
        event_id = event_id[len(event_id) - 1]

        ## check if event exists
        query = """
            SELECT hashed_id, title, description, location, duration, start_date, end_date, deadline, privacy, users.fullname
            FROM events
            JOIN users ON events.creator_id = users.id
            WHERE events.id = ?
        """
        event = db.execute(query, event_id)

        if len(event) <= 0 or event[0]['hashed_id'] != event_hash:
            return render_template('error.html', data={
                'code':'404', 
                'message':"Couldn't find the event you were looking for.",
                'loggedin': loggedin
            })
        event = event[0]

        # check if event deadline has passed
        if dateHasPassed(event['deadline']):
            return render_template('error.html', data={
                'code': '400',
                'message': "The deadline for this event has passed.",
                'loggedin': loggedin
            })
        

        # check if not submitted yet and get user availability
        if loggedin: 
            # check if not already submitted
            submitted = db.execute("SELECT user_id FROM event_users WHERE user_id = ? AND event_id = ? AND invitation_status = 'accepted' ", user_id, event_id)
            if len(submitted) <= 0:
                return redirect('/events/' + event_hash)
            
            # get user's submitted availability
            user_availability = db.execute("SELECT user_availability FROM event_users WHERE user_id = ? AND event_id = ? AND invitation_status = 'accepted'", user_id, event_id)

        # check if not submitted yet and get user availability
        elif not loggedin: 
            # check if not already submitted 
            if not session.get('submitted_events') or not event_id in session.get('submitted_events'):
                return redirect('/events/' + event_hash)

            # get user availability
            submission_id = session.get('submitted_events')[event_id]
            user_availability = db.execute('SELECT user_availability FROM unknown_submissions WHERE event_id = ? AND id = ?', event_id, submission_id)

            
        # format availability
        if len(user_availability) <= 0 : 
            user_availability = default_availability
            user_availability = json.loads(user_availability)
            user_availability = [user_availability]
        else : 
            user_availability = user_availability[0]['user_availability']
            user_availability = json.loads(user_availability)

        for day in user_availability[0]:
            i = 0
            for interval in user_availability[0][day]:
                interval.insert(0, i)
                i += 1

        if len(user_availability) > 1:
            for day in range(len(user_availability) - 1):
                i = 0
                for interval in range(len(user_availability[day + 1]['intervals'])):
                    user_availability[day + 1]['intervals'][interval].insert(0, i)
                    i += 1

        # render page
        return render_template('change-availability.html', availability=user_availability, event=event)

    if request.method == 'PATCH':
        # check if user is logged in    
        user_id = session.get('user_id')
        if user_id is None: loggedin = False
        else: loggedin = True

        if not event_hash:
            return jsonify({'succes': False, 'message': 'Event id not provided.', 'status': 400})
            
        event_id = event_hash.split('o')
        event_id = event_id[len(event_id) - 1]

        ## check if event exists
        event = db.execute("SELECT hashed_id, deadline FROM events WHERE events.id = ?", event_id)

        if len(event) <= 0 or event[0]['hashed_id'] != event_hash:
            return jsonify({'succes': False, 'message': "Couldn't find the event.", 'status': 404})
        event = event[0]

        # check if event deadline has passed
        if dateHasPassed(event['deadline']):
            return jsonify({'succes': False, 'message': "The deadline for this event has passed.", 'status': 400})
        


        ## validate submitted data
        availability = request.get_json()
        if not availability or len(availability) <= 0:
            return jsonify({"success": False, "message": "No availability provided", "status": 400})
        
        for day in availability[0]:
            if 'unavailable' in availability[0][day]:
                availability[0][day] = []

        if not isValidFullAvailability(availability):
            return jsonify({"success": False, "message": "Please fix all errors before submitting", "status": 400})

        # remove the indexes from the intervals
        availability = stripIndexesFromIntervals(availability)
        availability = json.dumps(availability)




        # update and check if the user hasn't already submitted at the same time
        if loggedin: 
            changedRows = db.execute("UPDATE event_users SET user_availability = ? WHERE event_id = ? AND user_id = ? AND invitation_status = 'accepted'", availability, event_id, user_id)

            if changedRows <= 0:
                return jsonify({'succes': False, 'message': "Can't edit. You haven't submitted yet.", 'status': 403})

                
            
        # check if not submitted yet then update
        elif not loggedin: 
            # check if not already submitted 
            if not session.get('submitted_events') or not event_id in session.get('submitted_events'):
                return jsonify({'succes': False, 'message': "Can't edit. You haven't submitted yet.", 'status': 403})
            
            # update
            submission_id = session.get('submitted_events')[event_id]
            changedRows = db.execute('UPDATE unknown_submissions SET user_availability = ? WHERE id = ? AND event_id = ?', availability, submission_id, event_id)

            print(availability)

            if changedRows <= 0:
                return jsonify({'succes': False, 'message': "Couldn't update your availability.", 'status': 500})


        return jsonify({'success': True})

   
# view event submissions
@app.route('/submissions/<string:event_hash>')
@login_required
def submissions(event_hash): 
    user_id = session.get('user_id')

    # make sure event exists and is created by the user
    event_id = event_hash.split('o')
    event_id = event_id[len(event_id) - 1]

    event = db.execute("SELECT * FROM events WHERE id = ?", event_id)
    if len(event) <= 0 or event[0]['hashed_id'] != event_hash or event[0]['creator_id'] != user_id:
        return redirect('/not-found')
    event = event[0]


    # get submissions (users with accounts)
    user_submissions = db.execute("""
        SELECT event_users.user_availability, users.fullname
        FROM event_users
        JOIN users ON event_users.user_id = users.id
        WHERE event_users.event_id = ? 
        AND event_users.invitation_status = 'accepted'
    """, event_id)
    
    # get submissions (users with no accounts)
    unknown_submissions = db.execute("SELECT user_availability, fullname FROM unknown_submissions WHERE event_id = ?", event_id)

    # format submissions
    submissions = user_submissions + unknown_submissions
    submissions = [
        {**sub, 'user_availability': json.loads(sub['user_availability'])} 
        for sub in submissions
    ]


    # get missing submissions
    missing_submissions = db.execute("""
        SELECT users.fullname FROM users
        JOIN event_users ON users.id = event_users.user_id
        WHERE event_users.event_id = ? AND invitation_status IN ('pending', 'declined')
     """, event_id)
    
    missing_submissions = [sub['fullname'] for sub in missing_submissions]
    print(missing_submissions)
    return render_template('submissions.html', submissions=submissions, event=event,  missing_submissions=missing_submissions)




################################################
################## MY DEFAULT AVAILABILITY
@app.route('/my-availability', methods = ['GET', "PATCH"])
def myAvailability(): 
    user_id = session.get('user_id')

    if request.method == 'GET':
        if user_id is None:
            return redirect('/login')
        
        availability = db.execute('SELECT default_availability FROM users WHERE id = ?', user_id)

        if len(availability) <= 0 :
            availability = default_availability
        else :
            availability = availability[0]['default_availability']

        availability = json.loads(availability)

        for day in availability:
            i = 0
            for interval in availability[day]:
                interval.insert(0, i)
                i += 1

        return render_template('my-availability.html', availability=availability)

    elif request.method == 'PATCH':
        if user_id is None:
            return jsonify({"success": False, "message": "User unauthorized.", "status": 401})

        # validate availability
        availability = request.get_json()
        for day in availability:
            if 'unavailable' in availability[day]:
                availability[day] = []

        if not isValidAvailability(availability):
            return jsonify({"success": False, "message": "Please fix all errors before submitting", "status": 400})

        # remove the indexes from the intervals
        for day in availability:
            for i in range(len(availability[day])):
                availability[day][i] = availability[day][i][1:]
            
        availability = json.dumps(availability)

        changedRows = db.execute('UPDATE users SET default_availability = ? WHERE id = ?', availability, user_id)
        if changedRows <= 0:
            return jsonify({"success": False, "message": "Couldn't update your availability.", "status": 404})
            

        return jsonify({"success": True})




################################################
################## BROADCAST LISTS
@app.route('/broadcast-lists')
@login_required
def broadcastLists(): 
    user_id = session.get('user_id')
    user_broadcast_lists = db.execute("SELECT id, broadcast_list_name FROM broadcast_lists WHERE creator_id = ?", user_id)
    return render_template('broadcast-lists.html', data = user_broadcast_lists)


@app.route('/broadcast-list', methods=['GET', 'POST', 'PATCH', 'DELETE'])
def broadcastList():
    user_id = session.get('user_id')
    if user_id is None:
        return jsonify({"success": False, "message": "User unauthorized", "status": 401})

    if request.method == "POST":
        req = request.get_json()

        # check if a list name is provided
        list_name = req['listName']
        if not list_name:
            return jsonify({'success': False, "message": "No list name provided", "status": 400})
        list_name = ' '.join(list_name.split())

        # check if the user already has a list with this name
        existing_list_names = db.execute("SELECT broadcast_list_name FROM broadcast_lists WHERE creator_id = ?", user_id)
        existing_list_names = [list['broadcast_list_name'].lower() for list in existing_list_names]

        if list_name.lower() in existing_list_names:
            return jsonify({'success': False, "message": "You already have a list with this name.", "status": 409})

        # check if at least 1 valid user is provided (user exists and is not the user himself)
        usersList = req['usersList']
        if len(usersList) <= 0 :
            return jsonify({'success': False, "message": "Add at least 1 user to the list.", "status": 400})
        
        usersList = [usr["id"] for usr in usersList]
        existing_user_ids = db.execute('SELECT id FROM users')
        existing_user_ids = [usr['id'] for usr in existing_user_ids]

        usersList = [id for id in usersList if id in existing_user_ids and id != user_id]
        
        if len(usersList) <= 0 :
            return jsonify({'success': False, "message": "Add at least 1 user to the list.", "status": 400})


        # create new list
        new_list_id = db.execute('INSERT INTO broadcast_lists (creator_id, broadcast_list_name) VALUES (?, ?)', user_id, list_name)

        for user in usersList:
            db.execute('INSERT INTO broadcast_list_contacts (broadcast_list_id, contact_id) VALUES (?, ?)', new_list_id, user)

        user_broadcast_lists = db.execute("SELECT id, broadcast_list_name FROM broadcast_lists WHERE creator_id = ?", user_id)
        return jsonify({"success": True, 'lists': user_broadcast_lists})

    elif request.method == 'PATCH':
        req = request.get_json()

        list_id = req["listId"]
        if not list_id:
            return jsonify({"success": False, "message": "List id is missing from the request.", "status": 400})

        # get old & new list name
        new_list_name = req["listName"]
        if not new_list_name:
            return jsonify({"success": False, "message": "No list name provided.", "status": 400})
        new_list_name = ' '.join(new_list_name.split())

        old_list_name = getListName(list_id, user_id)
        if not old_list_name:
            return jsonify({"success": False, "message": "List not found.", "status": 404})
        
        # check if the user already has a list with this name then update the list name
        existing_list_names = db.execute("SELECT broadcast_list_name FROM broadcast_lists WHERE creator_id = ?", user_id)
        existing_list_names = [list['broadcast_list_name'].lower() for list in existing_list_names]

        if new_list_name != old_list_name and new_list_name.lower() in existing_list_names:
            return jsonify({'success': False, "message": "You already have a list with this name.", "status": 409})
        
        db.execute('UPDATE broadcast_lists SET broadcast_list_name = ? WHERE id = ?', new_list_name, list_id)

        # get old & new list contacts
        new_list = req["usersList"]
        old_list = getListContacts(list_id)

        # we only need the ids
        new_list = [usr['id'] for usr in new_list]
        old_list = [usr['id'] for usr in old_list]

        if user_id in new_list:
            return jsonify({'success': False, 'message': "You can't add yourself to the list.", "status": 403})

        # check that new users ids are valid then add the new contacts
        existing_user_ids = db.execute('SELECT id FROM users')
        existing_user_ids = [usr['id'] for usr in existing_user_ids]

        added_users = [usr for usr in new_list if usr not in old_list]
        added_users = [usr for usr in added_users if usr in existing_user_ids]

        for user in added_users:
            db.execute('INSERT INTO broadcast_list_contacts (broadcast_list_id, contact_id) VALUES (?, ?)', list_id, user)
        
        # remove contacts
        removed_users = [usr for usr in old_list if usr not in new_list]
        for user in removed_users:
            db.execute('DELETE FROM broadcast_list_contacts WHERE broadcast_list_id = ? AND contact_id = ?', list_id, user)

        return jsonify({"success": True})
    
    elif request.method == "GET":
        list_id = request.args.get('listId')
        if not list_id:
            return jsonify({"success": False, "message": "List id is missing from the request.", "status": 400})
        
        # get list name
        list_name = getListName(list_id, user_id)
        if not list_name:
            return jsonify({"success": False, "message": "List not found.", "status": 404})
            
        # get list contacts
        contacts = getListContacts(list_id)

        return jsonify({"success": True, "data": {
            "list_id": list_id,
            "list_name": list_name,
            "contacts": contacts
        }})
    
    elif request.method == 'DELETE':
        req = request.get_json()

        # get list id
        list_id = req["listId"]
        if not list_id:
            return jsonify({"success": False, "message": "List id is missing from the request.", "status": 400})
        
        # check if an ongoing event is using this list
        events_using_list = db.execute("SELECT deadline FROM events JOIN event_broadcast_lists ON events.id = event_broadcast_lists.event_id WHERE broadcast_list_id = ?", list_id) 
        events_using_list = [event['deadline'] for event in events_using_list if not dateHasPassed(event['deadline'])]

        if len(events_using_list) > 0:
            return jsonify({"success": False, "message": "An ongoing event is using this list. Wait until the event is over.", "status": 409})
            
        # check if the user owns this list
        owned_by_user = db.execute('SELECT id FROM broadcast_lists WHERE id = ? AND creator_id = ?', list_id, user_id)
        if len(owned_by_user) <= 0 :
            return jsonify({"success": False, "message": "Couldn't delete this list.", "status": 404})


        # delete contacts links to this list (foreign key)
        db.execute("DELETE FROM broadcast_list_contacts WHERE broadcast_list_id = ?", list_id)

        # delete event links to this list (foreign key)
        db.execute('DELETE FROM event_broadcast_lists WHERE broadcast_list_id = ?', list_id)

        # delete list (primary key)
        deleted_rows = db.execute('DELETE FROM broadcast_lists WHERE id = ? AND creator_id = ?', list_id, user_id)

        if deleted_rows == 0:
            return jsonify({'success': False, "message": "Couldn't delete this list.", "status": 404})
        

        user_broadcast_lists = db.execute("SELECT id, broadcast_list_name FROM broadcast_lists WHERE creator_id = ?", user_id)
        return jsonify({"success": True, 'lists': user_broadcast_lists})


## USER EXISTS? AND ISN'T YOU?
@app.route('/api/user-exists', methods = ["POST"])
def userExists():
    user_id = session.get("user_id")
    if user_id is None:
        return jsonify({"success": False, "message": "User unauthorized", "status": 401})
    
    req = request.get_json()

    if not "email" in req:
        return jsonify({'success': False, "message": "No email provided.", "status": 400})

    user = db.execute('SELECT id, fullname, email FROM users WHERE email == ? ', req["email"])

    if len(user) <= 0 :
        return jsonify({'success': False, "message": "User not found", "status": 404})
    
    user = user[0]

    if user['id'] == user_id: 
        return jsonify({'success': False, "message": "You can't add yourself to the list.", "status": 403})
    
    
    return jsonify({"success": True, "user": user})





# Custom 404 error handler
@app.errorhandler(404)
def page_not_found(e):
    user_id = session.get('user_id')
    if user_id is None: loggedin = False
    else: loggedin = True

    return render_template('error.html', data={
        'code': '404',
        'message': "Couldn't find what you were looking for.",
        'loggedin': loggedin
    })

# All Errors handler
@app.errorhandler(Exception) 
def internal_server_error(e) :
    user_id = session.get('user_id')
    if user_id is None: loggedin = False
    else: loggedin = True

    return render_template('error.html', data={
        'code': '500',
        'message': "Oops! Something went wrong on our end. It's not you, it's us. We're working on fixing the issue. Please try again later.",
        'loggedin': loggedin
    })



if __name__ == '__main__':
    app.run(host=app.config['HOST'], port=app.config['PORT'])
