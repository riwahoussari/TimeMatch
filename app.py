from flask import Flask, render_template, jsonify, request
app = Flask(__name__)


@app.route('/')
def index():
    data = [
        {
            "event_id": "1",
            "name": "The very long and important event name",
            "deadline": "10/10/2024",
            "creator": "Alexander The Great",
            "privacy": "private",
            "invitation_status": "pending"
        },
        {
            "event_id": "2",
            "name": "Urgent Marketing Meeting",
            "deadline": "21/10/2024",
            "creator": "Riwa Houssari",
            "privacy": "private",
            "invitation_status": "accepted"
        }
    ]
    return render_template('index.html', data=data)


@app.route('/login')
def login(): 

    return render_template('login.html')


@app.route('/register')
def register(): 

    return render_template('register.html')


@app.route('/my-availability')
def myAvailability(): 

    return render_template('my-availability.html')


@app.route('/broadcast-lists')
def broadcastLists(): 

    return render_template('broadcast-lists.html')


@app.route('/create-event')
def createEvent(): 

    return render_template('create-event.html')


@app.route('/api/invitations')
def invitation():
    data = [
        {
            "event_id": "1",
            "name": "The very long and important event name",
            "deadline": "10/10/2024",
            "creator": "Alexander The Great",
            "privacy": "private",
            "invitation_status": "pending"
        },
        {
            "event_id": "2",
            "name": "Urgent Marketing Meeting",
            "deadline": "21/10/2024",
            "creator": "Riwa Houssari",
            "privacy": "private",
            "invitation_status": "accepted"
        }
    ]
    return jsonify(data)

@app.route('/api/my-events')
def myEvents():
    data = [
        {
            "name": "The very long and important event name",
            "deadline": "10/10/2024",
            "creator": "Alexander The Great",
            "privacy": "private"
        },
        {
            "name": "Urgent Marketing Meeting",
            "deadline": "21/10/2024",
            "creator": "Riwa Houssari",
            "privacy": "public"
        }
    ]
    return jsonify(data)

@app.route('/api/past-events')
def pastEvents():
    data = [
        {
            "name": "The very long and important event name",
            "deadline": "10/10/2024",
            "creator": "Alexander The Great",
            "privacy": "private"
        },
        {
            "name": "Urgent Marketing Meeting",
            "deadline": "21/10/2024",
            "creator": "Riwa Houssari",
            "privacy": "public"
        }
    ]
    return jsonify(data)


@app.route('/api/user-exists', methods = ["POST"])
def userExists():
    data = request.get_json()

    if data and "email" in data:
        email = data['email']

    if email and email == 'john@doe.com':
        return jsonify({"name": "John Doe", 'email': email, 'id': '1234'})
    
    
    return jsonify({})


@app.route('/api/new-broadcast-list', methods = ["POST"])
def createNewBroadcastList():
    data = request.get_json()
    lists = ['Family', 'School Friends','Work Friends','Marketing Team']

    if data and "listName" in data and data['listName'] in lists:
        return jsonify({"success": False, "message": "You already have a list with this name"})
    
    
    return jsonify({"success": True})



if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8000, debug=True)

