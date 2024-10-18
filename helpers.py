from flask import redirect, session
from functools import wraps

from datetime import datetime
import hashlib
import re
import pymysql
import os


def db_select(query, tuple=()):
    timeout = 10
    connection = pymysql.connect(
        charset="utf8mb4",
        connect_timeout=timeout,
        cursorclass=pymysql.cursors.DictCursor,
        db=os.getenv('DB_NAME'),
        host=os.getenv('DB_HOST'),
        password=os.getenv('DB_PASSWORD'),
        read_timeout=timeout,
        port=int(os.getenv('DB_PORT')),
        user=os.getenv('DB_USER'),
        write_timeout=timeout,
    )

    try: 
        cursor = connection.cursor()

        if len(tuple):
            cursor.execute(query, tuple)
        else:
            cursor.execute(query)

        return cursor.fetchall()

    finally:
        connection.close()





def login_required(f):
    
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None or session.get('user_id') == []:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function



## Utility functions
def dateHasPassed(date_str):
        # Parse the input date string into a datetime object
        input_date = datetime.strptime(date_str, '%Y-%m-%d')
        
        # Get today's date (only date part, ignoring time)
        today = datetime.today().date()

        # Compare input date to today
        if input_date.date() >= today:
            return 0  # Today or future
        else:
            return 1  # Past
 

def is_valid_email(email):
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(regex, email))



## create new event
def generate_unique_event_id(event_id):
    # Create a unique string using the current time and event ID
    unique_string = str(datetime.now()) + str(event_id)
    
    # Create a hash using sha256 from the unique string
    event_id_hash = hashlib.sha256(unique_string.encode()).hexdigest()
    
    # Truncate the hash to a suitable length (e.g., 16 characters)
    truncated_hash = event_id_hash[:16]
    
    # Concatenate the event ID at the end
    final_event_id = truncated_hash + "o" + str(event_id)
    
    return final_event_id
        

def validateNewEventInfo(info):

    user_id = session.get('user_id')
    if user_id is None:
        return {"success": False, "message": "User unauthorized", "status": 401}
    
    # Make sure event title is provided
    if not info['title']: 
        return {"success": False, "message": "Event title is missing", "status": 400}
    
    # Make sure event description is provided
    if not info['description']:  
        return {"success": False, "message": "Event description is missing", "status": 400}
    
    # Make sure event location is provided
    if not info['location']:  
        return {"success": False, "message": "Event location is missing", "status": 400}
    
    # Make sure deadline is provided
    if not info['deadline']:  
        return {"success": False, "message": "Submission deadline is missing", "status": 400}
    elif dateHasPassed(info['deadline']): 
        return {"success": False, "message":'Submission deadline cannot be in the past', "status": 400}
    
    # Make sure event start date is provided
    if not info['start_date']:  
        return {"success": False, "message": "Event start date is missing", "status": 400}
    elif dateHasPassed(info['start_date']): 
        return {"success": False, "message":'Event start date cannot be in the past', "status": 400}
    
    # Make sure event end date is provided
    if not info['end_date']:  
        return {"success": False, "message": "Event end date is missing", "status": 400}
    elif dateHasPassed(info['end_date']): 
        return {"success": False, "message":'Event end date cannot be in the past', "status": 400}
    
    # Make sure duration is provided
    if not info['duration']['hours'] and not info['duration']['mins']:
        return {"success": False, "message":'Event duration must be more than 0', "status": 400}


    startDate = datetime.strptime(info['start_date'], '%Y-%m-%d')
    endDate = datetime.strptime(info['end_date'], '%Y-%m-%d')
    deadlineDate = datetime.strptime(info['deadline'], '%Y-%m-%d')

    # Make sure end date is after or equal to start date
    if endDate.date() < startDate.date():
        return {"success": False, "message":'The end date must be on or after the start date.', "status": 400}

    # Make sure end date is after or equal to deadline
    if endDate.date() < deadlineDate.date():
        return {"success": False, "message":'The deadline date must be on or before the end date.', "status": 400}



    ## PRIVACY
    if not info['privacy'] or not info['privacy'] in ['public', 'private']:
        return {"success": False, "message":'Privacy type must be selected.', "status": 400}

    if info['privacy'] == 'private':
        # Validate password
        if not info['password'] or len(info['password']) != 8:
            return {"success": False, "message":'A valid password must be provided.', "status": 400}
        
        password = info['password'].upper()
        valid_value = re.sub(r'[^A-Z0-9]', '', password)
        
        if not password == valid_value:
            return {"success": False, "message":'A valid password must be provided.', "status": 400}
        
        # Validate users
        if info['added_users']:
            for user in info['added_users']:
                if user['id'] == user_id:
                    return {"success": False, "message":"Can't add yourself to the list.", "status": 400}
                    
                found = db_select('SELECT * FROM users WHERE id = %s AND email = %s', (user['id'], user['email'].lower()))
                if len(found) <= 0 :
                    return {"success": False, "message":"One of the users in the list was not found.", "status": 404}
                
        # Validate broadcast lists
        if info['added_lists']:
            for list in info['added_lists']:
                found = db_select('SELECT * FROM broadcast_lists WHERE id = %s AND creator_id = %s', (list, user_id))
                if len(found) <= 0:
                    return {"success": False, "message":"One of the broadcast lists was not found.", "status": 404}
                
    return {"success": True}



## update event info
def validateUpdateEventInfo(info, event):

    user_id = session.get('user_id')
    if user_id is None:
        return {"success": False, "message": "User unauthorized", "status": 401}
    
    # Make sure event title is provided
    if not info['title']: 
        return {"success": False, "message": "Event title is missing", "status": 400}
    
    # Make sure event description is provided
    if not info['description']:  
        return {"success": False, "message": "Event description is missing", "status": 400}
    
    # Make sure event location is provided
    if not info['location']:  
        return {"success": False, "message": "Event location is missing", "status": 400}
    
    # Make sure deadline is provided
    if not info['deadline']:  
        return {"success": False, "message": "Submission deadline is missing", "status": 400}
    elif dateHasPassed(info['deadline']): 
        return {"success": False, "message":'Submission deadline cannot be in the past.', "status": 400}


    # Make sure end date is after or equal to deadline
    endDate = datetime.strptime(event['end_date'], '%Y-%m-%d')
    deadlineDate = datetime.strptime(info['deadline'], '%Y-%m-%d')
    if endDate.date() < deadlineDate.date():
        return {"success": False, "message":'The deadline date must be on or before the end date.', "status": 400}



    ## PRIVACY
    if not info['privacy'] or not info['privacy'] in ['public', 'private']:
        return {"success": False, "message":'Privacy type must be selected.', "status": 400}

    if info['privacy'] == 'private':
        # Validate password
        if not info['password'] or len(info['password']) != 8:
            return {"success": False, "message":'A valid password must be provided.', "status": 400}
        
        password = info['password'].upper()
        valid_value = re.sub(r'[^A-Z0-9]', '', password)
        
        if not password == valid_value:
            return {"success": False, "message":'A valid password must be provided.', "status": 400}
        
        # Validate users
        if info['added_users']:
            for user in info['added_users']:
                if user['id'] == user_id:
                    return {"success": False, "message":"Can't add yourself to the list.", "status": 400}
                    
                found = db_select('SELECT * FROM users WHERE id = %s AND email = %s', (user['id'], user['email'].lower()))
                if len(found) <= 0 :
                    return {"success": False, "message":"One of the users in the list was not found.", "status": 404}
                
        # Validate broadcast lists
        if info['added_lists']:
            for list in info['added_lists']:
                found = db_select('SELECT * FROM broadcast_lists WHERE id = %s AND creator_id = %s', (list, user_id))
                if len(found) <= 0:
                    return {"success": False, "message":"One of the broadcast lists was not found.", "status": 404}
                
    return {"success": True}




## Availability
def stripIndexesFromIntervals(availability):
    for day in availability[0]:
        for interval in range(len(availability[0][day])):
            availability[0][day][interval] = availability[0][day][interval][1:]

    if len(availability) > 1:
        for i in range(len(availability) - 1):
            for interval in range(len(availability[i+1]['intervals'])):
                availability[i+1]['intervals'][interval] = availability[i+1]['intervals'][interval][1:]

    return availability

def isValidAvailability(availability) :
    for day in availability:
        day_intervals = availability[day]
        day_intervals = format_intervals(day_intervals)

        for interval in day_intervals:
            if len(interval) == 4 :
                return False
            
    return True


def isValidFullAvailability(availability):
    if not isValidAvailability(availability[0]):
        return False
    
    if len(availability) > 1 :
        for i in range(len(availability) - 1):
            day_intervals = availability[i + 1]['intervals']
            day_intervals = format_intervals(day_intervals)

            for interval in day_intervals:
                if len(interval) == 4 :
                    return False
    
    return True

       

def format_intervals(intervals) :
    # remove previous error codes
    for i in range(len(intervals)):
        interval = intervals[i]

        if len(intervals[i]) == 4 : interval.pop()
        
        if not is_valid_interval(interval[1:]) : interval.append(1)


    invalidIntervals = [interval for interval in intervals if len(interval) == 4]
    validIntervals = [interval for interval in intervals if len(interval) == 3]


    # check overlaps (error code 0)
    validIntervals = detect_overlapping_intervals(validIntervals)
    

    intervals = validIntervals + invalidIntervals
    invalidIntervals = [interval for interval in intervals if len(interval) == 4]


    # if all correct sort by time
    if len(invalidIntervals) == 0 :
        intervals = sort_intervals(intervals)
    
    # else sort by id
    else :
        intervals = sort_intervals_by_id(intervals)
    

    return intervals


# helpers
def time_to_minutes(time):
    hours, minutes = map(int, time.split(':'))
    return hours * 60 + minutes
 
def sort_intervals(intervals):
    intervals.sort(key=lambda interval: time_to_minutes(interval[1]))
    return intervals

def sort_intervals_by_id(intervals):
    return sorted(intervals, key=lambda interval: interval[0])

def is_valid_interval(interval):
    start, end = interval
    start = time_to_minutes(start)
    end = time_to_minutes(end)
    return not (end <= start and start != 0 and end != 0)

def is_overlapping(start_a, end_a, start_b, end_b):
    if end_a == 0 : end_a = 24*60
    if end_b == 0 : end_b = 24*60
            
    return start_a < end_b and start_b < end_a

def detect_overlapping_intervals(intervals):
    # Loop through each interval and compare it with every other interval
    if len(intervals) <= 1:
        return intervals
    
    for i in range(len(intervals)):
        start_a = intervals[i][1]
        end_a = intervals[i][2]
        start_a_minutes = time_to_minutes(start_a)
        end_a_minutes = time_to_minutes(end_a)

        for j in range(i + 1, len(intervals)):
            index_b, start_b, end_b = intervals[j]
            start_b_minutes = time_to_minutes(start_b)
            end_b_minutes = time_to_minutes(end_b)

            # Check if interval A overlaps with interval B
            if is_overlapping(start_a_minutes, end_a_minutes, start_b_minutes, end_b_minutes):
                # Add a 0 to both intervals if they overlap
                if len(intervals[i]) == 3:
                    intervals[i].append(0)
                if len(intervals[j]) == 3:
                    intervals[j].append(0)

    return intervals



## Broadcast Lists
def getListName(list_id, user_id):
    ## get List Name
    list_name = db_select('SELECT broadcast_list_name FROM broadcast_lists WHERE id = %s AND creator_id = %s', (list_id, user_id))

    if len(list_name) <= 0:
        return False
    
    list_name = list_name[0]['broadcast_list_name'] 

    return list_name


def getListContacts(list_id):

    ## get list contacts
    contacts = db_select('''
        SELECT users.id, fullname, email FROM users 
        JOIN broadcast_list_contacts ON users.id = broadcast_list_contacts.contact_id 
        WHERE broadcast_list_contacts.broadcast_list_id = %s
    ''', (list_id,))

    return contacts





    