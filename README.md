# Time Match
#### Video Demo:  <https://youtu.be/bqjzL41mj5g>
#### Description:
Time Match is a web app that allows groups of individuals to easily and quickly find a time where all (or most) of them are available for a certain event (e.g. a gathering, a dinner, a meeting...)

Time Match eliminates the hassle of trying to find a suitable time for everyone using normal messaging apps.

&nbsp; 
## The way it works:
### 1) A user, we'll call him **The Creator**, starts by creating an account than he creates an event. 
    To create the event The Creator will need to enter the event's title, description, location, duration, start date, end date, deadline and privacy. 

    The start date and the end date give us a date range within which the event could take place, thus The Submitters will have to submit their availability for all the days within that date range. 

    The privacy of the event can be either public or private.

    For public events The Submitters will only need the link of the event in order to access it and submit their availability.

    For private events, The Creator will be asked to create a password for the event, so now The Submitters will need both the link and the password of the event in order to access it and submit their availability.
    
    For private events, The Creator can also add the emails of The Submitters to the event's access list, so now The Submitters can directly access the event from there dashboard when they are logged in (no need for the link or the password).

### 2) After creating the event, **The Submitters** will submit their availabilities.
    When submitting the availability there is 2 sections.
    1. The General Availability Section: 
    This is your repeating availability for each day of the week.

    2. The Specific Availability Section: 
    This is a small calendar where you can select a specific date (from the event's date range) and overwrite your general availability. (e.g. if your availability for Saturday 26 October 2024 is different than the general availability you entered for Saturdays, you can overwrite this specific date)

### 3) Finally **The Creator** can go to the event's "Submissions" page and there he will see the best timing options where all or most of the participants are available for the event. 
    Timing options are ranked based on the duration of the option and the number of participants that can attend.

    In submissions page The Creator will also be presented with dynamic calendar that shows the availability of every singly submitter.

    The Creator will also be able to see the names of the invitees (only for private events) that have not submitted yet, and the names of the invitees that declined the invitation.

    The Creator is also able to toggle The Submitters on and off. When this happends both the calendar and the best timing options are updated to only consider The Submitters that are toggled "on". (this option is useful in cases where there are no good timing options so The Creator might have to exclude some participants that have less priority in order to hopefully have a good time match)

&nbsp; 
## Some Additional Features:
    - If the same group of people are creating multiple events together, The Creator can create a broadcast list containing the emails of all The Submitters, now everytime The Creator creates a new event he can select this list and add it to the event's access list without having to reenter the same emails again and again.

    - If a USER finds himself submitting to a lot of events, he can set his regular schedule in "My Availability" page. Now everytime USER wants to sumbit his avaialability the General Availability (section 1) will be pre-filled for him. (This feature save the USER from entering the same availability over and over again)
    


&nbsp; 
## BACKEND:
For the backend I am using Flask and MySQL database.

app.py is the main code for the backend where all the routes are configured.

helpers.py contains helper functions, and a bunch of user data validation functions to make sure that the received data in requests are valid.

I'm also using authlib library to allow users to sign up with their Google Accounts through Google OAuth.



&nbsp; 
## FRONTEND:
For the frontend I'm using HTML, CSS, Bootstrap and Javascript.


All pages require authentication except for login.html, register.html, event-password.html, submit-availability.html, change-availability.html and error.html


I have 2 main layouts for my pages which are layout.html and layout-2.html.
These 2 files contain the head element with all the css and js links, and the header element with the navbar of the pages.

&nbsp; 
### **index.html** 
This is the main dashboard for the users where they can see:
1) Ongoing events they created (under "My Events" tab)
2) Ongoing events they are invited to (under "Invitations" tab)
3) Events that have passed (under "Past Events" tab)

Everytime the user clicks on one of the 3 tabs, the events are fetched from the server using the fetch api and then dynamically rendered for the user. 

On this page users have a "Create New Event" button that allows them to create a new event

Actions: 

1) For the events that the user created
    - view the details card of this event (fetches event info then renders a modal)
    - edit the details of this event (goes to "Settings" page)
    - share event (copies the link of the event)
    - change avaialability (goes to the "Change Availability" page)
    - delete the event (opens a modal with a confirmation input then sends a delete request)

2) For the events that the user is invited to
    - view the details card of this event (fetches event info then renders a modal)
    - decline invitation (opens a modal with a confirmation input then sends a decline request)
    - accept invitations (goes to "Accept Invitation" page)
    - (Once accepted) change availability for (goes to "Change Invitation" page)

3) For past events
    - view the details card of this event (fetches event info then renders a modal)
    

Notes:

- For events created by the user, the event will move under the "Past Events" tab once the end date has passed
- For events that the user is invited to, the event will move under the "Past Events" tab once the deadline has passed
- Once the dealine has passed no user will be able to submit/change his availability for the event.
- The event details card includes the event's title, description, location, creator, duration, start date, end date, deadline and privacy.
- If a user submits his availability to a public event (no invitation neede), that event will appear under the "Invitations" tab.


&nbsp; 
### **my-availability.html**

This page is where the user can set his regular and repetitive schedule.  <br>
When the user wants to submit his avaialability to any event, the "General Availability" section will be pre-filled with the schedule set in this page.


&nbsp; 
### **broadcast-lists.html**

In this page the user can see all the lists he has created and edit them.
He can also create new lists.  <br>
To create one the user enters the name of the list and the emails of all the people he wants to add to this list.  <br>
Now every time the user creates a private event, he can select these broadcast lists and add them to the event's access list.


&nbsp; 
### **create-event.html**

In this page the user can create a new event by entering the following info:  <br>
Event Details: 
- title 
- location 
- description 
- duration 
- start date 
- end date 
- deadline

Sharing Details:
- privacy (public or private)
- password (for private events)
- individual emails (access list) (for private events) 
- broadcast lists (access list) (for private events) 


&nbsp; 
### **settings.html**
In this page the user can edit the following event settings:  <br>
Event Details:
- title
- location
- description
- deadline  

Sharing Details:
- privacy (public or private)
- password (for private events)
- individual emails (access list) (for private events) 
- broadcast lists (access list) (for private events) 


&nbsp; 
### **submit-availability.html**
In this page people can submit their availability (or accept invitations)  <br>
It is formed of 2 sections **General Availability** and **Specific Availability**


&nbsp; 
**General Availability** is the repetitive weekly schedule and it is pre-filled with the user's schedule (specified in "my-availability.html" page)


&nbsp; 
**Specific Availability** is a small calendar where the user can overwrite his/her general weekly availability for a specific date within the event's date range

Users are only allowed to submit once.
When a user that is not logged in submits to an event, that event's id is saved in his session, so next time he tries to access this page he will be redirected to "change-availability.html"


&nbsp; 
### **change-availability.html**
It is the same page as submit-availability but in this page both sections are pre-filled with the availability that the user has already submitted.

If a user hasn't already submitted his availability he will be redirected to "submit-availability.html"


&nbsp; 
### **event-password.html**
Who this page shows up for:
- Logged in users trying to access a private event they are not invited to. ("only password field is displayed and required")
- People that are not logged in tring to access a public event ("only fullname field is displayed and required")
- People thar are not logged in tring to access a private event ("both the password field and fullname field are displayed and required")

Once the user submits the required fields (and the password if required is correct), the user will be redirected to the "submit-availability.html" <br>
Once a user that is not logged in enters his fullname, his name will be saved in the sessions and he will not be asked for it again when trying to submit to other events.


&nbsp; 
### **submissions.html**
In this page the user that created an event will see:
- The best timing options for the event
- A calendar showing everyone's submitted availabitlity
- Invitees that haven't submitted yet (for private events)
- Invitees that declined the invitation (for private events)

the user is also able to toggle individual submitters on and off. When this happends both the calendar and the best timing options are updated to only consider the submitters that are toggled "on". <br>
This option is useful in cases such as:
- when there are no good timing options so **The Creator** might have to exclude some participants that have less priority in order to hopefully have a good time match
- when someone that wasn't supposed to access the event have submitted their availability thus messed up the best timing options (this happens if the user accidentally shares the event's link and/or password with the wrong people)


&nbsp; 
### **register.html**
This is where the users can register either by using their Google Account or by entering their fullname, email and  password


&nbsp; 
### **login.html**
This is where the users can login either by using their Google Account or by entering their account's email and password


&nbsp; 
### **error.html**
This is a custom error page made for better user experience



&nbsp; 
## The Algorithm for finding the best timing options
Pseudocode:
```
split the 24 hours of the day into 15min slots and put them in an array
For each day of the date range :
    create an array that contains a dictionnary for every slot of the day
    each dictionnary will contain "full attandance", "coming late" and "leaving early" keys which correspond to arrays that will contain the ids of the participants that can fully attand, come late or leave early respectively if the event were to start on that slot.
    The dictionnary also has the date of the day we're currently looping

    for each submitter :
        if the availability for this date is specified use it
        else use the general availability for that day of the week

        turn this availability into an array of 0s and 1s 
        (0 for a slot where unavailable, 1 for a slot where available)

        loop this binary availability array one chunk at a time 
        (each chunk is the number of 15mins slots in the duration of the event)

            if the chunk is all 1s:
                find the dictionnary that corresponds to the first slot of the chunk and push the submitter's id to "full attandance"
            
            else if the chunk begins with 0 and the rest is 1s:
                find the dictionnary that corresponds to the first slot of the chunk and push the submitter's id to "coming late"

            else if the chunk ends with 0 and the rest is 1s:
                find the dictionnary that corresponds to the first slot of the chunk and push the submitter's id to "leaving early"
        

    Now that we have the number of people that can fully attand and partially attand at every possible starting time, let's calculate the score for each starting time.

    for each time slot of the day:
        take the dictionnary that corresponds to this slot

        score = 0

        add 0 if noone can fully attend
        add 1.25 if only 1 can fully attend
        add 2 for every person that can attand if more than 1

        take the bigger number between the number of people that are coming late and the number of people that are leaving early 
        then multiply it by 1 and add it to the score

        now take the smaller number multiply it by 0.25 and add it to the score
    
        save the score of the slot in the dictionnary of that slot

    
    filter the array of dictionnaries from any slots that have a score equal or below 1.25
    move the dictionnaries to the array that contains the dictionnaries for all the dates


sort all the dictionnaries from highest score to lowest score

merge dictionnaries that are identical in score, date, full attandees, coming late attendees and leaving early attandees, then add the merged dictionnary to the top 10 options array

stop merging once top 10 options array has 10 dictionnaries
```
    


