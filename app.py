import sqlite3
import sys
import time
import json #In order to return SQL as json
import decimal #In order to format decimal to be used in json return
from datetime import datetime
from flask import Flask, url_for, render_template, request, g, Blueprint, session, redirect, flash
from werkzeug.security import generate_password_hash, check_password_hash

from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate

from flask_login import (
    UserMixin,
    login_user,
    LoginManager,
    current_user,
    logout_user,
    login_required,
)
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from forms import LoginForm


login_manager = LoginManager()
login_manager.session_protection = "strong"
login_manager.login_view = "login"
login_manager.login_message_category = "info"


prev_packet = None
prev_packet_contents = "Empty"

# Had to make the db connector to a repeatable callable function, as the connection have to be close everytime it gets used 
def dbConnect():
    global conn
    conn = sqlite3.connect('ebarge.db')
    global curs
    curs = conn.cursor()



#Makes flask pointers for static and template folders
app = Flask(__name__,
            static_folder='static',
            template_folder='template')


# Placeholder API functions so ready to revice data from Pi LTE solution
# """Rest full api which takes get_data as arguments"""
# @app.route("/reading_post_data", methods=["POST"])
# def reading_post_data():
#     test = request.get_data().decode("utf-8")
#     print(test)
#     return "OK", 200

# """Rest full api which takes get_json as arguments"""
# @app.route("/reading_post_json", methods=["POST"])
# def reading_post_json():
#     test = request.get_json()
#     print(test)
#     return "OK", 200




# Just makes a new secret key on start, which also invalidates every users session 
# but it's alright for this school project
app.secret_key = str.encode(str(Flask.secret_key))
login_manager.init_app(app)
login_manager.login_view = 'login'
print("Login manager starteed succesfully")

## https://medium.com/analytics-vidhya/how-to-use-flask-login-with-sqlite3-9891b3248324
class User(UserMixin):
    def __init__(self, id, email, password, ):
         self.id = str(id)
         self.email = email
         self.password = password
         self.authenticated = False
    def is_active(self):
         return self.is_active()
    def is_anonymous(self):
         return False
    def is_authenticated(self):
         return self.authenticated
    def is_active(self):
         return True
    def get_id(self):
         return self.id


         
@login_manager.user_loader
def load_user(user_email):
   conn = sqlite3.connect('ebarge.db')
   curs = conn.cursor()
   curs.execute("SELECT * from User where email = (?)",[user_email])
   lu = curs.fetchone()
   print(lu)
   if lu is None:
      return None
   else:
      print(f"{lu[0]},{lu[1]},{lu[2]},{lu[3]},{lu[4]},{lu[5]}")
      return User(int(lu[0]), lu[1], lu[2])
#load_user("lll")



# @login_manager.request_loader
# def request_loader(request):
#     email = request.form.get('email')
#     if email not in load_user(email):
#         return

#     user = User()
#     user.id = email
#     return user

"""Login with flask-login and sqlite3"""
@app.route("/login_post", methods=["GET", "POST"])
def login():
    dbConnect()
    print("Login post")
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        print(email, password)
        if email is None or password is None:
            flash('Please fill out the form.', 'error')
        else:
            print("Trying to get user")
            curs.execute("SELECT * from User where email = (?)",[email])
            lu = curs.fetchone()
            conn.close()
            print(lu)
            if lu is None:
                flash('Invalid username or password.', 'error')
            else:
                if check_password_hash(lu[2], password):
                    user = User(int(lu[0]), lu[1], lu[2])
                    login_user(user)
                    return redirect(url_for("dashboard"))
                else:
                    flash('Invalid username or password.', 'error')
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))



@app.route("/signup_post", methods=['GET','POST'])
def signup():
    dbConnect()
    if request.method == 'POST':

        email = request.form.get('email')
        name = request.form.get('name')
        company = request.form.get('company')
        contactNumber = request.form.get('contactNumber')
        password = request.form.get('password')

        sql = """SELECT email FROM User WHERE email = :email"""
        curs.execute(sql, [email])
        result = curs.fetchone()
        if result:
            #Email already registered
            print("User email already in DB")
            flash('Email already registered')
        else:
            print("Trying to save user to DB")
            sql = """INSERT INTO User (email, name, company, contactNumber, passwordHash) values(:email, :name, :company, :contactNumber, :password)"""
            print("User saved")
            # sql = """INSERT INTO Readings(temp, humid, containerID, batteryVolt, loggingDate) values(:temp, :humid, :containerId, :batVolt, :loggingDate)"""
            hashedPassword = generate_password_hash(password)
            curs.execute(sql, [email, name, company, contactNumber, hashedPassword])
            conn.commit()
            conn.close
            redirect(url_for('dashboard'))
            # return render_template('dashboard.html')
        #redirect(url_for('login'))
        return render_template('login.html',title='Login')
       
    

      



#Converts any decimals to float so it can then be formated to JSON which can then be sent to website
def dec_serializer(sqlData):
    if isinstance(sqlData, decimal.Decimal):
        return float(sqlData)

########################
##### Db handling ######
########################

# Adds a dht22 reading
# Parsing the input to avoid SQL injection, which is not crazy important in this project, but better to just always use it 
@app.route('/_addReadings', methods=['POST'])
def addReadings(temp, humid, containerId, batVolt, loggingDate):
    dbConnect()
    sql = """INSERT INTO Readings(temp, humid, containerID, batteryVolt, loggingDate) values(:temp, :humid, :containerId, :batVolt, :loggingDate)"""
    try:
        curs.execute(sql, [temp, humid, containerId, batVolt, loggingDate])
        conn.commit()
        conn.close()
        print("Readings Added")
    except Exception as e:
        print("Error : " + str(e))
    return "Reading added"


# Adds a container with the adminID which later binds to readings
@app.route('/_addContainer', methods=['POST'])
def addContainer(adminID):
    dbConnect()
    sql = """INSERT INTO Container(loadingDate) values(:dateTime, :adminID)"""
    try:
        dateTime = datetime.now()
        curs.execute(sql, [dateTime, adminID])
        conn.commit()
        conn.close()
        print("Container Added")
    except Exception as e:
        print("Error : " + str(e))
    return "Container added"

# return all readings
@app.route('/_getAllReadings', methods=['GET','POST'])
def getAllReadings():
    dbConnect()
    sql = """SELECT * FROM Readings;"""
    curs.execute(sql)
    data = curs.fetchall()
    for rowData in data:
        print(rowData)  
    conn.close()
    return json.dumps(data, default=dec_serializer)

# return inner join, gets all data belonging to specific container
@app.route('/_getContainerReadings', methods=['GET','POST'])
def getContainerReadings(containerId):
    dbConnect()
    sql = """SELECT * FROM Readings INNER JOIN Container ON :containerId = Container.ID"""
    curs.execute(sql, [containerId])
    data = curs.fetchall()
    print("Total number of rows in table: " + str(curs.rowcount))
    
    conn.close()
    #Calls the dec_serializer function which converts any decimals to float, which then comes back to be formated to JSON
    return json.dumps(data, default=dec_serializer)

#Gets the last reading entry for Pie charts 
@app.route('/_getLastContainerReadings', methods=['GET','POST'])
def getLastContainerReadings(containerId):
    dbConnect()
    sql = """SELECT * FROM Readings INNER JOIN Container ON :containerId = Container.ID ORDER BY ID DESC LIMIT 1"""
    curs.execute(sql, [containerId])
    data = curs.fetchall()
    print("Total number of rows in table: " + str(curs.rowcount))   
    conn.close()
    #Calls the dec_serializer function which converts any decimals to float, which then comes back to be formated to JSON
    #return json.dumps(data, default=dec_serializer)
    #For prototype only showing stats on 1 piechart
    return str(data)




# Deletes specifc container with ID
@app.route('/_deleteContainer', methods=['POST'])
def deleteContainer(containerId):
    dbConnect()
    sql = """DELETE FROM Container WHERE Container.ID = :containerId"""
    curs.execute(sql, [containerId])
    conn.commit()
    conn.close()
    return "Container deleted"

# Deletes specifc container with ID, and all readings of it
@app.route('/_deleteContainerAndReadings', methods=['POST'])
def deleteContainerAndReadings(containerId):
    dbConnect()
    sql = """DELETE FROM Readings WHERE Readings.containerId = :containerId"""
    curs.execute(sql, [containerId])
    sql2 = """DELETE FROM Container WHERE Container.ID = :containerId"""
    curs.execute(sql2, [containerId])
    conn.commit()
    conn.close()
    return "Container readings deleted"

@app.route('/_editAlarmSettings', methods=['POST'])
def editAlarmSettings():
    if request.method == "POST":
        dbConnect()
        req = request.form
        print(req)
        tempMax = req["tempRange"]
        humMax = req["humidRange"]
        repeatAlarm = "Empty"
        #Check box can be seen as either True or False depending on if its checked
        if req.getlist('alarmRepeating') :
            repeatAlarm = "True"
        else:
            repeatAlarm = "False"
        sql = """UPDATE alarmSetting SET tempMax = :tempMax, humMax = :humMax, repeatAlarm = :repeatAlarm WHERE ID = 1"""
        # ### sql = """ALTER TABLE alarmSetting (tempMax, humMax, repeatAlarm) VALUES(:tempMax, :humMax, :repeatAlarm)"""
        curs.execute(sql,[int(tempMax), int(humMax), repeatAlarm])
        conn.commit()
        conn.close()

        return '', 204



# Need to set the prev_packet_contents to global outside the Scheduler function
# def setGlobalVar():
#     global prev_packet_contents
#     prev_packet_contents = "Empty"
# setGlobalVar()

# LoRa function, which gets pushed on another thread, pause had to be applied to avoid cooking the CPU
# def loraController():
#     global prev_packet_contents
#     packet = None
#     # check for packet rx
#     packet = rfm9x.receive()
#     #print("Lora controller running")
#     if packet is not None:
#         prev_packet = packet
#         try:
#             packet_text = str(prev_packet, "utf-8")            
#             # Ignores the package if it's the same transmited package to avoid db dublication
#             print("Previous packet" + str(prev_packet_contents))
#             if packet_text != prev_packet_contents:
#                 # Splits up the incoming package on " , " which can then be used as list/array
#                 data = packet_text.split(",") 
#                 # prints out "Readings added" if succesfull 
#                 print("Adding readings to DB")
#                 print(data[0], data[1], data[2], data[3], datetime.now())
#                 addReadings(data[0], data[1], data[2], data[3], datetime.now())
#                 prev_packet_contents = packet_text
#         except Exception as e:
#             print("Error: " + str(e))
#         #print(packet_text)

### For testing ###
# getAllReadings()
# addContainer()
#addContainer()
# addReadings(22, 22, 1)
# addReadings(22, 23, 1)
# addReadings(24, 25, 1)
#addReadings(28, 30, 2)
#print(getAllReadings())
#print(getContainerReadings(2))
#print(getLastContainerReadings(2))
#deleteContainerAndReadings(1)
# conn.close()




# scheduler = BackgroundScheduler()
# #Removing all jobs in case they did not close down properly,¨
# # we dont need to have it running while the flask app is not up, also trying to close it on program exit at end
# scheduler.remove_all_jobs()
# scheduler.add_job(func=loraController, trigger="interval", seconds=5)
# scheduler.start()

# jsonGetLastReading = (json.loads(getLastContainerReadings(2)))
# print(jsonGetLastReading[0])
# print(jsonGetLastReading[1])
# print(jsonGetLastReading[2])
# print(jsonGetLastReading[3])


#### Login logic #####
# @app.route('/signup_post', methods=['POST'])
# def signup_post():
#     # code to validate and add user to database goes here
#     email = request.form.get('email')
#     password = request.form.get('password')

#     # user = User.query.filter_by(email=email).first() # if this returns a user, then the email already exists in database

#     if user: # if a user is found, we want to redirect back to signup page so user can try again
#         return redirect(url_for('auth.signup'))

#     # create a new user with the form data. Hash the password so the plaintext version isn't saved.
#     # new_user = User(email=email, password=generate_password_hash(password, method='sha256'))

#     # add the new user to the database
#     # db.session.add(new_user)
#     # db.session.commit()

#     return redirect(url_for('auth.login'))

# @app.route('/login_post', methods=['POST'])
# def login_post():
#     # login code goes here
#     email = request.form.get('email')
#     password = request.form.get('password')
#     remember = True if request.form.get('remember') else False

#     user = User.query.filter_by(email=email).first()

#     # check if the user actually exists
#     # take the user-supplied password, hash it, and compare it to the hashed password in the database
#     if not user or not check_password_hash(user.password, password):
#         flash('Please check your login details and try again.')
#         return redirect(url_for('auth.login')) # if the user doesn't exist or password is wrong, reload the page

#     # if the above check passes, then we know the user has the right credentials
#     return redirect(url_for('main.profile'))

# Old dashboard 
# @app.route('/dashboard')
# def dashboard():
#     # jsonGetLastReading = (json.loads(getLastContainerReadings(2)))
#     pieData = getLastContainerReadings(2).split(",") 
#     templateData = {
#         'humid1': pieData[1],
#         'temp1': pieData[2],
#         'batVolt1': pieData[5],
#     }
#     return render_template("dashboard.html", **templateData)

# place holder lists in case data have not been received yet from API
pie1 = [2,20,30,20,5.0]

pie2 = [3,24,26,20,5.2]

# Custom for exam needs to just show newest values as it is not a program exam but more hardware and network
@app.route("/reading_post_data", methods=["POST"])
def reading_post_data():
    incomingData = request.get_data().decode("utf-8")
    data = incomingData.split(",")
    if(data[0] == "2"):
        global pie1
        pie1 = data
        print(pie1)
    if(data[0] == "3"):
        global pie2
        pie2 = data    
        print(pie2)
    print(data)
    
    return "OK", 200


#Make defaul / adreess pointer which refers to index.html as start page
@app.route('/dashboard')
def dashboard():
    # jsonGetLastReading = (json.loads(getLastContainerReadings(2)))
    #pieData = getLastContainerReadings(2).split(",") 
    print(pie1)
    print(pie2)
    templateData = {
        'humid1': pie1[1],
        'temp1': pie1[2],
        'batVolt1': pie1[4],
        'humid2': pie2[1],
        'temp2': pie2[2],
        'batVolt2': pie2[4],

    }
    return render_template("dashboard.html", **templateData)

@app.route('/')
def landing():
    return render_template("login.html")
    

if __name__ == '__main__':
    
    
    #lora = Process(target=loraController)
    #lora.start()
    # Reloader false to avoid the lora while loop to be activated multiple times
    #app.run(debug=True, use_reloader=False)
    
    app.run(debug=True, host="0.0.0.0")

    #lora.join()

    ## Closes down the Lora controller program on exit
    # atexit.register(lambda: scheduler.shutdown(wait=False))

