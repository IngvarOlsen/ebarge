import sqlite3
import sys
import time
import json #In order to return SQL as json
import decimal #In order to format decimal to be used in json return
from datetime import datetime
from flask import Flask, url_for, render_template, request, g
# For mutlithreading
#from multiprocessing import Process, Value

from apscheduler.schedulers.background import BackgroundScheduler
# Flask version
#from flask_apscheduler import APScheduler
#To exit/end the lora scheduler on app exit
import atexit

## LORA imports, adafruit_rfm9x, busio and digitalio needs to be installed first 
# Import RFM9x
import adafruit_rfm9x
# Configure LoRa Radio
# Import Blinka Libraries
import busio
from digitalio import DigitalInOut, Direction, Pull
import board

## LoRa variables
CS = DigitalInOut(board.CE1)
RESET = DigitalInOut(board.D25)
spi = busio.SPI(board.SCK, MOSI=board.MOSI, MISO=board.MISO)
rfm9x = adafruit_rfm9x.RFM9x(spi, CS, RESET, 869.0)
prev_packet = None

prev_packet_contents = "Empty"


#Makes flask pointers for static and template folders
app = Flask(__name__,
            static_folder='static',
            template_folder='template')

#Converts any decimals to float so it can then be formated to JSON which can then be sent to website
def dec_serializer(sqlData):
    if isinstance(sqlData, decimal.Decimal):
        return float(sqlData)

########################
##### Db handling ######
########################

# Had to make the db connector to a repeatable callable function, as the connection have to be close everytime it gets used 
def dbConnect():
    global conn
    conn = sqlite3.connect('wegrain.db')
    global curs
    curs = conn.cursor()

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

# Adds a container
@app.route('/_addContainer', methods=['POST'])
def addContainer():
    dbConnect()
    sql = """INSERT INTO Container(loadingDate) values(:dateTime)"""
    dateTime = datetime.now()
    curs.execute(sql,[dateTime])
    conn.commit()
    conn.close()
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
    for rowData in data:
        print(rowData)  
        print("[0] :" + str(rowData[0]))
        print("[1] :" + str(rowData[1]))
        print("[2] :" + str(rowData[2]))
        print("[3] :" + str(rowData[3]))
        print("[4] :" + str(rowData[4]))
        print("[5] :" + str(rowData[5]))     
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
def loraController():
    global prev_packet_contents
    packet = None
    # check for packet rx
    packet = rfm9x.receive()
    #print("Lora controller running")
    if packet is not None:
        prev_packet = packet
        try:
            packet_text = str(prev_packet, "utf-8")            
            # Ignores the package if it's the same transmited package to avoid db dublication
            print("Previous packet" + str(prev_packet_contents))
            if packet_text != prev_packet_contents:
                # Splits up the incoming package on " , " which can then be used as list/array
                data = packet_text.split(",") 
                # prints out "Readings added" if succesfull 
                print("Adding readings to DB")
                print(data[0], data[1], data[2], data[3], datetime.now())
                addReadings(data[0], data[1], data[2], data[3], datetime.now())
                prev_packet_contents = packet_text
        except Exception as e:
            print("Error: " + str(e))
        #print(packet_text)

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




scheduler = BackgroundScheduler()
#Removing all jobs in case they did not close down properly,¨
# we dont need to have it running while the flask app is not up, also trying to close it on program exit at end
scheduler.remove_all_jobs()
scheduler.add_job(func=loraController, trigger="interval", seconds=5)
scheduler.start()

# jsonGetLastReading = (json.loads(getLastContainerReadings(2)))
# print(jsonGetLastReading[0])
# print(jsonGetLastReading[1])
# print(jsonGetLastReading[2])
# print(jsonGetLastReading[3])



#Make defaul / adreess pointer which refers to index.html as start page
@app.route('/')
def index():
    # jsonGetLastReading = (json.loads(getLastContainerReadings(2)))
    pieData = getLastContainerReadings(2).split(",") 
    templateData = {
        'humid': pieData[1],
        'temp': pieData[2],
        'batVolt': pieData[5]
    }
    return render_template("index.html", **templateData)
    

if __name__ == '__main__':
    
    
    #lora = Process(target=loraController)
    #lora.start()
    # Reloader false to avoid the lora while loop to be activated multiple times
    #app.run(debug=True, use_reloader=False)
    app.run(debug=True, host="0.0.0.0")
    #lora.join()

    ## Closes down the Lora controller program on exit
    atexit.register(lambda: scheduler.shutdown(wait=False))

