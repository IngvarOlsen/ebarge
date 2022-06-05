from time import sleep
from ulora import LoRa, ModemConfig, SPIConfig
import dht
import machine
from machine import ADC, Pin


# based on https://github.com/martynwheeler/u-lora

# PINOUT 
# RFM9X <--> ESP32 WROOM-32D
# VIN <--> 3v3
# GND <--> GND
# G0 <--> GPIO 0 (CAN BLOCK FROM FILESYSTEM ESP32 WHILE INSERTED)
# SCK <--> GPIO 14
# MISO <--> GPIO 12
# MOSI <--> GPIO 13
# CS <--> GPIO 5
# Lora Parameters

sensor = dht.DHT22(Pin(16))

RFM95_RST = 27
RFM95_SPIBUS = SPIConfig.esp32_1
RFM95_CS = 5
RFM95_INT = 0
RF95_FREQ = 869.0
RF95_POW = 20
CLIENT_ADDRESS = 1
SERVER_ADDRESS = 222

# initialise radio
lora = LoRa(RFM95_SPIBUS, RFM95_INT, CLIENT_ADDRESS, RFM95_CS, reset_pin=RFM95_RST, freq=RF95_FREQ, tx_power=RF95_POW, acks=True)

#ContainerId needs to be hard set
containerId = 2

# create function for returning current battery voltage
def get_battery_voltage():
    batread = ADC(Pin(32))
    batread_value = batread.read()
    batmult = 6.3 / 4096 # Battery voltage at 100% SoC / by ADC resolution
    batread_Volt = round(batread_value * batmult, 2)
    # print(batread_Volt) only used for testing
    return batread_Volt
# get_battery_voltage() only used for testing


# test of deepsleep
while False:
    print("Going to sleep byebye")
    machine.deepsleep(1000000)
    
# loop and send data
while True:
    #Temp, hum, containerID
    sensor.measure()
    dataToSend = str(sensor.temperature()) + " , " + str(sensor.humidity()) + " , " + str(containerId) + " , " + str(get_battery_voltage())
    for i in range(5): # sends 5 readings for reliability
        print(dataToSend)
        lora.send_to_wait(dataToSend, SERVER_ADDRESS)
        # print("sent")
        sleep(1)
    sleep(5)
    print("Going to deepsleep for 10 seconds.")
    machine.deepsleep(10000)     #10000ms sleep time
