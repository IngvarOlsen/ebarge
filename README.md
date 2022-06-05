# eBarge
School iot project. We make a battery powered esp32 solution which can record humidity via a DHT22, sends it with LoRa to a battery powered Raspberry Pi Zero which hosts a Flask app. The App has a python and sqlite3 backend, which then gets used on a user interface, which shows pie and line charts of the data.
Right now it's in the prototype stage. The idea of the project was to help farmers in Africa monitor temperature and humidity of their harvested foods to better avoid contamination, excess humidity and overall quality 


## Linux setup

### 1. Run update and upgrade and install git
```
sudo apt update
sudo apt upgrade
sudo apt-get install git
```

### 2. Download files via github
```
git clone https://github.com/IngvarOlsen/weGrain.git
```

### 3. Make virtual enviroment inside the gitfolder, or copy the folders "template", "static" and app.py to your new enviroment
```
pip install virtualenv
mkdir weGrain
cd weGrain
virtualenv venv
venv/bin/activate
```

### 4. Once activated install Flask
```
pip install Flask
```

### 5. Install rest of dependencies 
```
sudo apt install sqlite3
pip install flask_login

```

## Pin Layouts

### Raspberry Pi Zero pin
```
Vin to Raspberry Pi 3.3V
GND to Raspberry Pi Ground
RFM G0 to Raspberry Pi GPIO #5
RFM RST to Raspberry Pi GPIO #25
RFM CLK to Raspberry Pi SCK
RFM MISO to Raspberry Pi MISO
RFM MOSI to Raspberry Pi MOSI
RFM CS to Raspberry Pi CE1
```

### Esp32 Pins
 ```
VIN to Esp32 3v3
GND to Esp32 GND
G0 to Esp32 GPIO 0 (CAN BLOCK FROM FILESYSTEM ESP32 WHILE INSERTED)
SCK to Esp32 GPIO 14
MISO to Esp32 GPIO 12
MOSI to Esp32 GPIO 13
CS to Esp32 GPIO 5
```


