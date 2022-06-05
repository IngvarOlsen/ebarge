
import time
# Import RFM9x
import adafruit_rfm9x
# Configure LoRa Radio
# Import Blinka Libraries
import busio
from digitalio import DigitalInOut, Direction, Pull
import board
CS = DigitalInOut(board.CE1)
RESET = DigitalInOut(board.D25)
spi = busio.SPI(board.SCK, MOSI=board.MOSI, MISO=board.MISO)
rfm9x = adafruit_rfm9x.RFM9x(spi, CS, RESET, 869.0)
prev_packet = None
while True:
    packet = None
    # check for packet rx
    packet = rfm9x.receive()
    if packet is not None:
        prev_packet = packet
        try:
            packet_text = str(prev_packet, "utf-8")
        except Exception as e:
            print("Error: " + e)
        print(packet_text)
