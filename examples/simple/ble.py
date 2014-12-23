'''
Created on Nov 2, 2014

@author: karulis
'''
import bluetooth

if __name__ == '__main__':
    bles = bluetooth.discover_ble_devices()
    for item in bles:
        print(item)
