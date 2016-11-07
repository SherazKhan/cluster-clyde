import os
import requests

def get_ip():
    '''
    Helper function get to current external IP Address
    :return: external IP address in string format
    '''
    ip = requests.get('http://whatismyip.org')
    if ip.ok:
        return ip.content.split('<span')[1].split('>')[1].split('<')[0]
    return False
