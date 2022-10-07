import socket
import requests


def getIP(hostname):
    host_ip = socket.gethostbyname(hostname)
    return host_ip              


def scanWebHeader(domain):
    #"https://www.hackthissite.org"
    headers = requests.get(domain).headers
    print(requests.get(domain))
    print(headers)
    for key in headers:
        print(key)
    # X-Frame-Options Referrer-Policy Content-Security-Policy Permissions-Policy X-Content-Type-Options Strict-Transport-Security X-XSS-Protection
    headerHas = []
    headerHasNot = []

    if 'X-Frame-Options' in headers:
        headerHas.append('X-Frame-Options')
    else:
        headerHasNot.append('X-Frame-Options')

    if 'Referrer-Policy' in headers:
        headerHas.append('Referrer-Policy')
    else:
        headerHasNot.append('Referrer-Policy')

    if 'Content-Security-Policy' in headers:
        headerHas.append('Content-Security-Policy')
    else:
        headerHasNot.append('Content-Security-Policy')

    if 'Permissions-Policy' in headers:
        headerHas.append('Permissions-Policy')
    else:
        headerHasNot.append('Permissions-Policy')

    if 'X-Content-Type-Options' in headers:
        headerHas.append('X-Content-Type-Options')
    else:
        headerHasNot.append('X-Content-Type-Options')
    
    if 'X-XSS-Protection' in headers:
        headerHas.append('X-XSS-Protection')
    else:
        headerHasNot.append('X-XSS-Protection')
    
    
    context = {
        "header":headers,
        "headerHas" : headerHas,
        "headerHasNot": headerHasNot
    }
    return context
