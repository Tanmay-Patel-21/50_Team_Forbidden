from operator import imod
from pprint import pprint
from django.shortcuts import render
import threading
import win32con
import win32service
import socket
import requests
from . import hack
import nmap
from pprint import pprint
#Functions
def getIP(hostname):
    host_ip = socket.gethostbyname(hostname)
    return host_ip              


def scanWebHeader(domain):
    #"https://www.hackthissite.org"
    headers = requests.get(domain).headers
    # print(requests.get(domain))
    # print(headers)
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
        "Header":headers,
        "headerHas" : headerHas,
        "headerHasNot": headerHasNot
    }
    return context
    
# function to scan ports and see which ports are open
openPortsList = [] #open ports array global variable
def scan_port(port,hostname):
    # we will check port of localhost
    host = "localhost"
    host_ip = socket.gethostbyname(host)

    # print("host_ip = {}".format(host_ip))
    status = False

    # create instance of socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # connecting the host ip address and port
    try:
        s.connect((host_ip, port))
        status = True
    except:
        status = False

    if status:
        # print("port {} is open".format(port))
        openPortsList.append(port)
        return port

all_services=[]
def ListServices():
    resume = 0
    accessSCM = win32con.GENERIC_READ
    accessSrv = win32service.SC_MANAGER_ALL_ACCESS
    #Open Service Control Manager
    hscm = win32service.OpenSCManager(None, None, accessSCM)

    #Enumerate Service Control Manager DB
    typeFilter = win32service.SERVICE_WIN32
    stateFilter = win32service.SERVICE_STATE_ALL
    statuses = win32service.EnumServicesStatus(hscm, typeFilter, stateFilter)
    for x in statuses:
        # print(x) 
        all_services.append(x)

#Redirecting views
#Home
def dashboard(request):

    if request.method == "POST":
        header_info = {
        'X-Frame-Options' : "The X-Frame-Options HTTP response header can be used to indicate whether or not a browser should be allowed to render a page in a <frame>, <iframe>, <embed> or <object>. Sites can use this to avoid click-jacking attacks, by ensuring that their content is not embedded into other sites. The added security is provided only if the user accessing the document is using a browser that supports X-Frame-Options.",

        "Referrer-Policy" : "When a user navigates to a site via a hyperlink or a website loads an external resource, browsers inform the destination site of the origin of the requests through the use of the HTTP Referer (sic) header. Although this can be useful for a variety of purposes, it can also place the privacy of users at risk. HTTP Referrer Policy allows sites to have fine-grained control over how and when browsers transmit the HTTP Referer header.",

        'Content-Security-Policy' : 'Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross-Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft, to site defacement, to malware distribution.',

        'Permissions-Policy': 'Permissions Policy, formerly known as Feature Policy, allows the developer to control the browser features available to a page, its iframes, and subresources, by declaring a set of policies for the browser to enforce. These policies are applied to origins provided in a response header origin list.',

        'X-Content-Type-Options' : 'The X-Content-Type-Options response HTTP header is a marker used by the server to indicate that the MIME types advertised in the Content-Type headers should be followed and not be changed. The header allows you to avoid MIME type sniffing by saying that the MIME types are deliberately configured.',

        'X-XSS-Protection': 'The HTTP X-XSS-Protection response header is a feature of Internet Explorer, Chrome and Safari that stops pages from loading when they detect reflected cross-site scripting (XSS) attacks. These protections are largely unnecessary in modern browsers when sites implement a strong Content-Security-Policy that disables the use of inline JavaScript (unsafe-inline).'
                    

    }
     
        openPortsList.clear()
        hostname = request.POST['hostname']
        tranferProtocol = request.POST['tranferProtocol']
        scanType = request.POST['scanType']
        if scanType=="light":
            try:
                host_ip = getIP(hostname) 
                header_details = hack.scanWebHeader(tranferProtocol+"://"+hostname)
                for i in range(0,5000):
                    thread = threading.Thread(target=scan_port, args=(i,hostname))
                    thread.start()
                context = { 
                    "openPort": openPortsList,
                    "tranferProtocol":tranferProtocol,
                    "hostname":hostname,
                    "host_ip": host_ip,
                    "header_details" :header_details['header'],
                    "headerHas" : header_details['headerHas'],
                    "headerHasNot": header_details['headerHasNot'],
                    "headerInfo":header_info,
                    "scanType":scanType
                }

                return render(request,"./index.html",context)
            except Exception as err:
                print(err)
        elif scanType=="extensive":
            #Extensive scan code here 
            nm=nmap.PortScanner()
            extensiveScan=nm.scan(hosts=hostname,arguments='-A')
            header_details = hack.scanWebHeader(tranferProtocol+"://"+hostname)

            # print(type(extensiveScan['scan']))
            # pprint(list(extensiveScan['scan'].items()))
            extensiveScanList = list(extensiveScan['scan'].items())
            print(extensiveScanList)
            host_ip = list(extensiveScan['scan'].items())[0][1]['addresses']['ipv4']
            hostnames = list(extensiveScan['scan'].items())[0][1]['hostnames']
            portused = list(extensiveScan['scan'].items())[0][1]['portused']
            sslDetails = list(extensiveScan['scan'].items())[0][1]['tcp'][443]['script']['ssl-cert']

            # pprint(list(extensiveScan['scan'].items())[0][1]['hostnames'])
            # pprint(list(extensiveScan['scan'].items())[0][1]['portused'])
            # pprint(list(extensiveScan['scan'].items())[0][1]['tcp'])
            # # pprint(list(extensiveScan['scan'].items())[0][1]['tcp'][443])
            # pprint(list(extensiveScan['scan'].items())[0][1]['tcp'][443]['script']['ssl-cert'])

            context ={
                "scanType":"notScanned",
                "extensiveScan":extensiveScan,
                "hostname":hostnames,
                "host_ip":host_ip,
                "hostnames":hostnames,
                "portused":portused,
                "sslDetails":sslDetails,
                "scanType":scanType,
                "tranferProtocol":tranferProtocol,
                "header_details" :header_details['header'],
                "headerHas" : header_details['headerHas'],
                "headerHasNot": header_details['headerHasNot'],
                "headerInfo":header_info,
                "scanType":scanType
            }
            f = open("test.txt", "w")
            f.write(str(extensiveScan))
            f.close()
            return render(request,"./index.html",context)
    context ={
        "opePort":"Scan",
        "scanType": "Scan"
    }
    return render(request,"./index.html",context)

#open Ports
def openPorts(request):
    if request.method == "POST":
        openPortsList.clear()
        hostname = request.POST['hostname']
        try:
            for i in range(0,65535):
                thread = threading.Thread(target=scan_port, args=(i,hostname))
                thread.start()
            context = { 
                "openPort": openPortsList
            }
            return render(request,"./pages/open_port_scanner.html",context)
        except Exception as err:
            print(err)
    else:
        context ={
            "opePort":"Scan"
        }
    return render(request,"./pages/open_port_scanner.html",context)

#services
def services(request):
    ListServices()
    context = {
        "services":all_services
    }
    return render(request,"./pages/services.html",context)

#sql mapping
def sqlMap(request):
    return render(request,"./pages/sql_map.html")

#vulnurable headers
def vulHeaders(request):
    context = {}
    if request.method == "POST":
        hostname = request.POST['hostname']
        context = scanWebHeader(hostname)
        print(context)
    return render(request,"./pages/vul_header.html",context)
