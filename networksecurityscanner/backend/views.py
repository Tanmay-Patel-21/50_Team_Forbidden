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
import pprint
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
        openPortsList.clear()
        hostname = request.POST['hostname']
        tranferProtocol = request.POST['tranferProtocol']
        scanType = request.POST['scanType']
        if scanType == "light":
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
                }
                return render(request,"./index.html",context)
            except Exception as err:
                print(err)
        else:
            #Extensive scan code here 
            nm=nmap.PortScanner()
            scan_range=nm.scan(hosts=hostname,arguments='-A')
            dict= pprint.pprint(scan_range['scan'])
            print(dict)
            dict=scan_range['scan']
            print(dict)
            pass
    context ={
        "opePort":"Scan",
        "dict":"dict"
    }

    return render(request,"./index.html",context)

#open Ports
def openPorts(request):
    if request.method == "POST":
        openPortsList.clear()
        hostname = request.POST['hostname']
        # ports_scan = request.POST['scanop']

        #udp 4096 - 65535
        # if ports_scan == "tcp":
        #     scan_range = range(0,4095)
        # elif ports_scan == "udp":
        #     scan_range = range(4096,65535)
        # else:
        #     scan_range = range(0,65535)

        try:
            for i in range(0,5000):
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
