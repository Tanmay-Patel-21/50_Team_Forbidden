from multiprocessing import context
from django.shortcuts import render
import threading
import time
import win32con
import win32service
import sys
import socket
from datetime import datetime

#Functions

# function to scan ports and see which ports are open
openPortsList = [] #open ports array global variable
def scan_port(port,hostname):
    # we will check port of localhost
    host = hostname
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
        print("port {} is open".format(port))
        portNumber = "{}".format(port)
        openPortsList.append(portNumber)
        return port

start_time = time.time()

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
        print(x) 
        all_services.append(x)

#Redirecting views
#Home
def dashboard(request):
    return render(request,"./index.html")

#open Ports
def openPorts(request):
    if request.method == "POST":
        openPortsList.clear()
        hostname = request.POST['hostname']
        try:
            for i in range(0, 3000):
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
    return render(request,"./pages/vul_headers.html")