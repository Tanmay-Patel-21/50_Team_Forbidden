from django.shortcuts import render
import threading
import time

import sys
import socket
from datetime import datetime

# Defining a target
def dashboard(request):
    return render(request,"./index.html")

# function to scan ports and see which ports are open
openPortsList = []
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


def openPorts(request):
    if request.method == "POST":
        openPortsList.clear()
        hostname = request.POST['hostname']
        try:
            for i in range(0, 1500):
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