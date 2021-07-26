import psutil
import csv
import datetime
import os
import hashlib
from ipwhois import IPWhois
import ipaddress
from art import *
import socket

# Parse data per connection
def parseWrite(write):
    print("[+] Parsing data for each connection")
    hostname = socket.gethostname()
    # Iterate each connection
    for conn in netstat:
        proc = psutil.Process(conn.pid)
        parent = (proc.parent())
        timestamp = datetime.datetime.fromtimestamp(proc.create_time()).strftime("%Y-%m-%dT%H:%M:%S")
        username = proc.username()
        # Do different things if parent process exists
        if parent != None:
            parentpid = parent.pid
            parentprocess = parent.name()
        else:
            parentpid = "-"
            parentprocess = "-"
        pid = conn.pid
        process = proc.name()
        cmdLine = proc.cmdline()
        status = conn.status
        sourceIP = conn.laddr[0]
        sourcePort = conn.laddr[1]
        # Do different things if destination connection exists
        if conn.raddr:
            destIP = conn.raddr[0]
            destPort = conn.raddr[1]

            # Enrich dest IP with WHOIS data

            ip = ipaddress.ip_address(conn.raddr[0])
            if ip.is_private == False:
                try:
                    whois = IPWhois(destIP)
                    whois_data = whois.lookup_rdap()
                    # Define new fields with DNS data
                    countryCode = whois_data['asn_country_code']
                    asn = whois_data['asn']
                    asnDesc = whois_data['asn_description']
                except:
                    countryCode = "-"
                    asn = "-"
                    asnDesc = "-"
        else:
            destIP = "-"
            destPort = "-"
            countryCode = "-"
            asn = "-"
            asnDesc = "-"
        if proc.cmdline() and os.path.isfile(proc.cmdline()[0]):
            procPath = proc.cmdline()[0]
            h = hashlib.sha256()
            with open((procPath),'rb') as file:
                chunk = 0
                while chunk != b'':
                    chunk = file.read(1024)
                    h.update(chunk)
            procHash = h.hexdigest()
        else:
            procHash = "-"

        rows = [[hostname, timestamp, username, parentpid, parentprocess, pid, process, procHash, cmdLine, status, sourceIP, sourcePort, destIP, destPort, countryCode, asn, asnDesc]]
        write.writerows(rows)

tprint("NetProc",font="alligator2")
print("NetProc v1.0 | @chrisdfir")
# Declare var as all network connections
netstat = psutil.net_connections(kind='all')
date = datetime.datetime.now()
date = date.strftime("%Y-%m-%dT%H%M%S")
print("[+] Started at {}".format(date))
# Open CSV file
with open(".\\NetProc.csv",'w', newline='') as f:
    # Declare and write CSV headers
    fields = ['Hostname', 'Process Creation Timestamp', 'Username', 'PPID', 'Parent Process Name', 'PID', 'Process Name', 'SHA256 Hash', 'Cmd Line', 'Connection Status', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Country Code', 'ASN', 'Description']
    write = csv.writer(f)
    write.writerow(fields)

    parseWrite(write)
    print("[+] Complete")
    print("[+] Output file: NetProc.csv")