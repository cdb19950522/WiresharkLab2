#!/usr/bin/env python

import dpkt
import datetime
import socket
import argparse
import collections


# convert IP addresses to printable strings 
def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

# add your own function/class/method defines here.
def getprobe(unsorted,W_p,N_p):
    sortedbyport = sorted(unsorted,key=lambda x: x[1])
    port= list()
    for i in sortedbyport:
        port.append(i[1])
    numberisgood= [item for item, count in collections.Counter(port).items() if count >=N_p]
    newlist= list()
    portnumber = 0
    probe = list()
    totallist=list()
    #print numberisgood
    
    for j in numberisgood:
        for i in sortedbyport:
            if i[1] == j:
                newlist.append(i)
    for i in range(len(newlist)):
        if portnumber==0:
            portnumber = newlist[i][1]
            continue
        if newlist[i][1]==portnumber and i>0 and (newlist[i][0]-newlist[i-1][0]).total_seconds()<=W_p:
            probe.append(newlist[i])
            portnumber = newlist[i][1]
            if i ==len(newlist)-1:
                probe.append(newlist[i])
                totallist.append(probe) 
        else:

            probe.append(newlist[i-1])
            if len(probe)>=N_p:
                totallist.append(probe)
            probe=[]
            portnumber = newlist[i][1]
    return totallist

def getscan(unsorted,W_s,N_s):
    sortedbyport = sorted(unsorted,key=lambda x: x[1])
    scan=list()
    counter = 0 
    totalscan= list()
    for i in range(len(sortedbyport)):
        if i>0 and sortedbyport[i][1]-sortedbyport[i-1][1]<=W_s:
            scan.append(sortedbyport[i])
            #prev = sortedbyport[i][1]
            counter +=1
            if i == len(sortedbyport)-1 and counter>=N_s:
                totalscan.append(scan)
            
            
        else:
            if counter>=N_s:
                totalscan.append(scan)
            counter = 1
            scan = []
            scan.append(sortedbyport[i])
    return totalscan
def main():
    # parse all the arguments to the client
    parser = argparse.ArgumentParser(description='CS 352 Wireshark Assignment 2')
    parser.add_argument('-f', '--filename', type=str, help='pcap file to input', required=True)
    parser.add_argument('-t', '--targetip', type=str, help='a target IP address', required=True)
    parser.add_argument('-l', '--wp', type=int, help='Wp', required=True)
    parser.add_argument('-m', '--np', type=int, help='Np', required=True)
    parser.add_argument('-n', '--ws', type=int, help='Ws', required=True)
    parser.add_argument('-o', '--ns', type=int, help='Ns', required=True)

    # get the parameters into local variables
    args = vars(parser.parse_args())
    file_name = args['filename']
    target_ip = args['targetip']
    W_p = args['wp']
    N_p = args['np']
    W_s = args['ws']
    N_s = args['ns']

    input_data = dpkt.pcap.Reader(open(file_name,'r'))
    # list
    sortedbytime = list()
    unsorted = list()
    #list_of_all = dict()
    usortedbytime=list()
    uunsorted= list()

    for timestamp, packet in input_data:
        # this converts the packet arrival time in unix timestamp format
        # to a printable-string
        time_string = datetime.datetime.utcfromtimestamp(timestamp)
        # your code goes here ...
        #print time_string
        
        eth = dpkt.ethernet.Ethernet(packet)
        ip = eth.data
        
        
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            if ip.p==dpkt.ip.IP_PROTO_TCP:
                tcp = ip.data
                dst = socket.inet_ntoa(ip.dst)
                src = socket.inet_ntoa(ip.src)
                if dst == target_ip:
                    sortedbytime.append([time_string,tcp.dport,src])
                    unsorted.append([time_string,tcp.dport,src])
            elif ip.p==dpkt.ip.IP_PROTO_UDP:
                udp= ip.data
                dst = socket.inet_ntoa(ip.dst)
                src = socket.inet_ntoa(ip.src)
                if dst == target_ip:
                    usortedbytime.append([time_string,udp.dport,src])
                    uunsorted.append([time_string,udp.dport,src])
        
    totallist = getprobe(unsorted,W_p,N_p)
    totalscan = getscan(unsorted,W_s,N_s)
    udptotalprobe = getprobe(uunsorted,W_p,N_p)
    udptotalscan = getscan(uunsorted,W_s,N_s)
    
    
    print 'CS 352 Wireshark (Part 2)'
    print 'Reports for TCP'
    print 'Found',len(totallist),'probes'  
    for i in range(len(totallist)):
        print "Probe: [%d Packets]"%(len(totallist[i]))
        for j in range(len(totallist[i])):
            print '     Packet [Timestamp:',str(totallist[i][j][0]),'Port:',totallist[i][j][1],'Source IP:',totallist[i][j][2]
    
    print 'Found', len(totalscan),'scans'
    for i in range(len(totalscan)):
        print "Scan: [%d Packets]"%(len(totalscan[i]))
        for j in range(len(totalscan[i])):
            print '     Packet [Timestamp:',str(totalscan[i][j][0]),'Port:',totalscan[i][j][1],'Source IP:',totalscan[i][j][2]

    print 'Reports for UDP'
    print 'Found', len(udptotalprobe),'probes'
    for i in range(len(udptotalprobe)):
        print "Probe: [%d Packets]"%(len(udptotalprobe[i]))
        for j in range(len(udptotalprobe[i])):
            print '     Packet [Timestamp:',str(udptotalprobe[i][j][0]),'Port:',udptotalprobe[i][j][1],'Source IP:',udptotalprobe[i][j][2]
    
    print 'Found', len(udptotalscan),'scans'
    for i in range(len(udptotalscan)):
        print "Scan: [%d Packets]"%(len(udptotalscan[i]))
        for j in range(len(udptotalscan[i])):
            print '     Packet [Timestamp:',str(udptotalscan[i][j][0]),'Port:',udptotalscan[i][j][1],'Source IP:',udptotalscan[i][j][2]

# execute a main function in Python
if __name__ == "__main__":
    main()
