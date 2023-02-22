#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import argparse
import socket
import os
import sys
import struct
import time
import random
import traceback # useful for exception handling
import threading
import select
import io

def setupArgumentParser() -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description='A collection of Network Applications developed for SCC.203.')
        parser.set_defaults(func=ICMPPing, hostname='lancaster.ac.uk')
        subparsers = parser.add_subparsers(help='sub-command help')
        
        parser_p = subparsers.add_parser('ping', aliases=['p'], help='run ping')
        parser_p.set_defaults(timeout=4)
        parser_p.add_argument('hostname', type=str, help='host to ping towards')
        parser_p.add_argument('--count', '-c', nargs='?', type=int,
                              help='number of times to ping the host before stopping')
        parser_p.add_argument('--timeout', '-t', nargs='?',
                              type=int,
                              help='maximum timeout before considering request lost')
        parser_p.set_defaults(func=ICMPPing)

        parser_t = subparsers.add_parser('traceroute', aliases=['t'],
                                         help='run traceroute')
        parser_t.set_defaults(timeout=4, protocol='icmp')
        parser_t.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_t.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_t.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_t.set_defaults(func=Traceroute)
        
        parser_pt = subparsers.add_parser('paris-traceroute', aliases=['pt'],
                                         help='run paris-traceroute')
        parser_pt.set_defaults(timeout=4, protocol='icmp')
        parser_pt.add_argument('hostname', type=str, help='host to traceroute towards')
        parser_pt.add_argument('--timeout', '-t', nargs='?', type=int,
                              help='maximum timeout before considering request lost')
        parser_pt.add_argument('--protocol', '-p', nargs='?', type=str,
                              help='protocol to send request with (UDP/ICMP)')
        parser_pt.set_defaults(func=ParisTraceroute)

        parser_w = subparsers.add_parser('web', aliases=['w'], help='run web server')
        parser_w.set_defaults(port=8080)
        parser_w.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_w.set_defaults(func=WebServer)

        parser_x = subparsers.add_parser('proxy', aliases=['x'], help='run proxy')
        parser_x.set_defaults(port=8000)
        parser_x.add_argument('--port', '-p', type=int, nargs='?',
                              help='port number to start web server listening on')
        parser_x.set_defaults(func=Proxy)

        args = parser.parse_args()
        return args


class NetworkApplication:

    def checksum(self, dataToChecksum: str) -> str:
        csum = 0
        countTo = (len(dataToChecksum) // 2) * 2
        count = 0

        while count < countTo:
            thisVal = dataToChecksum[count+1] * 256 + dataToChecksum[count]
            csum = csum + thisVal
            csum = csum & 0xffffffff
            count = count + 2

        if countTo < len(dataToChecksum):
            csum = csum + dataToChecksum[len(dataToChecksum) - 1]
            csum = csum & 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum = csum + (csum >> 16)
        answer = ~csum
        answer = answer & 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)

        answer = socket.htons(answer)

        return answer

    def printOneResult(self, destinationAddress: str, packetLength: int, time: float, ttl: int, destinationHostname=''):
        if destinationHostname:
            print("%d bytes from %s (%s): ttl=%d time=%.2f ms" % (packetLength, destinationHostname, destinationAddress, ttl, time))
        else:
            print("%d bytes from %s: ttl=%d time=%.2f ms" % (packetLength, destinationAddress, ttl, time))

    def printAdditionalDetails(self, packetLoss=0.0, minimumDelay=0.0, averageDelay=0.0, maximumDelay=0.0):
        print("%.2f%% packet loss" % (packetLoss))
        if minimumDelay > 0 and averageDelay > 0 and maximumDelay > 0:
            print("rtt min/avg/max = %.2f/%.2f/%.2f ms" % (minimumDelay, averageDelay, maximumDelay))

    def printMultipleResults(self, ttl: int, destinationAddress: str, measurements: list, destinationHostname=''):
        latencies = ''
        noResponse = True
        for rtt in measurements:
            if rtt is not None:
                latencies += str(round(rtt, 3))
                latencies += ' ms  '
                noResponse = False
            else:
                latencies += '* ' 

        if noResponse is False:
            print("%d %s (%s) %s" % (ttl, destinationHostname, destinationAddress, latencies))
        else:
            print("%d %s" % (ttl, latencies))

class ICMPPing(NetworkApplication):

    def receiveOnePing(self, icmpSocket, destinationAddress, ID, timeSent, timeout):
        # 1. Wait for the socket to receive a reply
        global time_received
        icmpSocket.settimeout(timeout)
        time_received = 0
        timeleft = timeout
        # 2. Once received, record time of receipt, otherwise, handle a timeout
        while True:
            ready = select.select([icmpSocket], [], [], timeleft)
            data = None
            if ready[0] == []: # Timeout
                break
            data, addr = icmpSocket.recvfrom(1024)
            time_received = time.time()
            print("time received: ", time_received)
            if data != None:
                break
            timeleft -= time_received - timeSent
            if timeleft <= 0:       #timeout
                return
        # 3. Compare the time of receipt to time of sending, producing the total network delay
        delay =  time_received - timeSent
        # 4. Unpack the packet header for useful information, including the ID
        icmp_header = data[20:28]
        type, code, checksum, packet_id, sequence = struct.unpack('!BBHHH', icmp_header)
        # 5. Check that the ID matches between the request and reply
        if(ID != packet_id):
            return
        # 6. Return total network delay
        return delay * 1000

    def sendOnePing(self, icmpSocket, destinationAddress, ID):
        # 1. Build ICMP header
        ECHO_REQUEST = 8
        ECHO_REPLY = 0
        header = struct.pack("!BBHHH", ECHO_REQUEST, 0, 0, ID, 1)
        data = []
        data = bytes(data)

        # 2. Checksum ICMP packet using given function
        checked = self.checksum(header + data)
        # 3. Insert checksum into packet    
        packet = struct.pack("!BBHHH", ECHO_REQUEST, 0, checked, ID, 1)
        # print('size ' ,sys.getsizeof(data))

        # 4. Send packet using socket
        while packet:
            sent = icmpSocket.sendto(packet, (destinationAddress, 1))
            packet = packet[sent:]
        # 5. Record time of sending
        timeSent = time.time()
        return timeSent
        pass

    def doOnePing(self, destinationAddress, timeout):
        # 1. Create ICMP socket
        icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        # 2. Call sendOnePing function
        timeSent = self.sendOnePing(icmpSocket, destinationAddress, 1)      #id is 1
        # 3. Call receiveOnePing function
        delay = self.receiveOnePing(icmpSocket, destinationAddress, 1, timeSent, timeout)
        # 4. Close ICMP socket
        icmpSocket.close()
        # 5. Return total network delay
        return delay
        pass

    def __init__(self, args):
        print('Ping to: %s...' % (args.hostname))
        while True:
             # 1. Look up hostname, resolving it to an IP address
            ip = socket.gethostbyname(args.hostname)
            # 2. Call doOnePing function, approximately every second
            ping = self.doOnePing(ip, 1)
            time.sleep(1)
            # 3. Print out the returned delay (and other relevant details) using the printOneResult method
            self.printOneResult(ip, 50, ping, 150) # Example use of printOneResult - complete as appropriat
            # 4. Continue this process until stopped


class Traceroute(NetworkApplication):
    def receiveOnePing(self, icmpSocket, destinationAddress, ID, timeSent, timeout):
        # 1. Wait for the socket to receive a reply
        icmpSocket.settimeout(timeout)
        timeleft = timeout
        # 2. Once received, record time of receipt, otherwise, handle a timeout
        while True:
            ready = select.select([icmpSocket], [], [], timeleft)
            data = None
            if ready[0] == []: # Timeout
                break
            data, addr = icmpSocket.recvfrom(1024)
            time_received = time.time()
            if data != None:
                break
            timeleft -= time_received - timeSent
            if timeleft <= 0:       #timeout
                return
        # 3. Compare the time of receipt to time of sending, producing the total network delay
        delay =  time_received - timeSent
        # 4. Unpack the packet header for useful information, including the ID
        icmp_header = data[20:28]
        type, code, checksum, packet_id, sequence = struct.unpack('!BBHHH', icmp_header)
        if type == 0:
            return False, delay * 1000 

        # 6. Return total network delay
        return True, delay * 1000

    def sendOnePing(self, icmpSocket, destinationAddress, ID):
        # 1. Build ICMP header
        ECHO_REQUEST = 8
        header = struct.pack("!BBHHH", ECHO_REQUEST, 0, 0, ID, 1)

        # 2. Checksum ICMP packet using given function
        checked = self.checksum(header)
        # 3. Insert checksum into packet    
        packet = struct.pack("!BBHHH", ECHO_REQUEST, 0, checked, ID, 1)
        # print('size ' ,sys.getsizeof(data))

        # 4. Send packet using socket
        while packet:
            sent = icmpSocket.sendto(packet, (destinationAddress, 1))
            packet = packet[sent:]
        # 5. Record time of sending
        timeSent = time.time()
        return timeSent
        pass

    def tracing(self, destinationAddress, timeout, ttl):
        icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        icmpSocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
    
        # 2. Call sendOnePing function
        timeSent = self.sendOnePing(icmpSocket, destinationAddress, 0x4321)      #id is 1
        # 3. Call receiveOnePing function
        flag, delay = self.receiveOnePing(icmpSocket, destinationAddress, 1, timeSent, timeout)
        # 4. Close ICMP socket
        icmpSocket.close()
        # 5. Return total network delay
        return flag, delay
        pass

    def __init__(self, args):
        print('Traceroute to: %s...' % (args.hostname))
        ttl = 1
        while True:
            ip = socket.gethostbyname(args.hostname)
            flag, ping = self.tracing(ip, 1, ttl)
            time.sleep(1)
            self.printOneResult(ip, 50, ping, ttl)
            ttl += 1
            if(flag == False):
                break
            
            

        

class ParisTraceroute(NetworkApplication):
    def receiveOnePing(self, icmpSocket, timeSent, timeout):
        global timeleft, time_received, data
        icmpSocket.settimeout(timeout)
        timeleft = timeout

        while True:
            try:
                data = None
                data, addr = icmpSocket.recvfrom(1024)
                time_received = time.time()
                if  data != None:
                    break
            except socket.timeout:
                return None, 0
        delay =  time_received - timeSent
        
        icmp_header = data[20:28]
        type, code, checksum, packet_id, sequence = struct.unpack('BBHHH', icmp_header)

        return addr[0], delay * 1000

    def udp_receiveOnePing(self, udpSocket, timeSent, timeout):
        global timeleft, time_received, data
        udpSocket.settimeout(timeout)
        timeleft = timeout

        while True:
            try:
                data = None
                data, addr = udpSocket.recvfrom(1024)
                time_received = time.time()
                if  data != None:
                    print(data)
                    break
            except socket.timeout:
                return None, 0
        delay =  time_received - timeSent
        
        # icmp_header = data[20:28]
        # type, code, checksum, packet_id, sequence = struct.unpack('BBHHH', icmp_header)

        return addr[0], delay * 1000

    def sendOnePing(self, icmpSocket, destinationAddress, ID):
        # 1. Build ICMP header
        ECHO_REQUEST = 8
        header = struct.pack("BBHHH", ECHO_REQUEST, 0, 0, ID, 1)
        data = []
        data = bytes(data)

        # 2. Checksum ICMP packet using given function
        checked = self.checksum(header + data)
        # 3. Insert checksum into packet    
        packet = struct.pack("BBHHH", ECHO_REQUEST, 0, checked, ID, 1)
        # print('size ' ,sys.getsizeof(data))

        # 4. Send packet using socket
        sent = icmpSocket.sendto(packet+data, (destinationAddress, 1))

        # 5. Record time of sending
        timeSent = time.time()
        return timeSent, sent
        pass

    def udp_sendOnePing(self, udpSocket, destinationAddress):
        # 1. Build UDP header
        LOCAL_PORT = 25565
        DEST_PORT = 25566
        str = "Fuck you"

        udpSocket.bind(("127.0.0.1", LOCAL_PORT))
        data = []
        data = bytes(data)
        header = struct.pack("HHHH", LOCAL_PORT, DEST_PORT, 8+sys.getsizeof(data), 0)

        # 2. Checksum ICMP packet using given function
        checked = self.checksum(header + data)
        print(checked)
        # 3. Insert checksum into packet
        header = struct.pack("HHHH", LOCAL_PORT, DEST_PORT, 8+sys.getsizeof(data), checked)

        # 4. Send packet using socket
        sent = udpSocket.sendto(header + data, (destinationAddress, 12345))
        print('sent!!')
        # 5. Record time of sending
        timeSent = time.time()
        return timeSent, sent
        pass

    def tracing(self, destinationAddress, timeout, ttl):
        icmpSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        icmpSocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
    
        # 2. Call sendOnePing function
        timeSent, byte = self.sendOnePing(icmpSocket, destinationAddress, 1)      #id is 1
        # 3. Call receiveOnePing function
        src_ip, delay = self.receiveOnePing(icmpSocket, timeSent, timeout)
        # 4. Close ICMP socket
        icmpSocket.close()
        # 5. Return total network delay
        return src_ip, delay, byte
        pass

    def udp_tracing(self, destinationAddress, timeout, ttl):
        udpSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udpSocket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
    
        # 2. Call sendOnePing function
        timeSent, byte = self.udp_sendOnePing(udpSocket, destinationAddress)      #id is 1
        # 3. Call receiveOnePing function
        src_ip, delay = self.udp_receiveOnePing(udpSocket, timeSent, timeout)
        # 4. Close ICMP socket
        udpSocket.close()
        # 5. Return total network delay
        return src_ip, delay, byte
        pass




    def __init__(self, args):
        # Please ensure you print each result using the printOneResult method!
        print('Paris-Traceroute to: %s...' % (args.hostname))
        ip = socket.gethostbyname(args.hostname)
        ttl = 1
        loss = 0
        while True:
                # time.sleep(1)
                count = 0
                delayList = []
                for i in range(3):
                    if args.protocol == 'icmp':
                        src_ip, ping, byte = self.tracing(ip, args.timeout, ttl)
                    elif args.protocol == 'udp':
                        src_ip, ping, byte = self.udp_tracing(ip, args.timeout, ttl)
                    delayList.append(ping)
                    if src_ip == None:              # If there's a timeout error
                        loss += 1
                        self.printAdditionalDetails((loss/(ttl*3)) * 100)
                        count += 1
            
                if count == 3:
                    ttl += 1
                    continue

                try:
                    name = socket.gethostbyaddr(src_ip)[0]
                except:
                    name = ""
                self.printMultipleResults(ttl, ip, delayList, name)
                ttl += 1
                # if(src_ip not in ipArr):
                #     ipArr.append(src_ip)
                # else:
                #     ipArr.remove(src_ip)
                if(src_ip == ip):
                    # print(ipArr)
                    break
            




       


class WebServer(NetworkApplication):

    def handleRequest(self, tcpSocket):
        # 1. Receive request message from the client on connection socket
        data, src_ip = tcpSocket.recvfrom(1024)
        # 2. Extract the path of the requested object from the message (second part of the HTTP header)
        url = data.split(b' ')[1].decode('utf-8')
        url = url[1:]
        # 3. Read the corresponding file from disk
        # try:
        #     f = open(url, "rb")
        #     response = "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n".format(len(buffer))
        #     buffer = f.read()
        #     tcpSocket.sendall(response.encode('utf-8') + buffer)
        # except Exception:
        #     print(Exception)
        f = open(url, "rb")
        buffer = f.read()
        response = "HTTP/1.1 200 OK\r\n"
        tcpSocket.sendall(response.encode('utf-8') + buffer)
        # 5. Send the correct HTTP response error
        # 6. Send the content of the file to the socket
        # 7. Close the connection socket
        tcpSocket.close()
        # Content-Length: {}\r\n\r\n         .format(len(buffer)
        pass

    def __init__(self, args):
        print('Web Server starting on port: %i...' % (args.port))
        # 1. Create server socket
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # 2. Bind the server socket to server address and server port
        serverSocket.bind(("127.0.0.1", args.port))
        # 3. Continuously listen for connections to server socket
        conn = None
        while True:
            serverSocket.listen(1)
            conn, src_ip = serverSocket.accept()
            print(type(conn))
        # 4. When a connection is accepted, call handleRequest function, passing new connection socket (see https://docs.python.org/3/library/socket.html#socket.socket.accept)
            if conn != None:
                self.handleRequest(conn)
        # 5. Close server socket
            serverSocket.close()


class Proxy(NetworkApplication):

    def __init__(self, args):
        print('Web Proxy starting on port: %i...' % (args.port))


if __name__ == "__main__":
    args = setupArgumentParser()
    args.func(args)