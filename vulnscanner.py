*import os
import socket
import sys

def retBanner(ip, port):
    try:
        socket.setdefaulttimeout(2)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port)) #attempt a connection with each ip/port combo
        banner = sock.recv(1024)
        #print banner
        return banner
    except:
        return

def checkVuln(banner, seedfile):
    f = open(seedfile, 'r')
    for line in f.readlines(): #grabs the server's banner from main function and checks each line of the seedfile for a match
        if line.strip('\n') in banner:
            print '[+] Server is vulnerable: ' + banner.strip('\n')

def main():
# first: input validation
    if len(sys.argv) == 2:
        seedfile = sys.argv[1]
        if not os.path.isfile(seedfile): # checking for seedfile's existence
            print '[-] ' + seedfile + ' does not exist.'
            exit(0)
        if not os.access(seedfile, os.R_OK): # checking seedfile's access permissions
            print '[-] ' + seedfile + ' access denied.'
            exit(0)
    else:
        print '[-] Usage: ' + str(sys.argv[0]) + ' <vuln seedfile>' # making sure user uses correct command syntax
        exit(0)
# then: defining the ip range and ports to scan
    portList = [21,22,25,80,110,443] # todo: allow user to define which ports to scan at the commandline when the command is executed
    for x in range(1, 255):
        ip = '192.168.0.' +str(x) # todo: allow user to define what IP range to scan at the commandline when command is executed
# finally: the main function
        for port in portList:
            print '[*] testing ' + str(ip) + ':' + str(port)
            banner = retBanner(ip, port) # calls function retBanner
            if banner:
                print '[*] checking ' + ip + ': ' + banner
                checkVuln(banner, seedfile) # calls function checkVuln
if __name__ == '__main__':
    main()
