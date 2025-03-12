#!/usr/local/bin/python
import sys
import getopt
import socket
import os
import re

def check_arguments():
    # variables for checking -f and -n
    check_f = False
    check_n = False

    # check number of arguments
    if len(sys.argv) != 5:
        sys.exit("Wrong number of arguments")
    else:
        #print("Great number of arguments")
        # use getopt and set for -f and -n
        try:    
            opts, args = getopt.getopt(sys.argv[1:], "f:n:")
        except:
            sys.exit("ERROR! wrong arguments")

        # check -f and -n and put next argument to variable arg_f and arg_n from arg
        for opt, arg in opts:
            if opt in ['-f']:
                check_f = True
                arg_f = arg
            elif opt in ['-n']:
                check_n = True
                arg_n = arg

        # check the arragement of arguments
        if (check_f == False) or (check_n == False):
            sys.exit("Arguments are wrong arranged")
        else:
            #print ("Arguments are arranged OK")
            # delete 'fsp://'
            arg_f = arg_f[6:]
            # divide after special character
            udp_arg_n = arg_n.split(":")
            check_ipaddress(udp_arg_n[0])

            # check if it is digit
            if (udp_arg_n[1].isdigit() == False):
                sys.exit("ERROR: Port is not digit")
            else:
                # check if number is from correct interval
                if ((int(udp_arg_n[1]) < 0) or (int(udp_arg_n[1]) > 65535)):
                    sys.exit("ERROR: Wrong number of Port")
                else:
                    udp_arg_f = arg_f.split("/", 1)
                    return udp_arg_n, udp_arg_f

            

# checking IP address
def check_ipaddress(ipadd):
    #create regex fpr checking ip address if not correct then ERROR
    check_ip_add = r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9]).){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    if not (re.search(check_ip_add, ipadd)):
        sys.exit("Error: Wrong ip address")
    else:
        return

# UDP communication
def udp_socket(udp_arg_n, udp_arg_f):

    # messages
    msg1 = "WHEREIS "
    msg2 = udp_arg_f[0]
    msg = bytes(msg1 + msg2)
    udp_ip = udp_arg_n[0]
    udp_port = int(udp_arg_n[1])

    # checking name of server
    check_reg = r"^([a-zA-Z0-9-._]*)$"
    if not re.search(check_reg, udp_arg_f[0]):
        sys.exit("Error: Wrong server name")

    # create udp socket
    client_socket_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket_udp.settimeout(5)

    if (client_socket_udp <= 0):
        sys.exit("ERROR in UDP socket")
        
    # sending
    client_socket_udp.sendto(msg, (udp_ip, udp_port))

    # receiving and check recv time 
    try:
        data, addr = client_socket_udp.recvfrom(1024)
    except socket.timeout:
        sys.exit("ERROR: Timed out")

    # check recv message if it is OK or not
    if data[:2] != "OK":
        sys.exit("ERROR: Wrong recv")

    # close socket
    client_socket_udp.close()

    # printing data and modify for next use
    data_new = data[3:]
    data_new_udp = data_new.split(":")

    return data_new_udp, udp_arg_f
   

def tcp_socket(data_new_udp, udp_arg_f):
    result = False
    new_udp_arg_f = udp_arg_f[1].split("/")

    # check if we want index or *
    if ((udp_arg_f[1] != 'index') and (udp_arg_f[1] != '*')):
        if ((new_udp_arg_f[-1] == 'index') or (new_udp_arg_f[-1] == '*')):
            sys.exit("ERR Syntax")
  
    if (udp_arg_f[1] == "*"):
        udp_arg_f[1] = "index"
        result = True

    # messages
    msg_get = "Get " + udp_arg_f[1] + " FSP/1.0\r\n"
    msg_hostname = "Hostname: " + udp_arg_f[0] + "\r\n"
    msg_agent = "Agent: xsvora02\r\n\r\n"
    msg_all = bytes(msg_get + msg_hostname + msg_agent)
    tcp_ip = data_new_udp[0]
    tcp_port = int(data_new_udp[1])
    buffer_size = 2048

    # create tcp socket
    client_socket_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if (client_socket_tcp <= 0):
        sys.exit("ERROR in TCP socket")

    # connect
    client_socket_tcp.connect((tcp_ip, tcp_port))

    # sending
    client_socket_tcp.send(msg_all)

    full_file = ""
    # receiving
    while 1:
        data_tcp = client_socket_tcp.recv(buffer_size)
        if not data_tcp:
            break
        full_file += data_tcp

    # close socket
    client_socket_tcp.close()

    # create file and write content
    if (result == False):
        # find local directory
        new_path = os.path.dirname(os.path.abspath("fileget.py"))

        my_file = os.path.join(new_path, new_udp_arg_f[-1])
        with open(my_file, 'wb') as handle:    
            if 'FSP/1.0 Success' in full_file:
                my_file_text = full_file.split("\r\n\r\n", 1)
                handle.write(my_file_text[1])
                get_all = my_file_text[1].split("\r\n")
            else:
                sys.exit("File not found")
    else:
        if 'FSP/1.0 Success' in full_file:
            my_file_text = full_file.split("\r\n\r\n", 1)
            get_all = my_file_text[1].split("\r\n")
            for i in range(len(get_all) - 1):
                udp_arg_f[1] = get_all[i]
                tcp_socket(data_new_udp, udp_arg_f)
        else:
            sys.exit("ERROR Syntax")
        

# call functions
x, y = check_arguments()
z, w = udp_socket(x, y)
tcp_socket(z, w)
