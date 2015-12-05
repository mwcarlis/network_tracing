
import argparse
import time
import re

from recon_engine import ReconClient, SERVER_LOCKFILE_ALIVE, SERVER_LOCKFILE_WAIT
import filelock

CLIENT_LOCKFILE = '.recon_client.lock'

def client_request(request):

    client_flock = filelock.FileLock(CLIENT_LOCKFILE)
    server_alive_flock = filelock.FileLock(SERVER_LOCKFILE_ALIVE)
    server_wait_flock = filelock.FileLock(SERVER_LOCKFILE_WAIT)

    try:
        ## There is a Race here.
        server_alive_flock.acquire(timeout=0)
        server_alive_flock.release()
        raise Exception('The server is not alive')
    except filelock.Timeout:
        pass


    try:
        ## There is a Race here.
        server_wait_flock.acquire(timeout=0)
        server_wait_flock.release()
        raise Exception("The server isn't listening for clients")
    except filelock.Timeout:
        pass


    with client_flock.acquire(timeout=30):
        rcs = ReconClient()
        rcs.send('cm.args-www.kamotion.com')
        rcs.sock.close()



def IpAddressCheck(ip_addr):
    # Check the given Ip address is in the proper regex format
    matchObj = re.match('(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.?', ip_addr)
    if matchObj:
    #check the code for a valid numbers are in range 255
        for i in range(1,5):
            if int(matchObj.group(i)) > 255:
                error_msg = "%s : is not a valid IP address"%ip_addr
                raise argparse.ArgumentTypeError(error_msg)
        else:
            return ip_addr
    else:
        error_msg = "%s : does not contains IP address in decimal format"%ip_addr
        raise argparse.ArgumentTypeError(error_msg)


def HandleActive(args):
#code  to execute DNS,sniff and geoIP ipaddress in args.ip_address
    print args


'''code to execute DNS, geoIP
ipaddress in args.ip_address'''

def HandlePassive(args):
    print args


def HandleInd(args):
#'''code to take args.do ipaddress in args.ip_address'''
    if 'DNS' in args.do:
        print "executing DNS"

    if 'sniff' in args.do:
        print "executing sniff"

    if 'geoIP' in args.do:
        print "executing geoIP"
    print args

def GetParser():
    parser = argparse.ArgumentParser(prog='UI', description='\nReconnaissance Engine User Interface\n',epilog='\nThats right way to do Recon' )

    subparsers = parser.add_subparsers(help='choose active,passive or ind for independent')

    parser_active = subparsers.add_parser('active', help='active help: active <Ip_address>')
    parser_active.add_argument("ip_address", help="Enter the IP Address of the host you want to Recon\n",type=IpAddressCheck)
    parser_active.set_defaults(func=HandleActive)

    parser_passive = subparsers.add_parser('passive', help='passive help: passive <Ip_address>')
    parser_passive.add_argument("ip_address", help="Enter the IP Address of the host you want to Recon\n",type=IpAddressCheck)
    parser_passive.set_defaults(func=HandlePassive)

    parser_ind = subparsers.add_parser('ind', help='independent help: ind <Ip_address>')
    parser_ind.add_argument("ip_address", help="Enter the IP Address of the host you want to Recon\n",type=IpAddressCheck)
    parser_ind.add_argument("do", nargs='+', help="Enter either of DNS,geoIp,sniff \n",choices=['DNS','geoIP','sniff'])
    parser_ind.set_defaults(func=HandleInd)
    return parser

if __name__ == "__main__":
    client_request(None)
    # args=GetParser().parse_args()
    # args.func(args)
