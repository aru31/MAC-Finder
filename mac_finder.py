import os
import sys
import nmap
import socket
import fcntl
import struct


euid = os.geteuid()
if euid != 0:
    print("Script not started as root. Running sudo...")
    args = ['sudo', sys.executable] + sys.argv + [os.environ]
    os.execlpe('sudo', *args)


def get_ip_address(ifname):
    """ Get IP """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,
        struct.pack('256s', bytes(ifname[:15], 'utf-8'))
    )[20:24])


def run_nmap():
    """ Run NMAP """

    host = None
    if sys.argv[1].lower() == 'ethernet':
        host = get_ip_address('eno1')
    elif sys.argv[1].lower() == 'wifi':
        host = get_ip_address('wlo1')
    # print(f'Host IP: {host}')
    print(host)
    temp = host.split('.')
    temp.pop()

    _ip = '.'.join(temp)

    nm = nmap.PortScanner()
    hosts = _ip + '.0/24'
    print(hosts)
    nm.scan(hosts=hosts, arguments='-sn')

    ipv4_data = []
    ipv6_data = []
    for host in nm.all_hosts():
        # print(nm[host])
        mac_address = None
        device = 'Unknown'
        if 'mac' in nm[host]['addresses']:
            mac_address = nm[host]['addresses']['mac']
            try:
                device = nm[host]['vendor'][mac_address]
            except:
                pass

            if nm[host]['addresses']['ipv4']:
                ipv4_data.append((host, mac_address, device))
            else:
                ipv6_data.append((host, mac_address, device))
    return ipv4_data, ipv6_data


def run():
    """ Go, go, go """

    ipv4_data, ipv6_data = run_nmap()
    if ipv4_data:
        print('ipv4')
        for ip in ipv4_data:
            print(ip)
    if ipv6_data:
        print('ipv6')
        for ip in ipv6_data:
            print(ip)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Please enter the network type(wifi/ethernet)')
        sys.exit(1)
    run()
