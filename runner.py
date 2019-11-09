import threading
import sys
import os
import os.path
import platform
import subprocess
import time
import click


euid = os.geteuid()
if euid != 0:
    print("Script not started as root. Running sudo...")
    args = ['sudo', sys.executable] + sys.argv + [os.environ]
    os.execlpe('sudo', *args)


def load_dictionary(file):
    oui = {}
    with open(file, 'r') as f:
        for line in f:
            if '(hex)' in line:
                data = line.split('(hex)')
                key = data[0].replace('-', ':').lower().strip()
                company = data[1].strip()
                oui[key] = company
    return oui


def which(program):
    """Determines whether program exists
    """
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            path = path.strip('"')
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file
    raise


def showTimer(timeleft):
    """Shows a countdown timer"""
    total = int(timeleft) * 10
    for i in range(total):
        sys.stdout.write('\r')
        timeleft_string = '%ds left' % int((total - i + 1) / 10)
        if (total - i + 1) > 600:
            timeleft_string = '%dmin %ds left' % (
                int((total - i + 1) / 600), int((total - i + 1) / 10 % 60))
        sys.stdout.write("[%-50s] %d%% %15s" %
                         ('=' * int(50.5 * i / total), 101 * i / total, timeleft_string))
        sys.stdout.flush()
        time.sleep(0.1)
    print("")


@click.command()
@click.option('--loop', help='loop forever', is_flag=True)
@click.option('-s', '--scantime', default='60', help='time in seconds to scan')
def main(scantime, loop):
    """ Run the main command line function """
    if loop:
        while True:
            adapter = scan(scantime)
    else:
        scan(scantime)


def scan(scantime):
    """ Monitor wifi signals """

    print("OS: " + os.name)
    print("Platform: " + platform.system())
    oui = load_dictionary('oui.txt')

    tshark = which("tshark")

    adapter = 'wlo1mon'
    print("Using %s adapter and scanning for %s seconds..." %
          (adapter, scantime))

    t1 = threading.Thread(target=showTimer, args=(scantime,))
    t1.daemon = True
    t1.start()

    dump_file = '/tmp/tshark-temp'
    command = [tshark, '-I', '-i', adapter, '-a',
               'duration: ' + scantime, '-w', dump_file]

    run_tshark = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    stdout, nothing = run_tshark.communicate()

    t1.join()

    command = [
        tshark, '-r',
        dump_file, '-T',
        'fields', '-e',
        'wlan.sa', '-e',
        'wlan.bssid', '-e',
        'radiotap.dbm_antsignal'
    ]

    run_tshark = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output, nothing = run_tshark.communicate()

    foundMacs = {}
    for line in output.decode('utf-8').split('\n'):
        if line.strip() == '':
            continue
        mac = line.split()[0].strip().split(',')[0]
        dats = line.split()
        if len(dats) == 3:
            if ':' not in dats[0] or len(dats) != 3:
                continue
            if mac not in foundMacs:
                foundMacs[mac] = []
            dats_2_split = dats[2].split(',')
            if len(dats_2_split) > 1:
                rssi = float(dats_2_split[0]) / 2 + float(dats_2_split[1]) / 2
            else:
                rssi = float(dats_2_split[0])
            foundMacs[mac].append(rssi)

    if not foundMacs:
        print("Found no signals, are you sure %s supports monitor mode?" % adapter)
        sys.exit(1)

    for key, value in foundMacs.items():
        foundMacs[key] = float(sum(value)) / float(len(value))

    for mac in foundMacs:
        oui_id = 'Not in OUI'
        if mac[:8] in oui:
            oui_id = oui[mac[:8]]
        print(f'company: {oui_id}, mac: {mac} ' + str(foundMacs[mac]))

    os.remove(dump_file)
    return adapter


if __name__ == '__main__':
    main()
