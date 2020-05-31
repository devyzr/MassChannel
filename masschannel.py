import argparse
import os
import sys


class MassChannel:
    def main(self):
        # Call the cli, then pass the arguments to the function in turn
        args = self.cli()
        nmap_ports = self.masscan(args.ip, interface=args.i, rate=args.r,
                                  print_cmd=args.print_cmd, udp_scan=args.udp,
                                  tcp_scan=args.tcp)
        self.nmap_scan(args.ip, nmap_ports[0], nmap_ports[1], args.o)

    # A command line interface for the tool, returns the argument values
    def cli(self):
        parser = argparse.ArgumentParser(description='Scan a target with masscan and'
                                                     ' then channel the results into '
                                                     'nmap')
        parser.add_argument('ip', type=str, help='The IP or range of IPs that we\'ll '
                                                 'scan')
        # Outfile
        parser.add_argument('-o', metavar='OUTFILE', default='', type=str, help='Store '
                            'results in a file')
        # Network interface (eth0 for example)
        parser.add_argument('-i', metavar='INTERFACE', default='', type=str, help='The '
                            'interface to use')
        parser.add_argument('-r', metavar='RATE', default=1000, type=int, help='The '
                            'rate for masscan, default is 1000')
        parser.add_argument('-p', '--print_cmd', action='store_true', help='Print the '
                            'scanner commands before executing.')
        parser.add_argument('-u', '--udp', action='store_true', help='Scan UDP only')
        parser.add_argument('-t', '--tcp', action='store_true', help='Scan TCP only')

        args = parser.parse_args()
        return args

    # Calls masscan and sets the arguments. Results from the command are stored in a
    # temporary file, which is then read, deleted and the results are returned.
    def masscan(self, ip, interface='', rate=1000, outfile='', print_cmd=False,
                udp_scan=False, tcp_scan=False):
        command = 'sudo masscan %s -p1-65535,U:1-65535 --rate=%i' % (ip, rate)

        if tcp_scan and udp_scan:
            print("Flags --u and --t are mutually exlusive, exiting.")
            sys.exit()

        if udp_scan:
            command = command.replace('-p1-65535,U:1-65535', '-p1-65535')
        if tcp_scan:
            command = command.replace('-p1-65535,U:1-65535', '-pU:1-65535')

        if interface:
            command += ' -e %s' % interface

        command += ' -oL %s' % 'tmp_masscan.txt'

        if print_cmd:
            print(command)
        stream = os.popen(command)
        stream.read()
        results = []

        with open('tmp_masscan.txt', 'r') as res:
            for line in res:
                line = line.strip()
                # We skip the start and end flags
                if line == '#masscan' or line == '# end':
                    pass
                else:
                    results.append(line)

        os.remove('tmp_masscan.txt')

        # Separate results into TCP or UDP
        target_tcp = []
        target_udp = []

        for res in results:
            vals = res.split(' ')
            print('%s %s %s' % (vals[0], vals[1], vals[2]))
            if vals[1] == 'tcp':
                target_tcp.append(vals[2])
            elif vals[1] == 'udp':
                target_udp.append(vals[2])

        return [target_tcp, target_udp]

    def nmap_scan(self, ip, targets_tcp, targets_udp, outfile='', interface='',
                  print_cmd=False):
        base_command = 'sudo nmap -sV -T4 -p '
        command = base_command
        if targets_tcp:
            for t in targets_tcp:
                command += '%s,' % t
            command += ' %s' % ip
            if outfile:
                command += ' -oN tcp_%s' % outfile
            if interface:
                command += ' -e %s' % interface

            print('\nStarting nmap TCP scan')
            if print_cmd:
                print(command)
            os.system(command)

        command = base_command
        if targets_udp:
            command = command.replace('-sV', '-sUV')
            for t in targets_udp:
                command += '%s,' % t
            command += ' %s' % ip
            if outfile:
                command += ' -oN udp_%s' % outfile
            if interface:
                command += ' -e %s' % interface

            print('\nStarting nmap UDP scan')
            if print_cmd:
                print(command)
            os.system(command)


if __name__ == '__main__':
    MC = MassChannel
    MC().main()
