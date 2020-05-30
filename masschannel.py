import argparse
import os


class MassChannel:
    def main(self):
        args = self.cli()
        nmap_ports = self.masscan(args.ip, interface=args.i, rate=args.r)
        self.nmap_scan(args.ip, nmap_ports[0], nmap_ports[1], args.o)

    def cli(self):
        parser = argparse.ArgumentParser(description='Scan a target with masscan and'
                                                     ' then channel the results into '
                                                     'nmap')
        parser.add_argument('ip', type=str, help='The IP or range of IPs that we\'ll '
                                                 'scan')
        parser.add_argument('--o', default='', type=str, help='Store results in a file')
        parser.add_argument('--i', default='', type=str, help='The interface to use')
        parser.add_argument('--r', default=1000, type=int, help='The rate for masscan')

        args = parser.parse_args()
        return args

    def masscan(self, ip, interface='', rate=1000, outfile=''):
        command = 'sudo masscan %s -p1-65535,U:1-65535 --rate=%i' % (ip, rate)
        if interface:
            command += ' -e %s' % interface

        command += ' -oL %s' % 'tmp_masscan.txt'

        print(command)
        stream = os.popen(command)
        stream.read()
        results = []

        with open('tmp_masscan.txt', 'r') as res:
            for line in res:
                line = line.strip()
                if line == '#masscan' or line == '# end':
                    pass
                else:
                    results.append(line)

        os.remove('tmp_masscan.txt')

        target_tcp = []
        target_udp = []

        for res in results:
            vals = res.split(' ')
            if vals[1] == 'tcp':
                target_tcp.append(vals[2])
            elif vals[1] == 'udp':
                target_udp.append(vals[2])

        return [target_tcp, target_udp]

    def nmap_scan(self, ip, targets_tcp, targets_udp, outfile='', interface=''):
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
            print(command)
            os.system(command)


if __name__ == '__main__':
    MC = MassChannel
    MC().main()
