#!/usr/bin/env python

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from aws.boto_connections import AWSBotoAdapter
from aws.ec2_adapter import Ec2Adapter
import nmap
import argparse


class nmap_adapter():

    def __init__(self):
        self.portscan = nmap.PortScanner()
        self.scan_results = []
        self.nmap_arguments = '-P0'

    def callback_result(self, host, scan_result):
        print(host + " done!")
        print(self.scan_results)

    def nmapIsScanning(self):
        return self.portscan.still_scanning()

    def wait(self, time):
        self.portscan.wait(time)

    def launch_scan(self, instance_dict, ports):
        instance_ip = instance_dict['public_ip']
        instance_name = instance_dict['name']
        result = {}
        result['nmap_scan'] = self.portscan.scan(hosts=instance_ip, arguments=self.nmap_arguments + " -p " + ports)
        result['name'] = instance_name
        self.scan_results.append(result)
        print(instance_name + " (" + instance_ip + ") done!")

def main():
    parser = argparse.ArgumentParser(description='Creates a cloudfront distribution and related route53 needed')
    parser.add_argument('-p', '--profile', required=True, help='profile of the AWS account')
    parser.add_argument('-l', '--portlist', required=True, help='ports to evaluate')
    args = parser.parse_args()
    __profile = args.profile
    __port_list = args.portlist
    ec2client = Ec2Adapter(__profile)
    instances_dict = ec2client.get_ec2_instances()
    print("found " + str(len(instances_dict)) + " servers!")
    nm = nmap_adapter()
    for instance in instances_dict:
        nm.launch_scan(instance, __port_list)

    final_result = ""
    servername = ""
    for result in nm.scan_results:
        partial_result = ""
        put_in_final_report = False
        for keyname,valuename in result.iteritems():
            if keyname == 'name':
                servername = valuename
            if keyname == 'nmap_scan':
                for keynmap, valuenmap in valuename.iteritems():
                    if keynmap == 'scan':
                        for keyscan, valuescan in valuenmap.iteritems():
                            partial_result = partial_result + "results for " + servername + " (" + keyscan + ")\n"
                            for keytcp, valuetcp in valuescan.iteritems():
                               if keytcp == 'tcp':
                                   for keyport, valueport in valuetcp.iteritems():
                                        for keystate, valuestate in valueport.iteritems():
                                            if keystate == 'state':
                                                if valuestate == 'open':
                                                    put_in_final_report = True
                                                    partial_result = partial_result + " * " + str(keyport) + " tcp: " + valuestate +"\n"
                        if put_in_final_report:
                            final_result = final_result + partial_result

    print(final_result)

if __name__ == '__main__':
    main()