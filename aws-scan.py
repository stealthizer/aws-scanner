#!/usr/bin/env python

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from aws.boto_connections import AWSBotoAdapter
import nmap
import argparse


class nmap_adapter():

    def __init__(self):
        self.portscan = nmap.PortScannerAsync()
        self.scan_results = []
        self.nmap_arguments = '-P0 -p 80'

    def callback_result(self, host, scan_result):
        print(host + " done!")
        self.scan_results.append(scan_result)
        print(self.scan_results)

    def nmapIsScanning(self):
        return self.portscan.still_scanning()

    def wait(self, time):
        self.portscan.wait(time)

    def launch_scan(self, instance_ip):
        self.portscan.scan(hosts=instance_ip, arguments=self.nmap_arguments, callback=self.callback_result)

def get_ec2_ips(ec2client):
    public_ips=[]
    instances = ec2client.describe_instances()['Reservations']
    for instance in instances:
        if 'PublicIpAddress' in instance['Instances'][0].keys():
            public_ips.append(instance['Instances'][0]['PublicIpAddress'])
    return public_ips

def main():
    parser = argparse.ArgumentParser(description='Creates a cloudfront distribution and related route53 needed')
    parser.add_argument('-p', '--profile', required=True, help='profile of the AWS account')
    args = parser.parse_args()
    __profile = args.profile
    __ec2conn = AWSBotoAdapter()
    ec2client = __ec2conn.get_client("ec2", __profile)
    instances = get_ec2_ips(ec2client)
    nm = nmap_adapter()
    for instance_ip in instances:
        print("Scanning " + instance_ip)
        nm.launch_scan(instance_ip)
        while nm.nmapIsScanning():
            nm.wait(2)

if __name__ == '__main__':
    main()