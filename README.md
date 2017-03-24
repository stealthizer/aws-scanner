# aws-scanner

Description: By providing an aws profile, aws-scanner will get all public ips from instances and recursively launch an nmap to ensure that the network rules configured are consistent with what we think is exposed. 

As a result you will get a report of which servers have open ports found.

Usage: python aws-scan -p aws_profile -l portlist

