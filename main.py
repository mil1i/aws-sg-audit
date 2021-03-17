#!/usr/bin/env python3

import boto3
import argparse
import os

try:
    default_region = os.environ["AWS_DEFAULT_REGION"]
except KeyError:
    default_region = "us-east-1"


def lookup_by_id(sgid):
    sg = ec2.get_all_security_groups(group_ids=sgid)
    return sg[0].name


session = boto3.Session(profile_name='qq-readonly')

# Get a full list of the available regions
client = session.client('ec2')
regions_dict = client.describe_regions()
region_list = [region['RegionName'] for region in regions_dict['Regions']]

# Parse arguments
parser = argparse.ArgumentParser(description="Show unused security groups")
parser.add_argument("-r", "--region", type=str, default="us-east-1",
                    help="The default region is us-east-1. The list of available regions are as follows: "
                         f"{sorted(region_list)}")
parser.add_argument("-d", "--delete", help="delete security groups from AWS", action="store_true")
args = parser.parse_args()

client = session.client('ec2', region_name=args.region)
ec2 = session.resource('ec2', region_name=args.region)
all_groups = []
security_groups_in_use = []
bad_ports = [20, 21, 1433, 1434, 3306, 3389, 4333, 5432, 5500]
security_groups_with_bad_ports = []
bad_port_security_groups_in_use = []

# Get ALL security groups names
security_groups_dict = client.describe_security_groups()
security_groups = security_groups_dict['SecurityGroups']
for groupobj in security_groups:
    if groupobj['GroupName'] == 'default' or groupobj['GroupName'].startswith('d-') or groupobj['GroupName'].startswith(
            'AWS-OpsWorks-'):
        security_groups_in_use.append(groupobj['GroupId'])
    for perm in groupobj['IpPermissions']:
        try:
            if perm['FromPort'] == perm['ToPort']:
                if perm['ToPort'] in bad_ports and '0.0.0.0/0' in [ip['CidrIp'] for ip in perm['IpRanges']]:
                    security_groups_with_bad_ports.append(groupobj['GroupId'])
            elif any([bp in range(perm['FromPort'], perm['ToPort']) for bp in bad_ports]) and '0.0.0.0/0' in [ip['CidrIp'] for ip in perm['IpRanges']]:
                security_groups_with_bad_ports.append(groupobj['GroupId'])
        except KeyError:
            if perm['IpProtocol'] == '-1' and '0.0.0.0/0' in [ip['CidrIp'] for ip in perm['IpRanges']]:
                security_groups_with_bad_ports.append(groupobj['GroupId'])
    all_groups.append(groupobj['GroupId'])

# Get all security groups used by instances
instances_dict = client.describe_instances()
reservations = instances_dict['Reservations']
network_interface_count = 0

for i in reservations:
    for j in i['Instances']:
        for k in j['SecurityGroups']:
            if k['GroupId'] not in security_groups_in_use:
                security_groups_in_use.append(k['GroupId'])
            if k['GroupId'] in security_groups_with_bad_ports and k['GroupId'] not in bad_port_security_groups_in_use:
                bad_port_security_groups_in_use.append(k['GroupId'])

# Security Groups in use by Network Interfaces
eni_client = session.client('ec2', region_name=args.region)
eni_dict = eni_client.describe_network_interfaces()
for i in eni_dict['NetworkInterfaces']:
    for j in i['Groups']:
        if j['GroupId'] not in security_groups_in_use:
            security_groups_in_use.append(j['GroupId'])
        if j['GroupId'] in security_groups_with_bad_ports and j['GroupId'] not in bad_port_security_groups_in_use:
            bad_port_security_groups_in_use.append(j['GroupId'])

# Security groups used by classic ELBs
elb_client = session.client('elb', region_name=args.region)
elb_dict = elb_client.describe_load_balancers()
for i in elb_dict['LoadBalancerDescriptions']:
    for j in i['SecurityGroups']:
        if j not in security_groups_in_use:
            security_groups_in_use.append(j)
        if j in security_groups_with_bad_ports and j not in bad_port_security_groups_in_use:
            bad_port_security_groups_in_use.append(j)

# Security groups used by ALBs
elb2_client = session.client('elbv2', region_name=args.region)
elb2_dict = elb2_client.describe_load_balancers()
for i in elb2_dict['LoadBalancers']:
    try:
        # if i['Type'] == 'network':
        #     continue
        for j in i['SecurityGroups']:
            if j not in security_groups_in_use:
                security_groups_in_use.append(j)
            if j in security_groups_with_bad_ports and j not in bad_port_security_groups_in_use:
                bad_port_security_groups_in_use.append(j)
    except KeyError:
        pass

# Security groups used by RDS
rds_client = session.client('rds', region_name=args.region)
rds_dict = rds_client.describe_db_instances()
for i in rds_dict['DBInstances']:
    for j in i['VpcSecurityGroups']:
        if j['VpcSecurityGroupId'] not in security_groups_in_use:
            security_groups_in_use.append(j['VpcSecurityGroupId'])
        if j['VpcSecurityGroupId'] in security_groups_with_bad_ports and j['VpcSecurityGroupId'] not in bad_port_security_groups_in_use:
            bad_port_security_groups_in_use.append(j['VpcSecurityGroupId'])

# Security groups used by Lambdas
lambda_client = session.client('lambda', region_name=args.region)
lambda_functions = lambda_client.list_functions()
while True:
    if "NextMarker" in lambda_functions:
        nextMarker = lambda_functions["NextMarker"]
    else:
        nextMarker = ""
    for function in lambda_functions["Functions"]:
        functionName = function["FunctionName"]
        # print("FunctionName: " + functionName)
        functionVpcConfig = ""
        functionSecurityGroupIds = ""
        try:
            functionVpcConfig = function["VpcConfig"]
            functionSecurityGroupIds = functionVpcConfig["SecurityGroupIds"]
            for j in functionSecurityGroupIds:
                if j not in security_groups_in_use:
                    security_groups_in_use.append(j)
                if j in security_groups_with_bad_ports and j not in bad_port_security_groups_in_use:
                    bad_port_security_groups_in_use.append(j)
        except KeyError:
            continue
        # finally:
        #     print(functionSecurityGroupIds)
    if nextMarker == "":
        break
    else:
        lambda_functions = lambda_client.list_functions(Marker=nextMarker)

delete_candidates = []
bad_group_delete_candidates = []
for group in all_groups:
    if group not in security_groups_in_use:
        delete_candidates.append(group)

for group in security_groups_with_bad_ports:
    if group not in bad_port_security_groups_in_use:
        bad_group_delete_candidates.append(group)

if args.delete:
    print("We will now delete security groups identified to not be in use.")
    for group in delete_candidates:
        security_group = ec2.SecurityGroup(group)
        try:
            print("delete option commented out")
            # security_group.delete()
        except Exception as e:
            print(e)
            print(f"{security_group.group_name} requires manual remediation.")
else:
    print("The list of security groups to be removed is below.")
    print("Run this again with `-d` to remove them")
    for group in sorted(delete_candidates):
        print("   " + group)
    print("---------------")
    print("List of bad security groups in use:")
    print("---------------")
    for group in sorted(set(bad_port_security_groups_in_use)):
        print("   " + group)
    print("---------------")
    print("List of bad security groups NOT used:")
    print("---------------")
    for group in sorted(set(bad_group_delete_candidates)):
        print("   " + group)


if len(delete_candidates) > 0:
    print("---------------")
    print("Activity Report")
    print("---------------")

    print(u"Total number of Security Groups evaluated: {0:d}".format(len(all_groups)))
    print(u"Total number of EC2 Instances evaluated: {0:d}".format(len(reservations)))
    print(u"Total number of Load Balancers evaluated: {0:d}".format(len(elb_dict['LoadBalancerDescriptions']) +
                                                                    len(elb2_dict['LoadBalancers'])))
    print(u"Total number of RDS Instances evaluated: {0:d}".format(len(rds_dict['DBInstances'])))
    print(u"Total number of Network Interfaces evaluated: {0:d}".format(len(eni_dict['NetworkInterfaces'])))
    print(u"Total number of Security Groups in-use evaluated: {0:d}".format(len(security_groups_in_use)))
    print(u"Total number of Bad Security Groups in-use evaluated: {0:d}".format(len(set(bad_port_security_groups_in_use))))
    if args.delete:
        print(u"Total number of Unused Security Groups deleted: {0:d}".format(len(delete_candidates)))
        print(u"Total number of Unused Bad Security Groups deleted: {0:d}".format(len(set(bad_group_delete_candidates))))
    else:
        print(u"Total number of Unused Security Groups targeted for removal: {0:d}".format(len(delete_candidates)))
        print(u"Total number of Unused Bad Security Groups targeted for removal: {0:d}".format(len(set(bad_group_delete_candidates))))

        # For each security group in the total list, if not in the "used" list, flag for deletion
        # If running with a "--delete" flag, delete the ones flagged.
