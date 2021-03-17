#!/usr/bin/env python3

import boto3
import argparse
import os


def main():
    try:
        default_region = os.environ["AWS_DEFAULT_REGION"]
    except KeyError:
        default_region = "us-east-1"

    session = boto3.Session(profile_name='qq-readonly')
    # Get a full list of the available regions
    tmpClient = session.client('ec2')
    regions_dict = tmpClient.describe_regions()
    region_list = [region['RegionName'] for region in regions_dict['Regions']]

    # Parse arguments
    parser = argparse.ArgumentParser(description="Show unused security groups")
    parser.add_argument("-r", "--region", type=str, default=default_region,
                        help="The default region is us-east-1. The list of available regions are as follows: "
                             f"{sorted(region_list)}")
    parser.add_argument("-d", "--delete", help="delete security groups from AWS", action="store_true")
    args = parser.parse_args()

    bad_ports = [20, 21, 1433, 1434, 3306, 3389, 4333, 5432, 5500]
    all_groups, used_groups, bad_groups = get_all_security_groups(session, args.region, bad_ports)
    used_bad_groups = []

    used_groups, used_bad_groups, instance_count = get_instance_security_groups(session, args.region, used_groups,
                                                                                bad_groups, used_bad_groups)
    used_groups, used_bad_groups, eni_count = get_eni_security_groups(session, args.region, used_groups,
                                                                      bad_groups, used_bad_groups)
    used_groups, used_bad_groups, clb_count = get_clb_security_groups(session, args.region, used_groups,
                                                                      bad_groups, used_bad_groups)
    used_groups, used_bad_groups, alb_count = get_alb_security_groups(session, args.region, used_groups,
                                                                      bad_groups, used_bad_groups)
    used_groups, used_bad_groups, rds_count = get_rds_security_groups(session, args.region, used_groups,
                                                                      bad_groups, used_bad_groups)
    used_groups, used_bad_groups, lambda_count = get_lambda_security_groups(session, args.region, used_groups,
                                                                            bad_groups, used_bad_groups)

    sg_delete_candidates = []
    bad_sg_delete_candidates = []
    for unusedgroup in all_groups:
        if unusedgroup not in used_groups:
            sg_delete_candidates.append(unusedgroup)

    for unusedbadgroup in bad_groups:
        if unusedbadgroup not in used_bad_groups:
            bad_sg_delete_candidates.append(unusedbadgroup)

    if args.delete:
        print("We will now delete security groups identified to not be in use.")
        for group in sg_delete_candidates:
            ec2resource = session.resource('ec2', region_name=args.region)
            security_group = ec2resource.SecurityGroup(group)
            try:
                print("delete option commented out")
                # security_group.delete()
            except Exception as e:
                print(e)
                print(f"{security_group.group_name} requires manual remediation.")
    else:
        print("The list of security groups to be removed is below.")
        print("Run this again with `-d` to remove them")
        for group in sorted(sg_delete_candidates):
            print("   " + group)
        print("---------------")
        print("List of bad security groups in use:")
        print("---------------")
        for group in sorted(set(used_bad_groups)):
            print("   " + group)
        print("---------------")
        print("List of bad security groups NOT used:")
        print("---------------")
        for group in sorted(set(bad_sg_delete_candidates)):
            print("   " + group)

    if len(sg_delete_candidates) > 0:
        print("---------------")
        print("Activity Report")
        print("---------------")

        print(u"Total number of Security Groups evaluated: {0:d}".format(len(all_groups)))
        print(u"Total number of EC2 Instances evaluated: {0:d}".format(instance_count))
        print(u"Total number of Load Balancers evaluated: {0:d}".format(len(clb_count) + len(alb_count)))
        print(u"Total number of RDS Instances evaluated: {0:d}".format(len(rds_count)))
        print(u"Total number of Network Interfaces evaluated: {0:d}".format(len(eni_count)))
        print(u"Total number of Lambda Functions evaluated: {0:d}".format(len(lambda_count)))
        print(u"Total number of Security Groups in-use evaluated: {0:d}".format(len(used_groups)))
        print(u"Total number of Bad Security Groups in-use evaluated: {0:d}".format(
            len(set(used_bad_groups))))
        if args.delete:
            print(u"Total number of Unused Security Groups deleted: {0:d}".format(len(sg_delete_candidates)))
            print(u"Total number of Unused Bad Security Groups deleted: {0:d}".format(
                len(set(bad_sg_delete_candidates))))
        else:
            print(u"Total number of Unused Security Groups targeted for removal: {0:d}".
                  format(len(sg_delete_candidates)))
            print(u"Total number of Unused Bad Security Groups targeted for removal: {0:d}".
                  format(len(set(bad_sg_delete_candidates))))

            # For each security group in the total list, if not in the "used" list, flag for deletion
            # If running with a "--delete" flag, delete the ones flagged.


def get_all_security_groups(sesh, region, badports):
    # Get ALL security groups names
    ec2_client = sesh.client('ec2', region_name=region)
    paginator = ec2_client.get_paginator('describe_security_groups')
    security_groups_dict = paginator.paginate().build_full_result()
    security_groups = security_groups_dict['SecurityGroups']
    all_security_groups = []
    used_security_groups = []
    badports_security_groups = []
    for groupobj in security_groups:
        if groupobj['GroupName'] == 'default' or groupobj['GroupName'].startswith('d-') \
                or groupobj['GroupName'].startswith('AWS-OpsWorks-'):
            used_security_groups.append(groupobj['GroupId'])
        for perm in groupobj['IpPermissions']:
            try:
                if perm['FromPort'] == perm['ToPort']:
                    if perm['ToPort'] in badports and '0.0.0.0/0' in [ip['CidrIp'] for ip in perm['IpRanges']]:
                        badports_security_groups.append(groupobj['GroupId'])
                elif any([bp in range(perm['FromPort'], perm['ToPort']) for bp in badports]) \
                        and '0.0.0.0/0' in [ip['CidrIp'] for ip in perm['IpRanges']]:
                    badports_security_groups.append(groupobj['GroupId'])
            except KeyError:
                if perm['IpProtocol'] == '-1' and '0.0.0.0/0' in [ip['CidrIp'] for ip in perm['IpRanges']]:
                    badports_security_groups.append(groupobj['GroupId'])
        all_security_groups.append(groupobj['GroupId'])
    return all_security_groups, used_security_groups, badports_security_groups


def add_to_groups_in_use(sg, usedsgs):
    if sg not in usedsgs:
        usedsgs.append(sg)


def find_bad_security_groups(sg, all_badsgs, used_badsgs):
    if sg in all_badsgs and sg not in used_badsgs:
        used_badsgs.append(sg)


def get_instance_security_groups(sesh, region, used_sgs, all_bp_sgs, used_bp_sgs):
    # Get all security groups used by instances
    ec2_client = sesh.client('ec2', region_name=region)
    paginator = ec2_client.get_paginator('describe_instances')
    instances_dict = paginator.paginate().build_full_result()
    reservations = instances_dict['Reservations']
    instcount = 0
    for i in reservations:
        for j in i['Instances']:
            instcount += 1
            for k in j['SecurityGroups']:
                add_to_groups_in_use(k['GroupId'], used_sgs)
                find_bad_security_groups(k['GroupId'], all_bp_sgs, used_bp_sgs)
    return used_sgs, used_bp_sgs, instcount


def get_eni_security_groups(sesh, region, used_sgs, all_bp_sgs, used_bp_sgs):
    # Security Groups in use by Network Interfaces
    ec2_client = sesh.client('ec2', region_name=region)
    paginator = ec2_client.get_paginator('describe_network_interfaces')
    eni_dict = paginator.paginate().build_full_result()
    for i in eni_dict['NetworkInterfaces']:
        for j in i['Groups']:
            add_to_groups_in_use(j['GroupId'], used_sgs)
            find_bad_security_groups(j['GroupId'], all_bp_sgs, used_bp_sgs)
    return used_sgs, used_bp_sgs, eni_dict['NetworkInterfaces']


def get_clb_security_groups(sesh, region, used_sgs, all_bp_sgs, used_bp_sgs):
    # Security groups used by classic ELBs
    elb_client = sesh.client('elb', region_name=region)
    paginator = elb_client.get_paginator('describe_load_balancers')
    elb_dict = paginator.paginate().build_full_result()
    for i in elb_dict['LoadBalancerDescriptions']:
        for j in i['SecurityGroups']:
            add_to_groups_in_use(j, used_sgs)
            find_bad_security_groups(j, all_bp_sgs, used_bp_sgs)
    return used_sgs, used_bp_sgs, elb_dict['LoadBalancerDescriptions']


def get_alb_security_groups(sesh, region, used_sgs, all_bp_sgs, used_bp_sgs):
    # Security groups used by ALBs
    elb2_client = sesh.client('elbv2', region_name=region)
    paginator = elb2_client.get_paginator('describe_load_balancers')
    elb2_dict = paginator.paginate().build_full_result()
    for i in elb2_dict['LoadBalancers']:
        try:
            # if i['Type'] == 'network':
            #     continue
            for j in i['SecurityGroups']:
                add_to_groups_in_use(j, used_sgs)
                find_bad_security_groups(j, all_bp_sgs, used_bp_sgs)
        except KeyError:
            pass
    return used_sgs, used_bp_sgs, elb2_dict['LoadBalancers']


def get_rds_security_groups(sesh, region, used_sgs, all_bp_sgs, used_bp_sgs):
    # Security groups used by RDS
    rds_client = sesh.client('rds', region_name=region)
    paginator = rds_client.get_paginator('describe_db_instances')
    rds_dict = paginator.paginate().build_full_result()
    for i in rds_dict['DBInstances']:
        for j in i['VpcSecurityGroups']:
            add_to_groups_in_use(j['VpcSecurityGroupId'], used_sgs)
            find_bad_security_groups(j['VpcSecurityGroupId'], all_bp_sgs, used_bp_sgs)
    return used_sgs, used_bp_sgs, rds_dict['DBInstances']


def get_lambda_security_groups(sesh, region, used_sgs, all_bp_sgs, used_bp_sgs):
    # Security groups used by Lambdas
    lambda_client = sesh.client('lambda', region_name=region)
    paginator = lambda_client.get_paginator('list_functions')
    lambda_functions = paginator.paginate().build_full_result()
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
                    add_to_groups_in_use(j, used_sgs)
                    find_bad_security_groups(j, all_bp_sgs, used_bp_sgs)
            except KeyError:
                continue
            # finally:
            #     print(functionSecurityGroupIds)
        if nextMarker == "":
            break
        else:
            lambda_functions = lambda_client.list_functions(Marker=nextMarker)
    return used_sgs, used_bp_sgs, lambda_functions["Functions"]


if __name__ == "__main__":
    main()
