#!/usr/bin/env python3

import boto3
import argparse
import os
from library.security_group_manager import SecurityGroupManager


def main():
    default_region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
    default_profile = os.getenv("AWS_PROFILE")

    # Parse arguments
    parser = argparse.ArgumentParser(description="Show unused security groups")
    parser.add_argument("-r", "--region", type=str, default=default_region, help="The default region is us-east-1.")
    parser.add_argument("-p", "--ports", type=int, nargs="+",
                        default=[20, 21, 1433, 1434, 3306, 3389, 4333, 5432, 5500],
                        help="Specify \"Bad Ports\" that you want to filter for. (seperate by space)")
    parser.add_argument("--profile", type=str, default=default_profile, help="AWS Profile to use for making the call")
    parser.add_argument("-d", "--delete", help="delete security groups from AWS", action="store_true")
    args = parser.parse_args()

    if args.profile:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
    else:
        session = boto3.Session(region_name=args.region)

    sg_manager = SecurityGroupManager(args, session)
    if args.delete:
        print("We will now delete security groups identified to not be in use.")
        for group in sg_manager.delete_groups:
            ec2resource = session.resource("ec2", region_name=args.region)
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
        for group in sorted(set(sg_manager.delete_groups)):
            print("   " + group)
        print("---------------")
        print("List of bad security groups in use:")
        print("---------------")
        for group in sorted(set(sg_manager.bad_groups_in_use)):
            print("   " + group)
        print("---------------")
        print("List of bad security groups NOT used:")
        print("---------------")
        for group in sorted(set(sg_manager.delete_bad_groups)):
            print("   " + group)

    if len(set(sg_manager.delete_groups)) > 0:
        print("---------------")
        print("Activity Report")
        print("---------------")

        print(u"Total number of Security Groups evaluated: {0:d}".format(len(set(sg_manager.all_groups))))
        print(u"Total number of EC2 Instances evaluated: {0:d}".format(len(sg_manager.instances)))
        print(u"Total number of Load Balancers evaluated: {0:d}".format(len(sg_manager.elb_lbs) +
                                                                        len(sg_manager.elbv2_lbs)))
        print(u"Total number of RDS Instances evaluated: {0:d}".format(len(sg_manager.rds_instances)))
        print(u"Total number of Network Interfaces evaluated: {0:d}".format(len(sg_manager.elastic_network_instances)))
        print(u"Total number of Lambda Functions evaluated: {0:d}".format(len(sg_manager.lambda_functions)))
        print(u"Total number of Security Groups in-use evaluated: {0:d}".format(len(set(sg_manager.groups_in_use))))
        print(u"Total number of Bad Security Groups in-use evaluated: {0:d}".format(
            len(set(sg_manager.bad_groups_in_use))))
        if args.delete:
            print(u"Total number of Unused Security Groups deleted: {0:d}".format(len(set(sg_manager.delete_groups))))
            print(u"Total number of Unused Bad Security Groups deleted: {0:d}".format(
                len(set(sg_manager.delete_bad_groups))))
        else:
            print(u"Total number of Unused Security Groups targeted for removal: {0:d}".
                  format(len(set(sg_manager.delete_groups))))
            print(u"Total number of Unused Bad Security Groups targeted for removal: {0:d}".
                  format(len(set(sg_manager.delete_bad_groups))))

            # For each security group in the total list, if not in the "used" list, flag for deletion
            # If running with a "--delete" flag, delete the ones flagged.

    print(" ")
    sg_manager.get_resources_using_group()


if __name__ == "__main__":
    main()
