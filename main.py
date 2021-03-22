#!/usr/bin/env python3

import boto3
import argparse
import os
from library.security_group_manager import SecurityGroupManager


def main():
    try:
        default_region = os.environ["AWS_DEFAULT_REGION"]
    except KeyError:
        default_region = "us-east-1"

    session = boto3.Session(profile_name="qq-readonly")
    # Get a full list of the available regions
    tmpClient = session.client("ec2")
    regions_dict = tmpClient.describe_regions()
    region_list = [region["RegionName"] for region in regions_dict["Regions"]]

    # Parse arguments
    parser = argparse.ArgumentParser(description="Show unused security groups")
    parser.add_argument("-r", "--region", type=str, default=default_region,
                        help="The default region is us-east-1. The list of available regions are as follows: "
                             f"{sorted(region_list)}")
    parser.add_argument("-d", "--delete", help="delete security groups from AWS", action="store_true")
    args = parser.parse_args()

    sg_manager = SecurityGroupManager(session, args.region)

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


if __name__ == "__main__":
    main()
