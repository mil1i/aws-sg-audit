#!/usr/bin/env python3

import boto3
import botocore.exceptions
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
    parser.add_argument("--outdir", type=str, default=None, help="Directory to dump security groups in json format")
    parser.add_argument("--restore", type=str, default=None, help="Directory to use to restore SecurityGroups from")
    parser.add_argument("-d", "--delete", help="Delete security groups from AWS", action="store_true")
    parser.add_argument("-m", "--mark", help="Mark security group for removal prior to deleting", action="store_true")
    parser.add_argument("--dryrun", help="Enable the DryRun flag to not make changes to any resources",
                        action="store_true")
    args = parser.parse_args()

    if args.mark and not args.outdir:
        exit("Please specify a directory to backup security groups to before marking for deletion")

    if args.profile:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
    else:
        session = boto3.Session(region_name=args.region)

    sg_manager = SecurityGroupManager(args, session)

    # TODO: Remove me and line below
    # sg_manager.get_ecs_services_security_groups()

    if args.delete:
        sg_manager.get_marked_for_deletion_groups()
        ec2resource = session.resource("ec2", region_name=args.region)
        for sg in sg_manager.marked_sgs:
            delete_sg = ec2resource.SecurityGroup(sg["GroupId"])
            delete_sg.delete(DryRun=args.dryrun)
        exit(f"Deleted {len(sg_manager.marked_sgs)} security groups")

    if args.restore:
        sg_manager.load_from_file(args.restore)
        ec2resource = session.resource("ec2", region_name=args.region)
        sg_manager.restore_security_groups(ec2resource)
        exit(f"Completed restoring security groups from '{args.restore}'")

    sg_manager.get_unused_groups()

    if args.outdir:
        sg_manager.get_resources_using_group()
        ec2resource = session.resource("ec2", region_name=args.region)
        for sg in sg_manager.all_security_groups:
            if sg["GroupId"] in sg_manager.delete_bad_groups or sg["GroupId"] in sg_manager.delete_groups:
                sg_manager.dump_to_file(args.outdir, sg)
                if args.mark:
                    print(f"Updating security group to be marked for deletion: \'{sg['GroupId']}\'")
                    sg_manager.mark_for_deletion(ec2resource, sg)

    if len(set(sg_manager.delete_groups)) > 0:
        #     print("The list of security groups to be removed is below.")
        #     print("Run this again with `-d` to remove them")
        #     for group in sorted(set(sg_manager.delete_groups)):
        #         print("   " + group)
        #     print("---------------")
        #     print("List of bad security groups in use:")
        #     print("---------------")
        #     for group in sorted(set(sg_manager.bad_groups_in_use)):
        #         print("   " + group)
        #     print("---------------")
        #     print("List of bad security groups NOT used:")
        #     print("---------------")
        #     for group in sorted(set(sg_manager.delete_bad_groups)):
        #         print("   " + group)
        print("---------------")
        print("Activity Report")
        print("---------------")

        print(u"Total number of Security Groups evaluated: {0:d}".format(len(set(sg_manager.all_groups))))
        print(u"Total number of EC2 Instances evaluated: {0:d}".format(len(sg_manager.instances)))
        print(u"Total number of ECS Service evaluated: {0:d}".format(len(sg_manager.instances)))
        print(u"Total number of Load Balancers evaluated: {0:d}".format(len(sg_manager.elb_lbs) +
                                                                        len(sg_manager.elbv2_lbs)))
        print(u"Total number of RDS Instances evaluated: {0:d}".format(len(sg_manager.rds_instances)))
        print(u"Total number of Network Interfaces evaluated: {0:d}".format(len(sg_manager.elastic_network_instances)))
        print(u"Total number of Lambda Functions evaluated: {0:d}".format(len(sg_manager.lambda_functions)))
        print(u"Total number of Security Groups in-use evaluated: {0:d}".format(len(set(sg_manager.groups_in_use))))
        print(u"Total number of Bad Security Groups in-use evaluated: {0:d}".format(
            len(set(sg_manager.bad_groups_in_use))))
        print(u"Total number of Unused Security Groups targeted for removal: {0:d}".
              format(len(set(sg_manager.delete_groups))))
        print(u"Total number of Unused Bad Security Groups targeted for removal: {0:d}".
              format(len(set(sg_manager.delete_bad_groups))))


if __name__ == "__main__":
    main()
