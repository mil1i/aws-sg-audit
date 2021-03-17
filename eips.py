import boto3
import argparse
import os

try:
    default_region = os.environ["AWS_DEFAULT_REGION"]
except KeyError:
    default_region = "us-east-1"


# Get a full list of the available regions
session = boto3.Session(profile_name='qq-readonly')
client = session.client('ec2')
regions_dict = client.describe_regions()
region_list = [region['RegionName'] for region in regions_dict['Regions']]

# Parse arguments
parser = argparse.ArgumentParser(description="Show unused security groups")
parser.add_argument("-r", "--region", type=str, default="us-east-1",
                    help="The default region is us-east-1. The list of available regions are as follows: "
                         f"{sorted(region_list)}")
# parser.add_argument("-d", "--delete", help="delete security groups from AWS", action="store_true")
args = parser.parse_args()

client = session.client('ec2', region_name=args.region)

unassociated_eip = list(dict())
eip_dict = client.describe_addresses()
for e in eip_dict["Addresses"]:
    if "InstanceId" not in e or e["InstanceId"] == "" or e["InstanceId"] is None:
        unassociated_eip.append(e)

print(unassociated_eip)