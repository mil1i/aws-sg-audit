# AWS Security Group Auditing

This script tool will use the AWS boto3 library to scan all security groups in a given account/region. It will check all resources that may be using each security group, and find any unused groups that can be deleted.

You can tell it to mark a security group for deletion, and to do so, you must also specify a directory to dump the json files for each security group as a backup.

To delete the security groups, the tool will only look for each security with the tag 'MarkForDeletion' with a value of 'true'. If the security group has a dependency, it will not delete and just pass to the next group.

Resources evaluated:
 - ELB 
 - ALB 
 - Lambda Function
 - RDS Instance
 - EC2 Instance
 - ECS Service
 - Elastic Network Interface (ENI)


 - **MISSING**: Security group rule entry check
 

This tool will also locate any security groups will port rules that are open to the public that should not be. The default list of security group rules checked are below, and can be overriden via a flag.

- 20, 21, 22, 389, 53, 445, 1433, 1434, 3306, 3389, 4333, 5432, 5500 and ALL PORTS (-1)

## Usage

### Arguments
```shell
# AWS Connection Authorization
--profile                 AWS Profile to use for making the call
-r, --region              The default region is us-east-1

# Ports to flag as bad ports if open to the public (0.0.0.0/0)
-p, --ports               Defaults to: [20, 21, 22, 389, 53, 445, 1433, 1434, 3306, 3389, 4333, 5432, 5500]
                          Specify ports deemed bad to be opened to the public to filter for. (seperate by space)


# White Listing security groups from removal
--equals                  Defaults to: ["default", "eks-cluster-default"]
                          Specify security group names to whitelist, exact match. (seperate by space)
--starts-with             Defaults to: ["d-", "AWS-OpsWorks-", "aurora-rds-"],
                          Specify security group names to whitelist, name starts with. (seperate by space)
--ends-with               Defaults to: ["-ecs-service-sg", "-ecs-task-sg"]
                          Specify security group names to whitelist, name ends with. (seperate by space)

# Output directory to backup security group rules before deletion (required if specifying --mark)
--outdir                  Directory to dump security groups in json format

# Directory containing json dump backup (see above) containing security groups to restore
--restore                 Directory containing json dump of security groups backed up in json format
--restore-ingress-rules   Will restore ingress rules to security group as specified from json backup files

# Output directory to save generated report to
--report                  Directory to create the security output report to


# Add tag to EC2 SecurityGroup to which this script checks for deleting security groups  
-m, --mark                Mark security group for removal prior to deleting
--remove-ingress-rules    Remove ALL ingress rules from security group when marking for deletion

# Will attempt to delete any security group that contains the flag "MarkedForDeletion" with a value of true
-d, --delete              Delete security groups from AWS

# Will use the boto3 dry-run functionality to determine if user has access to perform the function requested
--dryrun                  Enable the DryRun flag to not make changes to any resources

```


Run print report only:
```shell
python3 main.py [--dryrun]
```

Run xlsx report generation only:
```shell
python3 main.py --report <directory to generate report to> [--dryrun]
```

Backup only:

```shell
python3 main.py --outdir <directory to store json backups> [--dryrun]
```

Backup and tag/mark for deletions:

```shell
python3 main.py --outdir <directory to store json backups> --mark [--remove-ingress-rules] [--dryrun]
```

Restore groups marked for deletion (set "MarkedForDeletion" tag to false, and restore ingress rules if flag passed):

```shell
python3 main.py --restore <directory to store json backups> [--restore-ingress-rules] [--dryrun]
```

Delete security groups that were marked for deletion:

```shell
python3 main.py --delete [--dryrun]

```
