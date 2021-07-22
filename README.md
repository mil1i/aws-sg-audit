# main.py

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
 - **MISSING**: Security group rule


This tool will also locate any security groups will port rules that are open to the public that should not be. The default list of security group rules checked are below, and can be overriden via a flag.

- 20, 21, 1433, 1434, 3306, 3389, 4333, 5432, 5500 and ALL PORTS (-1)

## Usage


Run report only:
```shell
python3 main.py [--dryrun]
```

Backup only:

```shell
python3 main.py --outdir <directory to store json backups>
```

Backup and tag/mark for deletions:

```shell
python3 main.py --outdir <directory to store json backups> --mark [--dryrun]
```

Delete security groups that were marked for deletion:

```shell
python3 main.py --delete [--dryrun]

```
