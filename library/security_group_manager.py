

class SecurityGroupManager:
    def __init__(self, args, session):
        self.args = args
        self.aws_connection = session
        self.aws_region = args.region
        self.bad_ports = args.ports
        self.all_groups = list()
        self.all_security_groups = list()
        self.groups_in_use = list()
        self.bad_groups = list()
        self.bad_groups_in_use = list()
        self.delete_groups = list()
        self.delete_bad_groups = list()
        self.instances = list()
        self.instances_security_groups = list()
        self.elastic_network_instances = list()
        self.eni_security_groups = list()
        self.ecs_clusters = list()
        self.ecs_services = list()
        self.ecs_security_groups = list()
        self.elb_lbs = list()
        self.elb_security_groups = list()
        self.elbv2_lbs = list()
        self.elbv2_security_groups = list()
        self.rds_instances = list()
        self.rds_security_groups = list()
        self.lambda_functions = list()
        self.lambda_security_groups = list()
        self.marked_sgs = list()
        self.restore_sgs = list()

    # Get ALL security groups names
    def get_all_security_groups(self):
        ec2_client = self.aws_connection.client("ec2", region_name=self.aws_region)
        paginator = ec2_client.get_paginator("describe_security_groups")
        security_groups_dict = paginator.paginate().build_full_result()
        self.all_security_groups = security_groups_dict["SecurityGroups"]
        for group in self.all_security_groups:
            if group["GroupName"] in self.args.equals or group["GroupName"].startswith(tuple(self.args.startswith)) \
                    or group["GroupName"].endswith(tuple(self.args.endswith)):
                self.groups_in_use.append(group["GroupId"])
            for perm in group["IpPermissions"]:
                try:
                    if perm["FromPort"] == perm["ToPort"]:
                        if perm["ToPort"] in self.bad_ports and "0.0.0.0/0" in [ip["CidrIp"] for ip in perm["IpRanges"]]:
                            self.bad_groups.append(group["GroupId"])
                    elif any([bp in range(perm["FromPort"], perm['ToPort']) for bp in self.bad_ports]) \
                            and "0.0.0.0/0" in [ip["CidrIp"] for ip in perm["IpRanges"]]:
                        self.bad_groups.append(group['GroupId'])
                except KeyError:
                    if perm["IpProtocol"] == "-1" and "0.0.0.0/0" in [ip["CidrIp"] for ip in perm["IpRanges"]]:
                        self.bad_groups.append(group["GroupId"])
            self.all_groups.append(group["GroupId"])
        return self.all_groups

    def _add_to_groups_in_use(self, sg):
        if sg not in self.groups_in_use:
            self.groups_in_use.append(sg)

    def _find_bad_security_groups(self, sg):
        if sg in self.bad_groups and sg not in self.bad_groups_in_use:
            self.bad_groups_in_use.append(sg)

    @staticmethod
    def _populate_xlsx_column(sheet, column_num, resource, column_id, column_format):
        row = 0
        if len(resource) > 0:
            sheet.write(row, column_num, column_id, column_format)
            row += 1
            colwidth = len(column_id)
            for ins in resource:
                sheet.write(row, column_num, ins)
                if len(ins) > colwidth:
                    colwidth = len(ins)
                row += 1
            sheet.set_column(column_num, column_num, colwidth + 1)
            return column_num + 1

    def get_resources_using_group(self, reportdir):
        try:
            import xlsxwriter
        except ImportError as e:
            xlsxwriter = None
            exit(f"Missing required dependency: {e.name}")
        import os
        workbook = xlsxwriter.Workbook(os.path.join(os.path.abspath(reportdir), "sg-bad-groups.xlsx"))
        column_title_format = workbook.add_format()
        column_title_format.set_bold(True)
        column_title_format.set_bg_color("lime")
        print("Generating report containing security groups with bad rules...")
        resources_using = dict()
        for sg in self.bad_groups_in_use:
            worksheet = workbook.add_worksheet(sg)
            col = 0
            resources_using[sg] = dict()
            resources_using[sg]["instances"] = list()
            resources_using[sg]["eni"] = list()
            resources_using[sg]["ecs"] = list()
            resources_using[sg]["elb"] = list()
            resources_using[sg]["elbv2"] = list()
            resources_using[sg]["rds"] = list()
            resources_using[sg]["lambda"] = list()
            # EC2 Instances
            for inst in self.instances_security_groups:
                for i, sgs in inst.items():
                    if sg in sgs:
                        resources_using[sg]["instances"].append(i)
            col = self._populate_xlsx_column(sheet=worksheet, column_num=col, resource=resources_using[sg]["instances"],
                                             column_id="EC2 InstanceId", column_format=column_title_format)
            # Elastic Network Interfaces
            for i in self.eni_security_groups:
                for e, sgs in i.items():
                    if sg in sgs:
                        resources_using[sg]["eni"].append(e)
            col = self._populate_xlsx_column(sheet=worksheet, column_num=col, resource=resources_using[sg]["eni"],
                                             column_id="ENI Id", column_format=column_title_format)
            # ECS Services
            for svc in self.ecs_services:
                for s, sgs in svc.items():
                    if sg in sgs:
                        resources_using[sg]["ecs"].append(s)
            col = self._populate_xlsx_column(sheet=worksheet, column_num=col, resource=resources_using[sg]["ecs"],
                                             column_id="ECS Service", column_format=column_title_format)
            # ELBv1
            for elb in self.elb_security_groups:
                for e1, sgs in elb.items():
                    if sg in sgs:
                        resources_using[sg]["elb"].append(e1)
            col = self._populate_xlsx_column(sheet=worksheet, column_num=col, resource=resources_using[sg]["elb"],
                                             column_id="ELB Id", column_format=column_title_format)
            # ELBv2
            for elbv2 in self.elbv2_security_groups:
                for e2, sgs in elbv2.items():
                    if sg in sgs:
                        resources_using[sg]["elbv2"].append(e2)
            col = self._populate_xlsx_column(sheet=worksheet, column_num=col, resource=resources_using[sg]["elbv2"],
                                             column_id="ELBv2 Id", column_format=column_title_format)
            # RDS Instances
            for rdi in self.rds_security_groups:
                for r, sgs in rdi.items():
                    if sg in sgs:
                        resources_using[sg]["rds"].append(r)
            col = self._populate_xlsx_column(sheet=worksheet, column_num=col, resource=resources_using[sg]["rds"],
                                             column_id="RDS InstanceId", column_format=column_title_format)
            # Lambda Functions
            for lf in self.lambda_security_groups:
                for f, sgs in lf.items():
                    if sg in sgs:
                        resources_using[sg]["lambda"].append(f)
            col = self._populate_xlsx_column(sheet=worksheet, column_num=col, resource=resources_using[sg]["lambda"],
                                             column_id="Lambda Function", column_format=column_title_format)
        workbook.close()
        print(f"Report generated and saved to: {os.path.join(os.path.abspath(reportdir), 'sg-bad-groups.xlsx')}")
        return resources_using

    def get_unused_groups(self):
        self.get_all_security_groups()
        self.get_instance_security_groups()
        self.get_eni_security_groups()
        self.get_ecs_services_security_groups()
        self.get_elb_security_groups()
        self.get_elbv2_security_groups()
        self.get_rds_security_groups()
        self.get_lambda_security_groups()
        for unused_group in self.all_groups:
            if unused_group not in self.groups_in_use:
                self.delete_groups.append(unused_group)

        for unused_bad_group in self.bad_groups:
            if unused_bad_group not in self.bad_groups_in_use:
                self.delete_bad_groups.append(unused_bad_group)
        return self.delete_groups, self.delete_bad_groups

    # Get all security groups that have the tag "MarkedForDeletion = true"
    def get_marked_for_deletion_groups(self):
        self.get_all_security_groups()
        for sg in self.all_security_groups:
            try:
                for tag in sg["Tags"]:
                    if tag["Key"] == "MarkedForDeletion" and tag["Value"] == "true":
                        self.marked_sgs.append(sg)
            except KeyError as err:
                continue
        return self.marked_sgs

    @staticmethod
    def is_marked_for_deletion(ec2, sg):
        sg_tag_collector = ec2.describe_security_groups(GroupIds=[sg["GroupId"]])
        try:
            sg_tags = sg_tag_collector["SecurityGroups"][0]["Tags"]
            if "MarkedForDeletion" in [v for e in sg_tags for v in e.values()]:
                for tag in sg_tags:
                    if tag["Key"] == "MarkedForDeletion" and tag["Value"] == "true":
                        return True
            return False
        except KeyError:
            return False

    def _get_instances(self):
        ec2_client = self.aws_connection.client("ec2", region_name=self.aws_region)
        paginator = ec2_client.get_paginator("describe_instances")
        instances_dict = paginator.paginate().build_full_result()
        reservations = instances_dict["Reservations"]
        for i in reservations:
            for inst in i["Instances"]:
                self.instances.append(inst)
        return self.instances

    # Get all security groups used by instances
    def get_instance_security_groups(self):
        for inst in self._get_instances():
            sg_in_group = list()
            for sg in inst["SecurityGroups"]:
                self._add_to_groups_in_use(sg["GroupId"])
                self._find_bad_security_groups(sg["GroupId"])
                sg_in_group.append(sg["GroupId"])
            self.instances_security_groups.append({inst["InstanceId"]: sg_in_group})
        return self.instances_security_groups

    def _get_elastic_network_interfaces(self):
        ec2_client = self.aws_connection.client("ec2", region_name=self.aws_region)
        paginator = ec2_client.get_paginator("describe_network_interfaces")
        eni_dict = paginator.paginate().build_full_result()
        self.elastic_network_instances = [i for i in eni_dict["NetworkInterfaces"]]
        return self.elastic_network_instances

    # Security Groups in use by Network Interfaces
    def get_eni_security_groups(self):
        for i in self._get_elastic_network_interfaces():
            sg_in_group = list()
            for sg in i["Groups"]:
                self._add_to_groups_in_use(sg["GroupId"])
                self._find_bad_security_groups(sg["GroupId"])
                sg_in_group.append(sg["GroupId"])
            self.eni_security_groups.append({i["NetworkInterfaceId"]: sg_in_group})
        return self.eni_security_groups

    def _get_elb(self):
        elb_client = self.aws_connection.client("elb", region_name=self.aws_region)
        paginator = elb_client.get_paginator("describe_load_balancers")
        elb_dict = paginator.paginate().build_full_result()
        self.elb_lbs = [elb for elb in elb_dict["LoadBalancerDescriptions"]]
        return self.elb_lbs

    # Security groups used by classic ELBs
    def get_elb_security_groups(self):
        for lb in self._get_elb():
            sg_in_group = list()
            for sg in lb["SecurityGroups"]:
                self._add_to_groups_in_use(sg)
                self._find_bad_security_groups(sg)
                sg_in_group.append(sg)
            self.elb_security_groups.append({lb["LoadBalancerName"]: sg_in_group})
        return self.elb_security_groups

    def _get_elbv2(self):
        elbv2_client = self.aws_connection.client("elbv2", region_name=self.aws_region)
        paginator = elbv2_client.get_paginator("describe_load_balancers")
        elbv2_dict = paginator.paginate().build_full_result()
        self.elbv2_lbs = [alb for alb in elbv2_dict["LoadBalancers"]]
        return self.elbv2_lbs

    # Security groups used by ALBs
    def get_elbv2_security_groups(self):
        for lb in self._get_elbv2():
            sg_in_group = list()
            try:
                # if i["Type"] == "network":
                #     continue
                for sg in lb["SecurityGroups"]:
                    self._add_to_groups_in_use(sg)
                    self._find_bad_security_groups(sg)
                    sg_in_group.append(sg)
            except KeyError:
                pass
            self.elbv2_security_groups.append({lb["LoadBalancerName"]: sg_in_group})
        return self.elbv2_security_groups

    def _get_rds_instances(self):
        rds_client = self.aws_connection.client("rds", region_name=self.aws_region)
        paginator = rds_client.get_paginator("describe_db_instances")
        rds_dict = paginator.paginate().build_full_result()
        self.rds_instances = [rds for rds in rds_dict["DBInstances"]]
        return self.rds_instances

    # Security groups used by RDS
    def get_rds_security_groups(self):
        for rdi in self._get_rds_instances():
            sg_in_group = list()
            for sg in rdi["VpcSecurityGroups"]:
                self._add_to_groups_in_use(sg["VpcSecurityGroupId"])
                self._find_bad_security_groups(sg["VpcSecurityGroupId"])
                sg_in_group.append(sg["VpcSecurityGroupId"])
            self.rds_security_groups.append({rdi["DBInstanceIdentifier"]: sg_in_group})
        return self.rds_security_groups

    def _get_lambda_functions(self):
        lambda_client = self.aws_connection.client("lambda", region_name=self.aws_region)
        paginator = lambda_client.get_paginator('list_functions')
        lambda_functions = paginator.paginate().build_full_result()
        self.lambda_functions = [function for function in lambda_functions["Functions"]]
        return self.lambda_functions

    # Security groups used by Lambdas
    def get_lambda_security_groups(self):
        for function in self._get_lambda_functions():
            functionName = function["FunctionName"]
            sg_in_group = list()
            try:
                functionVpcConfig = function["VpcConfig"]
                functionSecurityGroupIds = functionVpcConfig["SecurityGroupIds"]
                for sg in functionSecurityGroupIds:
                    self._add_to_groups_in_use(sg)
                    self._find_bad_security_groups(sg)
                    sg_in_group.append(sg)
                self.lambda_security_groups.append({functionName: sg_in_group})
            except KeyError:
                continue
            # finally:
            #     print(functionSecurityGroupIds)
        return self.lambda_security_groups

    # Get ECS cluster/service/tasks information
    def _get_ecs_services(self):
        ecs_client = self.aws_connection.client("ecs", region_name=self.aws_region)
        paginator_cluster = ecs_client.get_paginator("list_clusters")
        paginator_services = ecs_client.get_paginator("list_services")
        ecs_clusters_dict = paginator_cluster.paginate().build_full_result()
        self.ecs_clusters = [cluster for cluster in ecs_clusters_dict["clusterArns"]]
        for cluster in self.ecs_clusters:
            cluster_services = paginator_services.paginate(cluster=cluster).build_full_result()
            for service in cluster_services["serviceArns"]:
                service_config = ecs_client.describe_services(cluster=cluster, services=[service])
                if len(service_config["services"]) > 0:
                    self.ecs_services.append({service: service_config["services"][0]})
        return self.ecs_services

    # Security groups used by ECS Services
    def get_ecs_services_security_groups(self):
        for service in self._get_ecs_services():
            for svc in service:
                sgs_service = []
                try:
                    sgs_service = [sg for sg in
                                   service[svc]["networkConfiguration"]["awsvpcConfiguration"]["securityGroups"]]
                except KeyError:
                    pass
                sgs_deployments = []
                try:
                    svc_deployments = [deployment["networkConfiguration"]["awsvpcConfiguration"]["securityGroups"]
                                       for deployment in service[svc]["deployments"]]
                    sgs_deployments = [sg for sg in svc_deployments]
                except KeyError:
                    pass
                if sgs_deployments and sgs_service:
                    for sg in sgs_deployments:
                        sgs_service.extend(sg)
                    for sg in set(sgs_service):
                        self._add_to_groups_in_use(sg)
                        self._find_bad_security_groups(sg)
                        self.ecs_security_groups.append(sg)
        return self.ecs_security_groups

    # Dump security groups to file
    @staticmethod
    def dump_to_file(sgdir, sg):
        import json
        import os
        try:
            fobj = open(os.path.join(os.path.abspath(sgdir), f"{sg['GroupId']}.{sg['GroupName']}.json"), "w+")
            fobj.truncate()
            json.dump(sg, fobj)
        except FileExistsError as err:
            exit(f"Unable to create file:\n {err}")

    # Read security group from json dump
    def load_from_file(self, sgdir):
        import json
        import glob
        import os
        try:
            files = [f for f in glob.glob(os.path.join(os.path.abspath(sgdir), "*.json"))]
            for file in files:
                fobj = open(file, "r")
                sgobj = json.load(fobj)
                self.restore_sgs.append(sgobj)
            return self.restore_sgs
        except FileNotFoundError as err:
            exit(f"Unable to locate files:\n {err}")

    # Restore security groups
    def restore_security_groups(self, ec2):
        import botocore.exceptions
        for sg in self.restore_sgs:
            load_sg = ec2.SecurityGroup(sg["GroupId"])
            try:
                load_sg.create_tags(
                    DryRun=self.args.dryrun,
                    Tags=[
                        {
                            "Key": "MarkedForDeletion",
                            "Value": "false"
                        },
                    ]
                )
            except botocore.exceptions.ClientError as error:
                if error.response["Error"]["Code"] == 'DryRunOperation':
                    print(f"DryRunOperation - CreateTags: {error.response['Error']['Message']}")
            if self.args.restore_ingress_rules:
                try:
                    load_sg.authorize_ingress(
                        DryRun=self.args.dryrun,
                        IpPermissions=sg["IpPermissions"]
                    )
                except botocore.exceptions.ClientError as error:
                    if error.response["Error"]["Code"] == 'DryRunOperation':
                        print(f"DryRunOperation - AuthorizeIngress: {error.response['Error']['Message']}\n")
            print(f"Restored security group: \'{sg['GroupId']}\'")

    # Mark for Deletion preparation
    def mark_for_deletion(self, ec2, sg):
        import botocore.exceptions
        tag_client = self.aws_connection.client("ec2", region_name=self.aws_region)
        if self.is_marked_for_deletion(tag_client, sg):
            print(f"security group already marked for deletion: \'{sg['GroupId']}\'")
            return
        marked_sg = ec2.SecurityGroup(sg["GroupId"])
        try:
            print(f"creating tag to mark security group for deletion: \'{sg['GroupId']}\'")
            marked_sg.create_tags(
                DryRun=self.args.dryrun,
                Tags=[
                    {
                        "Key": "MarkedForDeletion",
                        "Value": "true"
                    },
                ]
            )
        except botocore.exceptions.ClientError as error:
            if error.response["Error"]["Code"] == 'DryRunOperation':
                print(f"DryRunOperation - CreateTags: {error.response['Error']['Message']}")
        if self.args.remove_ingress_rules:
            try:
                marked_sg.revoke_ingress(
                    DryRun=self.args.dryrun,
                    IpPermissions=sg["IpPermissions"]
                )
            except botocore.exceptions.ClientError as error:
                if error.response["Error"]["Code"] == 'DryRunOperation':
                    print(f"DryRunOperation - RevokeIngress: {error.response['Error']['Message']}\n")
