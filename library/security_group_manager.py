

class SecurityGroupManager:
    def __init__(self, args, session):
        self.aws_connection = session
        self.aws_region = args.region
        self.bad_ports = args.ports
        self.all_groups = list()
        self.groups_in_use = list()
        self.bad_groups = list()
        self.bad_groups_in_use = list()
        self.delete_groups = list()
        self.delete_bad_groups = list()
        self.instances = list()
        self.instances_security_groups = list()
        self.elastic_network_instances = list()
        self.eni_security_groups = list()
        self.elb_lbs = list()
        self.elb_security_groups = list()
        self.elbv2_lbs = list()
        self.elbv2_security_groups = list()
        self.rds_instances = list()
        self.rds_security_groups = list()
        self.lambda_functions = list()
        self.lambda_security_groups = list()
        self.get_all_security_groups()
        self.get_instance_security_groups()
        self.get_eni_security_groups()
        self.get_elb_security_groups()
        self.get_elbv2_security_groups()
        self.get_rds_security_groups()
        self.get_lambda_security_groups()
        self.get_unused_groups()

    # Get ALL security groups names
    def get_all_security_groups(self):
        ec2_client = self.aws_connection.client("ec2", region_name=self.aws_region)
        paginator = ec2_client.get_paginator("describe_security_groups")
        security_groups_dict = paginator.paginate().build_full_result()
        security_groups = security_groups_dict["SecurityGroups"]
        for group in security_groups:
            if group["GroupName"] == "default" or group["GroupName"].startswith("d-") \
                    or group["GroupName"].startswith("AWS-OpsWorks-"):
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

    def get_resources_using_group(self):
        resources_using = dict()
        for sg in self.bad_groups_in_use:
            resources_using[sg] = dict()
            resources_using[sg]["instances"] = list()
            resources_using[sg]["eni"] = list()
            resources_using[sg]["elb"] = list()
            resources_using[sg]["elbv2"] = list()
            resources_using[sg]["rds"] = list()
            resources_using[sg]["lambda"] = list()
            print(f"------------")
            print(f"Resources utilizing {sg}:")
            print(f"------------")
            for inst in self.instances_security_groups:
                for i, sgs in inst.items():
                    if sg in sgs:
                        resources_using[sg]["instances"].append(i)
            if len(resources_using[sg]["instances"]) > 0:
                print(f"Instances:")
                print(f"------------")
                print(*resources_using[sg]["instances"], sep="\n")
                print(f"------------")
            for i in self.eni_security_groups:
                for e, sgs in i.items():
                    if sg in sgs:
                        resources_using[sg]["eni"].append(e)
            if len(resources_using[sg]["eni"]) > 0:
                print(f"Elastic Network Interfaces:")
                print(f"------------")
                print(*resources_using[sg]["eni"], sep="\n")
                print(f"------------")
            for elb in self.elb_security_groups:
                for e1, sgs in elb.items():
                    if sg in sgs:
                        resources_using[sg]["elb"].append(e1)
            if len(resources_using[sg]["elb"]) > 0:
                print(f"ELBs:")
                print(f"------------")
                print(*resources_using[sg]["elb"], sep="\n")
                print(f"------------")
            for elbv2 in self.elbv2_security_groups:
                for e2, sgs in elbv2.items():
                    if sg in sgs:
                        resources_using[sg]["elbv2"].append(e2)
            if len(resources_using[sg]["elbv2"]) > 0:
                print(f"ELBv2s:")
                print(f"------------")
                print(*resources_using[sg]["elbv2"], sep="\n")
                print(f"------------")
            for rdi in self.rds_security_groups:
                for r, sgs in rdi.items():
                    if sg in sgs:
                        resources_using[sg]["rds"].append(r)
            if len(resources_using[sg]["rds"]) > 0:
                print(f"RDS Instances:")
                print(f"------------")
                print(*resources_using[sg]["rds"], sep="\n")
                print(f"------------")
            for lf in self.lambda_security_groups:
                for f, sgs in lf.items():
                    if sg in sgs:
                        resources_using[sg]["lambda"].append(f)
            if len(resources_using[sg]["lambda"]) > 0:
                print(f"Lambda Functions:")
                print(f"------------")
                print(*resources_using[sg]["lambda"], sep="\n")
                print(f"------------")
        return resources_using

    def get_unused_groups(self):
        for unused_group in self.all_groups:
            if unused_group not in self.groups_in_use:
                self.delete_groups.append(unused_group)

        for unused_bad_group in self.bad_groups:
            if unused_bad_group not in self.bad_groups_in_use:
                self.delete_bad_groups.append(unused_bad_group)
        return self.delete_groups, self.delete_bad_groups

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
