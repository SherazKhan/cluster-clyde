import boto3
import sys
import glob
import time
import os

from utils import get_ip


class Cluster(object):


    def __init__(self, key_name='cluster_clyde_default', n_nodes=2, ami='ami-40d28157', instance_type='t2.micro'):
        """
        Constructor for cluster management object
        :param key_name: str - string of existing key name, if it doesn't exist it will be created.
                              this only refers to the name as: '<pem_key>.pem'
        :param n_nodes: int - Number of nodes to launch
        :param ami: str - Amazon Machine Image code
        :param instance_type: str - The type of EC2 instances to launch.
        """

        # set attributes
        self.ami = ami
        self.instance_type = instance_type
        self.key_name = key_name if not key_name.endswith('.pem') else key_name.replace('.pem', '')
        self.n_nodes = n_nodes
        self.instances = []
        self.security_group = None

        # Begin setting up and deploying cluster
        sys.stdout.write('Connecting to Boto3 EC2 resources...')
        self.ec2 = boto3.resource('ec2')
        self.client = boto3.client('ec2')
        sys.stdout.write('Done. Ready to start cluster. (cluster.start_cluster())\n')


    def start_cluster(self):
        """
        Performas all aspects of launching the cluster; checks keypairs, VPC, subnet, security group config, etc.
        :return:
        """
        sys.stdout.write('Checking keypair exists using key_name: "{}"...'.format(self.key_name))
        self.check_key()
        sys.stdout.write('Done.\n')

        sys.stdout.write('Checking for Cluster Clyde\'s Virtual Private Cloud (cluster_clyde_vpc) on AWS...')
        self.check_vpc()
        sys.stdout.write('Done.\n')

        sys.stdout.write('Checking for Cluster Clyde\'s Subnet in the VPC...')
        self.check_subnet()
        sys.stdout.write('Done.\n')

        sys.stdout.write('Validating security group...')
        self.check_security_group()
        sys.stdout.write('Done.\n')

        sys.stdout.write('Configuring security group...')
        self.configure_security_group()
        sys.stdout.write('Done configuring security group.\n')

        sys.stdout.write('Launching instances...')
        #self.launch_instances()
        sys.stdout.write('Done.\n')


    @staticmethod
    def make_credentials_file(aws_access_key_id, aws_secret_access_key):
        """
        Creates a credential file for user
        be careful, this overwrites any existing credential file
        @:param aws_access_key_id: str - Access key id given by AWS
        @:param aws_secret_access_key: str - secret key provided in association with key id from AWS
        """
        # TODO: Make it so we can append profiles to credential file instead of just [default] profile

        aws_dir = os.path.join(os.path.expanduser('~'), '.aws')

        # If .aws isn't a directory in home folder, make it
        if not os.path.isdir(aws_dir):
            os.mkdir(aws_dir)

        # write credential file with
        with open(os.path.join(aws_dir, 'credentials'), 'w') as f:
            f.write('''[default]\naws_access_key_id = {}\naws_secret_access_key = {}'''
                    .format(aws_access_key_id, aws_secret_access_key))
        return True


    @staticmethod
    def make_config_file(region):
        """
        Creates a config file for user
        be careful, this overwrites any existing config file
        @param region: str - AWS region ie. us-east-1
        """
        # TODO: Make it so we can append profiles to config file instead of just [default] profile

        aws_dir = os.path.join(os.path.expanduser('~'), '.aws')

        # If .aws isn't a directory in home folder, make it
        if not os.path.isdir(aws_dir):
            os.mkdir(aws_dir)

        # write config file with
        with open(os.path.join(aws_dir, 'config'), 'w') as f:
            f.write('''[default]\nregion = {}'''
                    .format(region))
        return True



    def check_subnet(self):
        '''Checks if subnet exists in VPC and sets as self.subnet'''
        subnets = [subnet for subnet in self.vpc.subnets.filter(Filters=[{'Name': 'tag:Name',
                                                                          'Values': ['cclyde_subnet',]}])]
        if subnets:
            sys.stdout.write('\n\tFound existing subnet...')
            self.subnet = subnets[0]
        else:
            sys.stdout.write('\n\tCould not find subnet, creating it...')
            self.subnet = self.vpc.create_subnet(DryRun=False,
                                                 CidrBlock='172.31.0.0/16')
            self.subnet.create_tags(Tags=[{'Key': 'Name', 'Value': 'cclyde_subnet'}])
        self.subnet.load()
        return True


    def check_vpc(self):
        '''Checks if VPC exists and sets it as self.vpc'''
        vpcs = [vpc for vpc in self.ec2.vpcs.filter(Filters=[{'Name': 'tag:Name', 'Values': ['cclyde_vpc']}])]
        if vpcs:
            sys.stdout.write('\n\tFound existing VPC...')
            self.vpc = vpcs[0]
        else:
            sys.stdout.write('\n\tDid not find VPC, creating new one...')
            self.vpc = self.ec2.create_vpc(DryRun=False,
                                           CidrBlock='172.31.0.0/16',
                                           InstanceTenancy='default')
            self.vpc.create_tags(Tags=[{'Key': 'Name', 'Value': 'cclyde_vpc'}])
        self.vpc.load()
        return True


    def check_key(self):
        '''Verify key exists, used to launch and connect to instances'''
        home_dir = os.path.expanduser('~')
        self.pem_key_path = os.path.join(home_dir, '.aws', '{}.pem'.format(self.key_name))

        if not os.path.exists(self.pem_key_path):
            sys.stdout.write('\n\tKey pair name: "{}" not found, creating it...'.format(self.key_name))

            # Enure AWS doesn't have this keypair on file, meaning user doesn't have it but amazon does.
            keypairs = self.client.describe_key_pairs()
            for keypair in keypairs.get('KeyPairs'):
                if keypair.get('KeyName') == self.key_name:
                    sys.stdout.write('\n\tFound existing keypair on AWS that was not found locally, deleting it...')
                    self.client.delete_key_pair(KeyName=self.key_name)

            # Create the keypair with boto3
            sys.stdout.write('\n\tCreating keypair called {}...'.format('{}'.format(self.key_name)))
            keypair = self.client.create_key_pair(KeyName='{}'.format(self.key_name))

            # Now write the key material to the .pem file
            with open(self.pem_key_path, 'w') as keyfile:
                keyfile.write(keypair.get('KeyMaterial'))
        else:
            sys.stdout.write('\n\tFound pem_key: "{}"...'.format(self.key_name))

        return True


    def check_security_group(self):
        '''Validates "cclyde" security group exits on AWS in the VPC, otherwise creates it.'''

        # Check if cclyde already exists as security group in the vpc
        sg = [sg for sg in self.vpc.security_groups.iterator() if sg.group_name == 'cclyde']

        # Either establish connection to the existing security group, or create one
        if sg:
            sys.stdout.write('Found existing cclyde security group, connecting to it...')
            self.security_group = self.ec2.SecurityGroup(sg[0].group_id)
        else:
            sys.stdout.write('"cclyde" security group does not exit in your AWS EC2, creating one for you...')
            response = self.client.create_security_group(GroupName='cclyde',
                                                         VpcId=self.vpc.id,
                                                         Description='Cluster-Clyde Security Group')
            self.security_group = self.ec2.SecurityGroup(response.get('GroupId'))
            self.security_group.create_tags(Tags=[{'Key': 'Name', 'Value': 'cclyde_security_group'}])
            self.security_group.load()


    def launch_instances(self):
        '''Launches EC2 instances'''
        instances = self.ec2.create_instances(ImageId=self.ami,
                                              InstanceType=self.instance_type,
                                              MinCount=self.n_nodes,
                                              MaxCount=self.n_nodes,
                                              KeyName=self.key_name,
                                              NetworkInterfaces=[{'AssociatePublicIpAddress': True,
                                                                  'SubnetId': self.subnet.id,
                                                                  'Groups': [self.security_group.id, ],
                                                                  'DeviceIndex': 0}])

        # Block until all instances are in 'running' state (code 16)
        while True:
            running = 0

            # Refresh instances from AWS.
            for instance in instances:
                instance.load()
                state = instance.state.get('Name')
                if state == 'running':
                    running += 1

            # Write status and break if all running, otherwise sleep for a sec before checking status again
            sys.stdout.write('\rLaunching instances: {} out of {} instances running...please wait..'
                             .format(running, len(instances)))
            if all([instance.state.get('Name') == 'running' for instance in instances]):
                break
            else:
                time.sleep(1.0)

        # Assign tag names to all the nodes
        sys.stdout.write('\rAll instances in running state!\nSetting node names...')
        for i, instance in enumerate(instances):
            instance.create_tags(
                Tags=[{'Key': 'Name', 'Value': 'cclyde_node{}'.format(i) if i else 'cclyde_master_node'}])
            instance.load()

        self.instances = instances


    def configure_security_group(self):
        '''
        Ensures the configuration of the security group
        Allowing communication from each node to master and client to master ports 8787 and 8786
        '''

        ip = get_ip()
        ip = ip + '/32' if ip else '0.0.0.0.0/0'  # Make warning about this.. or think of something else.

        # Required permissions
        permissions = [

            # Allow connection to port 22 for client and all nodes
            {'IpProtocol': 'tcp',
             'FromPort': 22,
             'ToPort': 22,
             'UserIdGroupPairs': [{'VpcId': self.vpc.id,
                                   'GroupId': self.security_group.group_id, },
                                  ],
             'IpRanges': [{'CidrIp': ip},
                          ],
             },

            # Allow connection to port 8786 for client and all nodes
            {'IpProtocol': 'tcp',
             'FromPort': 80,
             'ToPort': 8786,
             'UserIdGroupPairs': [{'VpcId': self.vpc.id,
                                   'GroupId': self.security_group.group_id, },
                                  ],
             'IpRanges': [{'CidrIp': ip},
                          ],
             },

            # Allow connection to port 8787 for client and all nodes
            {'IpProtocol': 'tcp',
             'FromPort': 80,
             'ToPort': 8787,
             'UserIdGroupPairs': [{'VpcId': self.vpc.id,
                                   'GroupId': self.security_group.group_id, },
                                  ],
             'IpRanges': [{'CidrIp': ip},
                          ],
             },
        ]

        # Try and apply each required permission to the security group.
        for permission in permissions:
            sys.stdout.write('\n\tWorking on permission: {} from port: {} to port: {}'.format(permission.get('IpProtocol'),
                                                                                          permission.get('FromPort'),
                                                                                          permission.get('ToPort')))
            try:
                self.security_group.authorize_ingress(
                    DryRun=False,
                    IpPermissions=[permission, ]
                )
                sys.stdout.write('...Done\n')
            except Exception as exc:
                # Raised because ip permission(s) already exist
                sys.stdout.write('\n\t-It appears you may already have cclyde security group configured for this:\n\t{}\n'
                                 .format(exc))


    def __str__(self):
        return u'Cluster instance: Num Nodes: {}'.format(self.n_nodes)
