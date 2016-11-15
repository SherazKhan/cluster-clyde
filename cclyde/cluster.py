import boto3
import sys
import time
import os
import logging

from pssh import ParallelSSHClient, utils
from utils import get_ip, get_dask_permissions


class Cluster(object):


    def __init__(self,
                 key_name='cluster_clyde_default',
                 n_nodes=2,
                 ami='ami-40d28157',
                 instance_type='t2.micro',
                 volume_size=0):
        """
        Constructor for cluster management object
        :param key_name: str - string of existing key name, if it doesn't exist it will be created.
                              this only refers to the name as: '<pem_key>.pem'
        :param n_nodes: int - Number of nodes to launch
        :param ami: str - Amazon Machine Image code
        :param instance_type: str - The type of EC2 instances to launch.
        :param volume_size: int - Size of attached volume to EC2 instance(s) in GB; 0 if no volume attached
                            if 0 - default instance storage is 8GB but will be lost upon cluster shutdown
        """

        logging.basicConfig()
        logging.captureWarnings(True)
        self.logger = logging.getLogger('Cluster-Clyde')
        self.logger.setLevel(logging.DEBUG)

        # set attributes
        self.ami = ami
        self.instance_type = instance_type
        self.key_name = key_name if not key_name.endswith('.pem') else key_name.replace('.pem', '')
        self.pem_key_path = None
        self.n_nodes = n_nodes
        if self.n_nodes < 2:
            raise ValueError('Number of nodes should be >= 2')
        self.volume_size = int(volume_size)
        self.instances = []
        self.security_group = None
        self.internet_gateway = None
        self.route_table = None
        self.loaded_paramiko_key = None  # paramiko loaded key
        self.nodes = []
        self.nodes_to_run_command = []


        # Begin by just connecting to boto3, this alone ensures that user has config and credentials files in ~/.aws/
        sys.stdout.write('Connecting to Boto3 and EC2 resources...')
        self.ec2 = boto3.resource('ec2')
        self.client = boto3.client('ec2')
        sys.stdout.write('Done. Ready to start cluster! Run: >>> cluster.start_cluster()\n')


    def start_cluster(self):
        """
        Performs all aspects of launching the cluster; checks keypairs, VPC, subnet, security group config, etc.
        :return:
        """

        self.logger.warning('\tOnce instances are running, you may be accumulating charges from AWS; be sure to run '
                            'cluster.stop_cluster() *AND* confirm instances are stopped/terminated via AWS console!')

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

        sys.stdout.write('Checking for Cluster Clyde\'s internet gateway...')
        self.check_internet_gateway()
        sys.stdout.write('Done.\n')

        sys.stdout.write('Attaching internet gateway to VPC if needed...')
        self.check_internet_gateway_VPC_connection()
        sys.stdout.write('Done.\n')

        sys.stdout.write('Confirming proper VPC route table configuration...')
        self.check_vpc_route_table()
        sys.stdout.write('Done.\n')

        sys.stdout.write('Launching instances...')
        self.launch_instances()
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


    @property
    def ssh_client(self):
        """Creates the parallel ssh client, recreates it every time it's used because sometimes the connection hosts
        will be different"""
        self.loaded_paramiko_key = utils.load_private_key(self.pem_key_path)

        hosts = [node.get('public_ip') for node in self.nodes]
        return ParallelSSHClient(hosts=hosts, user='ubuntu', pkey=self.loaded_paramiko_key)


    def install_anaconda(self):
        """Installs Anaconda on all cluster nodes"""

        sys.stdout.write('Installing Anaconda on cluster')
        output = self.ssh_client.run_command(
            'wget https://raw.githubusercontent.com/milesgranger/cluster-clyde/master/cclyde/utils/anaconda_bootstrap.sh '
            '&& bash anaconda_bootstrap.sh')

        for host in output:
            for line in output[host]['stdout']:
                print("Host %s - output: %s" % (host, line))

        return True


    def create_python_env(self, env_name):
        """Creates a python env"""
        pass


    def run_cluster_command(self, command, target='entire-cluster'):
        """Runs arbitrary command on all nodes in cluster
        command: str - command to run ie. "ls -l ~/"
        target: str - one of either 'entire-cluster', 'master', 'cluster-exclude-master', or specific node name
        python_env_command: bool - if this is any command to use the environment's bin, the full path to the bin is
                                   prepended infront of the command. ie /home/ubuntu/anaconda/envs/default/bin/<command>
        """

        # Assert the target is either the whole cluster, master, all but master or one of the specific nodes
        assert target in ['entire-cluster', 'master', 'cluster-exclude-master'].extend([node.get('host_name')
                                                                                        for node in self.nodes])

        if target == 'entire-cluster':
            self.nodes_to_run_command = self.nodes

        elif target == 'master':
            self.nodes_to_run_command = [node for node in self.nodes if 'master' in node.get('host_name')]
            assert len(self.nodes_to_run_command) == 1

        elif target == 'cluster-exclude-master':
            self.nodes_to_run_command = [node for node in self.nodes if 'master' not in node.get('host_name')]
            assert len(self.nodes_to_run_command) == len(self.nodes) - 1

        else:
            self.nodes_to_run_command = [node for node in self.nodes
                                         if target == node.get('host_name') or target == node.get('public_ip')]

        self.ssh_client.hosts = [node.get('public_ip') for node in self.nodes_to_run_command]
        output = self.ssh_client.run_command(command)
        for host in output:
            for line in output[host]['stdout']:
                host_name = [node.get('host_name') for node in self.nodes_to_run_command
                             if node.get('public_ip') == host][0]
                print("Host %s - IP: %s - output: %s" % (host_name, host, line))


    def check_internet_gateway(self):
        """
        Checks that a 'cclyde_internet_gateway' exists, creates one if not.
        """
        internet_gateway = [ig for ig in self.ec2.internet_gateways.filter(Filters=[{'Name': 'tag:Name',
                                                                                     'Values': ['cclyde_internet_gateway']}])]
        # If an internet gateway was found, set it, otherwise create one.
        if internet_gateway:
            sys.stdout.write('found existing cclyde gateway...')
            self.internet_gateway = internet_gateway[0]
        else:
            sys.stdout.write('no existing cclyde gateway, creating one...')
            self.internet_gateway = self.ec2.create_internet_gateway(DryRun=False)
            self.internet_gateway.create_tags(Tags=[{'Key': 'Name', 'Value': 'cclyde_internet_gateway'}])

        self.internet_gateway.load()


    def check_internet_gateway_VPC_connection(self):
        """
        Ensures that the internet gateway is attached to VPC
        """
        try:
            self.internet_gateway.attach_to_vpc(DryRun=False, VpcId=self.vpc.id)
        except Exception as exc:
            if 'Resource.AlreadyAssociated' in '{}'.format(exc):
                sys.stdout.write('gateway already associated with VPC...')
            else:
                raise Exception(exc)


    def check_vpc_route_table(self):
        """
        Confirms the proper routing for the vpc route table.
        """
        route_table = [rt for rt in self.vpc.route_tables.all()
                       if any([_rt.destination_cidr_block == self.vpc.cidr_block for _rt in rt.routes])]
        if route_table:
            sys.stdout.write('Found existing route table, confirming proper config...')
            self.route_table = route_table[0]
        else:
            raise NotImplementedError('Route table should have been created automatically just by creating the VPC,'
                                      ' a fix is not implemented')

        # Confirm that the destinations on the route table include 0.0.0.0/0 --> id of internet gateway & cidr to local
        if not any([rt_attr.get('DestinationCidrBlock') == '0.0.0.0/0'
                    for rt_attr in self.route_table.routes_attribute]):
            sys.stdout.write('\n\tadding 0.0.0.0/0 dest. with cclyde iternet-gateway as target to route table...')
            self.route_table.create_route(DryRun=False,
                                          DestinationCidrBlock='0.0.0.0/0',
                                          GatewayId=self.internet_gateway.id)
        self.route_table.load()
        self.internet_gateway.load()
        self.vpc.load()
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


    def configure_security_group(self):
        '''
        Ensures the configuration of the security group
        Allowing communication from each node to master and client to master ports 8787 and 8786
        '''

        ip = get_ip()
        ip = ip + '/32' if ip else '0.0.0.0.0/0'  # Make warning about this.. or think of something else.

        # Required permissions
        permissions = get_dask_permissions(obj=self, ip=ip)

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
                # TODO: Check if this is the proper way to do the following exception checking and re-raising..:

                # Raised because ip permission(s) already exist, probably, check if that's the case here
                if 'InvalidPermission.Duplicate' in '{}'.format(exc):
                    sys.stdout.write('...already exists! Passing.\n')

                # If it was raised for another reason, pass it along as an exception
                else:
                    raise Exception(exc)


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
        sys.stdout.write('\rAll {} instances in running state!\nSetting node names...'.format(self.n_nodes))
        for i, instance in enumerate(instances):
            instance.create_tags(
                Tags=[{'Key': 'Name', 'Value': 'cclyde_node-{}'.format(i) if i else 'cclyde_node-master'}])
            instance.load()

        # Make list of dicts, where each is just the node name and its public ip address
        self.nodes = [{'host_name': [tag for tag in node.tags if tag.get('Key') == 'Name'][0].get('Value'),
                       'public_ip': node.public_ip_address
                       } for node in instances]

        # Assign full AWS EC2 instances to class var if needed later
        self.instances = instances


    def __str__(self):
        return u'Cluster instance: Num Nodes: {}'.format(self.n_nodes)
