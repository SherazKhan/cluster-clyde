import boto3
import sys
import time
import os
import logging
import threading

from paramiko.client import SSHClient
from paramiko import AutoAddPolicy
from concurrent.futures import ThreadPoolExecutor
from utils import get_ip, get_dask_permissions


class Cluster(object):

    def __init__(self,
                 key_name='cclyde_default',
                 cluster_name='default',
                 n_nodes=2,
                 ami='ami-40d28157',
                 instance_type='t2.micro',
                 python_env='default',
                 volume_size=0):
        """
        Constructor for cluster management object
        :param key_name: str - string of existing key name, if it doesn't exist it will be created.
                              this only refers to the name as: '<pem_key>.pem'
        :param cluster_name: str - name of this new cluster, this is given as a tag to created instances to allow
               reconnection/starting of instances.
        :param n_nodes: int - Number of nodes to launch
        :param ami: str - Amazon Machine Image code
        :param instance_type: str - The type of EC2 instances to launch.
        :param python_env: str - name of python environment to use,
                                 default --> /home/ubuntu/anaconda/bin,
                                 other --> /home/ubuntu/anaconda/envs/<python_env>/bin
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
        self.nodes_to_run_command = []
        self.python_env = python_env.lower().strip()
        self.configured = False
        self.anaconda_installed = False
        self.cluster_name = cluster_name


        # Object SSH #
        self.ssh_client = SSHClient()
        self.ssh_client.set_missing_host_key_policy(AutoAddPolicy())


        # Begin by just connecting to boto3, this alone ensures that user has config and credentials files in ~/.aws/
        sys.stdout.write('Connecting to Boto3 and EC2 resources...')
        self.ec2 = boto3.resource('ec2')
        self.client = boto3.client('ec2')
        sys.stdout.write('Done. \nReady to configure in preparation to launch cluster! Run: >>> cluster.configure()\n')


    def configure(self):
        """
        Runs all configuration methods, before start_cluster() method.
        """
        sys.stdout.write('Checking keypair exists using key_name: "{}"...'.format(self.key_name))
        self.check_key()
        sys.stdout.write('Done.\n')

        sys.stdout.write('Checking for Cluster Clyde\'s Virtual Private Cloud (cclyde_vpc) on AWS...')
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

        self.configured = True

        sys.stdout.write('Everything is configured, you can now run >>> cluster.launch_instances() '
                         'OR cluster.reconnect_to_cluster()')


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
    def nodes(self):
        # Make list of dicts, where each is just the node name and its public and internal ip addresses
        nodes = [{'host_name': [tag for tag in node.tags if tag.get('Key') == 'Name'][0].get('Value'),
                  'public_ip': node.public_ip_address,
                  'internal_ip': node.private_ip_address
                  } for node in self.instances]
        return nodes


    @property
    def python_env(self):
        """@property just to have .setter to modify env path when python_env is changed"""
        return self._python_env


    @python_env.setter
    def python_env(self, python_env):
        """If user sets different python_env, need to update the path to that environment as well"""
        # TODO: Add check to see if this environment exists on the cluster; if not, create it.
        python_env = python_env.lower().strip()

        self._python_env = python_env  # Set temp _python_env which @property will use
        self.python_env_path = '/home/ubuntu/anaconda/bin/' \
                               if python_env == 'default' else '/home/ubuntu/anaconda/envs/{}/bin/'.format(python_env)


    def install_anaconda(self):
        """Installs Anaconda on all cluster nodes"""
        sys.stdout.write('Installing Anaconda on cluster...\n\n')
        command = 'wget https://raw.githubusercontent.com/milesgranger/cluster-clyde/master/cclyde/utils/anaconda_bootstrap.sh ' \
                  '&& bash anaconda_bootstrap.sh'
        results = self.run_cluster_command(command, target='cluster', ignore_output=False)
        self.anaconda_installed = True
        sys.stdout.write('Done.')
        return results


    def create_python_env(self, env_name, activate=True):
        """Creates a python env"""
        # TODO: Remember to add env_name to the self.python_env which will also update the path
        pass


    def install_python_packages(self, packages, method='pip', target='cluster', only_exit_codes=True):
        """
        Convienience function to install python package(s)
        packages: list - list of packages to install into current python_env environment. ie ['numpy', 'pandas==18.0']
        For more control over installation of packages to specific nodes use
        run_cluster_command('pip install <package>', target=<node name>, python_env_cmd=True)
        """
        packages = [p.strip() for p in packages]

        # Install all packages one by one to help avoid errors incase just one package errors out.
        for package in packages:
            sys.stdout.write('\nInstalling package: {}'.format(package))
            if method == 'pip':
                command = 'pip install {}'.format(package)
            else:
                command = 'conda install {} -y'.format(package)

            # Run the command to install this package, then iterate over all host results
            results = self.run_cluster_command(command=command, target=target, python_env_cmd=True)
            for result in results:
                if only_exit_codes:
                    to_print = '\n----------\n{} \tExit code: {}\n'.format(result.get('host_name'),
                                                                           result.get('exit_code'))
                else:
                    to_print = '\n----------\n{} stdout: {}\nstderr: {}\nExit code: {}\n'.format(result.get('host_name'),
                                                                                                 result.get('stdout'),
                                                                                                 result.get('stderr'),
                                                                                                 result.get('exit_code'))
                sys.stdout.write(to_print)

        return True


    def launch_dask(self):
        """On a running cluster with anaconda installs and launches dask distributed in the current python_env"""

        # Ensure anaconda has been installed on cluster
        if not self.anaconda_installed:
            raise AssertionError('Need to have anaconda installed on cluster; run >>>cluster.install_anaconda()')

        # Locate mater, to use its internal ip address for worker nodes to connect to
        master = filter(lambda node: node.get('host_name', '').endswith('master'), self.nodes)
        if master:
            master = master[0]
        else:
            raise Warning('Master node not found in self.nodes')


        # Ensure distributed is installed on the cluster.
        sys.stdout.write('Installing dask.distributed on cluster\n')
        output = self.run_cluster_command('{}conda install distributed -y'.format(self.python_env_path),
                                          target='cluster',
                                          ignore_output=False)
        for r in output:
            sys.stdout.write('\nNode: {} exit code: {}'.format(r.get('host_name'), r.get('exit_code')))
            if r.get('exit_code'):
                sys.stderr.write('\nStdout: {}\nStderr: {}\n'.format(r.get('stdout'), r.get('stderr')))
        time.sleep(10)

        # Launch the scheduler on the master node
        sys.stdout.write('\nLaunching scheduler on master node...')
        output = self.run_cluster_command('nohup {}dask-scheduler &'.format(self.python_env_path),
                                          target='master',
                                          python_env_cmd=False,
                                          ignore_output=True)
        time.sleep(5)
        sys.stdout.write('Done.\n')


        # Launch the workers
        sys.stdout.write('\nLaunching workers...')
        # TODO: Add ability for --nprocs & --nthreads; now it defaults to one process with threads == n_cores
        output = self.run_cluster_command('nohup {}dask-worker {}:8786 &'.format(self.python_env_path,
                                                                                 master.get('internal_ip')),
                                          target='exclude-master',
                                          python_env_cmd=False,
                                          ignore_output=True)

        time.sleep(5)
        sys.stdout.write('Done.\n')

        sys.stdout.write('\nScheduler should be available here: {0}:8786'
                         '\nWeb Dashboard should be available here: {0}:8787'.format(master.get('public_ip')))




    def run_cluster_command(self, command, target='cluster', python_env_cmd=False, ignore_output=False):
        """
        Runs arbitrary command on all nodes in cluster

        command: str - command to run ie. "ls -l ~/"

        target: str - one of either 'cluster', 'master', 'exclude-master', or specific node name

        python_env_command: bool - if this is any command to use the environment's bin, the full path to the bin is
                                   prepended infront of the command. ie <command> --> /home/ubuntu/anaconda/bin/<command>
                                   IMPORTANT: if your python command includes something like: 'nohup <my_command>'
                                   you should not set this because it would end up like: /home/ubuntu/anaconda/bin/nohup <my_command>

        returns list of dicts generator with informaiton about node and given output form the command (if not ignore_output)
        """
        # Assert the target is either the whole cluster, master, all but master or one of the specific nodes
        choices = ['cluster', 'master', 'exclude-master']
        choices.extend([node.get('host_name') for node in self.nodes])
        choices.extend([node.get('public_ip') for node in self.nodes])
        choices.extend([node.get('internal_ip') for node in self.nodes])
        assert target in choices

        # Determine what nodes to run this command on
        if target == 'cluster':
            self.nodes_to_run_command = self.nodes

        elif target == 'master':
            self.nodes_to_run_command = [node for node in self.nodes if 'master' in node.get('host_name')]
            assert len(self.nodes_to_run_command) == 1, 'Found more than one master: {}'.format(self.nodes_to_run_command)

        elif target == 'exclude-master':
            self.nodes_to_run_command = [node for node in self.nodes if 'master' not in node.get('host_name')]
            assert len(self.nodes_to_run_command) == len(self.nodes) - 1

        else:
            self.nodes_to_run_command = [node for node in self.nodes
                                         if target == node.get('host_name') or target == node.get('public_ip')]

        # Sanity check; make sure we're gonig to run on at least one node.
        assert len(self.nodes_to_run_command) > 0, 'Based on target: {}, no nodes to run command on'.format(target)

        # prepend python_env_path if this is python command
        command = self.python_env_path + command if python_env_cmd else command

        def run_command_on_node(node):
            """Runs a command on given node; processed by threads"""

            result = dict(host_name=node.get('host_name'),
                          public_ip=node.get('public_ip'),
                          exit_code=None,
                          stdout='',
                          stderr='')

            client = SSHClient()
            client.set_missing_host_key_policy(AutoAddPolicy())
            client.connect(hostname=node.get('public_ip'),
                           username='ubuntu',
                           key_filename=self.pem_key_path,
                           timeout=60,
                           banner_timeout=60)
            channel = client.get_transport().open_session()
            stdout = channel.makefile()
            stderr = channel.makefile_stderr()
            channel.exec_command(command=command)

            # If user doesn't care about exit code, don't bother looking for output/exit code
            if not ignore_output:
                while True:

                    # If user deosn't want output, just look for the exit code.
                    if stdout.readable():
                        result['stdout'] += stdout.readline(size=2048)
                    if stderr.readable():
                        result['stderr'] += stderr.readline(size=2048)

                    if channel.exit_status_ready():
                        result['exit_code'] = channel.exit_status
                        break
                    else:
                        time.sleep(0.5)

            # Close files and client connection
            stderr.close()
            stdout.close()
            client.close()
            return result

        # Map nodes_to_run_command to function above
        with ThreadPoolExecutor(max_workers=20) as executor:
            results = executor.map(run_command_on_node, self.nodes_to_run_command)

        return results




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



    def launch_instances_nonblocking(self):
        """
        Launches EC2 instances, but doesn't block main thread
        Check that instances are running with self.instance_launching_thread.is_alive() --> False = instances are ready.
        """
        self.instance_launching_thread = threading.Thread(target=self.launch_instances, )
        self.instance_launching_thread.start()



    def launch_instances(self):
        """Launches EC2 instances, must run configure() method beforehand"""

        if not self.configured:
            raise AttributeError('Cluster is not yet configured, please run >>> cluster.configure() before attempting '
                                 'to launch instances.')

        self.logger.warning('\tOnce instances are running, you may be accumulating charges from AWS; be sure to run '
                            'cluster.stop_cluster() *AND* confirm instances are stopped/terminated via AWS console!')

        instances = self.ec2.create_instances(ImageId=self.ami,
                                              InstanceType=self.instance_type,
                                              MinCount=self.n_nodes,
                                              MaxCount=self.n_nodes,
                                              KeyName=self.key_name,
                                              NetworkInterfaces=[{'AssociatePublicIpAddress': True,
                                                                  'SubnetId': self.subnet.id,
                                                                  'Groups': [self.security_group.id, ],
                                                                  'DeviceIndex': 0}])

        # Block until all instances are in 'running' state (code 16) & ready for connection
        self.wait_for_instances(instances)

        # Assign tag names to all the nodes
        sys.stdout.write('\rAll {} instances ready!\nSetting node names...'.format(self.n_nodes))
        for i, instance in enumerate(instances):
            instance.create_tags(
                Tags=[{'Key': 'cluster_association', 'Value': self.cluster_name},
                      {'Key': 'Name', 'Value': 'cclyde_node-{}'.format(i) if i else 'cclyde_node-master'}
                      ])
            instance.load()
        sys.stdout.write('Done.\n')

        # Assign full AWS EC2 instances to class var if needed later
        self.instances = instances

        # install anaconda
        self.install_anaconda()
        return


    def reconnect_to_cluster(self):
        """
        Instead of running launch_instances(), run this to reconnect to a cluster; it is expected that there
        are instances on the cclyde_vpc who's Tag 'cluster_association' matches the given current self.cluster_name
        will raise an exception if none are found on VPC.
        :return:
        """

        if not self.configured:
            raise AttributeError('Cluster is not yet configured, please run >>> cluster.configure() before attempting '
                                 'to connect to instances.')

        # Get instances with the current obj cluster_name
        instances = [inst for inst in self.vpc.instances.filter(Filters=([{'Name': 'tag:cluster_association',
                                                                           'Values': [self.cluster_name, ]}]))]

        if not instances:
            raise ValueError('No instances found on VPC with the cluster_association to cluster_name: {}'
                             .format(self.cluster_name))

        # Check if these instances are already running.
        if all([i.state.get('Name') == 'running' for i in instances]):
            sys.stdout.write('\nConnected to exiting running instances. Count: {}, cluster_name: {}\n'
                             .format(len(instances), self.cluster_name))

        else:
            sys.stdout.write('\nFound non-running instances.. starting them...\n')
            self.client.start_instances(InstanceIds=[inst.id for inst in instances])
            self.wait_for_instances(instances)
            sys.stdout.write('\rDone.\n')

        self.instances = instances

        return



    def wait_for_instances(self, instances):
        """
        Wait for instances to be in reachable state; checks for running and then to be reachable
        :param instances: <list> - iterable of Boto3 Instance objects.
        :return: None - Blocks until all are running and ready for be connected to.
        """
        # First loop until all instances are running
        while True:
            running = 0

            # Refresh instances from AWS.
            for instance in instances:
                instance.load()
                state = instance.state.get('Name')
                if state == 'running':
                    running += 1

            # Write status and break if all running, otherwise sleep for a sec before checking status again
            sys.stdout.write('\rInstances starting: {} out of {} instances running...please wait..'
                             .format(running, len(instances)))
            if all([instance.state.get('Name') == 'running' for instance in instances]):

                break
            else:
                time.sleep(1.0)

        # Now wait for all instance status 'reachability' to be passed before continuing
        sys.stdout.write('\rAll instances in running state, waiting for all to be reachable...\n')
        loops = 0
        wheel = {0: "<(' '<)", 1: "<(' ')>", 2: "(>' ')>", 3: "<(' ')>"}  # Have fun while we wait, looks like kirby? :)
        while True:
            ready_count = 0

            # Request instance updates
            statuses = self.client.describe_instance_status(InstanceIds=[node.id for node in instances])
            for status in statuses.get('InstanceStatuses'):
                ready_count += 1 if status.get('InstanceStatus').get('Status') == 'ok' else 0

            sys.stdout.write('\r{} of {} instances ready for connection; please wait, this takes a while... {}'
                             .format(ready_count, len(instances), wheel.get(loops)))

            loops += 1
            loops = loops if loops < 4 else 0
            if ready_count == len(instances):
                break
            else:
                time.sleep(3)


    def stop_cluster(self):
        """Stops cluster"""
        for instance in self.instances:
            instance.stop(Force=True)
        self.logger.warning('Stopped instances. Please check your AWS console to ensure nodes are stopped!')


    def terminate_cluster(self):
        """Terminates instances in cluster"""
        for instance in self.instances:
            instance.terminate()
        self.logger.warning('Terminated instances. Please check your AWS console to ensure termination of nodes!')


    def __str__(self):
        return u'Cluster instance: Num Nodes: {}'.format(self.n_nodes)
