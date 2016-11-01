import boto3
import sys

from utils.external_ip import get_ip


class Cluster(object):

    def __init__(self, key_name=None, nodes=2):
        """
        Constructor for cluster management object
        :param key_name: str - string of existing key name, if it doesn't exist it will be created.
        """
        sys.stdout.write('Connecting to Boto3 EC2 resources...')
        self.ec2 = boto3.resource('ec2')
        self.client = boto3.client('ec2')
        sys.stdout.write('Done.\n')

        sys.stdout.write('Validating security group...')
        self.validate_security_group()
        sys.stdout.write('Done.\n')

        sys.stdout.write('Configuring security group...')
        self.configure_security_group()
        sys.stdout.write('Done configuring security group.\n')

        sys.stdout.write('Creating volumes...')
        self.launch_volumes()
        sys.stdout.write('Done.\n')

        sys.stdout.write('Launching instances...')


        self.nodes = nodes


    def launch_instances(self):
        pass

    def launch_volumes(self):
        pass


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
             'UserIdGroupPairs': [{'GroupName': self.security_group.group_name,
                                   'GroupId': self.security_group.group_id, },
                                  ],
             'IpRanges': [{'CidrIp': ip},
                          ],
             },

            # Allow connection to port 8786 for client and all nodes
            {'IpProtocol': 'tcp',
             'FromPort': 80,
             'ToPort': 8786,
             'UserIdGroupPairs': [{'GroupName': self.security_group.group_name,
                                   'GroupId': self.security_group.group_id, },
                                  ],
             'IpRanges': [{'CidrIp': ip},
                          ],
             },

            # Allow connection to port 8787 for client and all nodes
            {'IpProtocol': 'tcp',
             'FromPort': 80,
             'ToPort': 8787,
             'UserIdGroupPairs': [{'GroupName': self.security_group.group_name,
                                   'GroupId': self.security_group.group_id, },
                                  ],
             'IpRanges': [{'CidrIp': ip},
                          ],
             },
        ]

        # Try and apply each required permission to the security group.
        for permission in permissions:
            sys.stdout.write('Working on permission: {} from port: {} to port: {}'.format(permission.get('IpProtocol'),
                                                                                          permission.get('FromPort'),
                                                                                          permission.get('ToPort')))
            try:
                self.security_group.authorize_ingress(
                    DryRun=False,
                    GroupName=self.security_group.group_name,
                    IpPermissions=[permission]
                )
                sys.stdout.write('...Done\n')
            except Exception as exc:
                # Raised because ip permission(s) already exist
                sys.stdout.write('\n-It appears you may already have cclyde security group configured for this:\n\n{}\n\n'
                                 .format(exc))



    def validate_security_group(self):
        '''Validates "cclyde" security group exits on AWS EC2, otherwise creates it.'''

        # Check if cclyde already exists as security group
        sg = [sg for sg in self.ec2.security_groups.iterator() if sg.group_name == 'cclyde']

        # Either establish connection to the existing security group, or create one
        if sg:
            sys.stdout.write('Found existing cclyde security group, connecting to it...')
            self.security_group = self.ec2.SecurityGroup(sg[0].group_id)
        else:
            sys.stdout.write('"cclyde" security group does not exit in your AWS EC2, creating one for you...')
            response = self.client.create_security_group(GroupName='cclyde',
                                                         Description='Cluster-Clyde Security Group')
            self.security_group = self.ec2.SecurityGroup(response.get('GroupId'))




    def __str__(self):
        return u'Cluster instance: Num Nodes: {}'.format(self.nodes)
