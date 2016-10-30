import boto3


class Cluster(object):

    def __init__(self, key_name=None, nodes=2):
        """
        Constructor for cluster management object
        :param key_name: str - string of existing key name, if it doesn't exist it will be created.
        """

        print 'Connecting to Boto3 EC2 resources...'
        self.ec2 = boto3.resource('ec2')
        self.client = boto3.client('ec2')

        print 'Validating security group...'
        self.validate_security_group()

        self.nodes = nodes



    def validate_security_group(self):
        '''Validates "cclyde" security group exits on AWS EC2, otherwise creates it.'''

        # Check if cclyde already exists as security group
        sg = [sg for sg in self.ec2.security_groups.iterator() if sg.group_name == 'cclyde']

        # Either establish connection to the existing security group, or create one
        if sg:
            print 'Found existing cclyde security group, connecting to it...'
            self.security_group = self.ec2.SecurityGroup(sg[0].group_id)
        else:
            print '"cclyde" security group does not exit in your AWS EC2, creating one for you...'
            response = self.client.create_security_group(GroupName='cclyde',
                                                         Description='Cluster-Clyde Security Group')
            self.security_group = self.ec2.SecurityGroup(response.get('GroupId'))
        print 'Done.'



    def __str__(self):
        return u'Cluster instance: Num Nodes: {}'.format(self.nodes)
