import boto3


class Cluster(object):

    nodes = 0

    def __init__(self, key_name=None):
        """
        Constructor for cluster management object
        :param key_name: str - string of existing key name, if it doesn't exist it will be created.
        """

        print 'Connecting to Boto3 EC2 resource...'
        self.ec2 = boto3.resource('ec2')

        print 'Validating keypair...'
        self.validate_key(key_name)



    def validate_key(self, key_name):
        '''Validates the supplied keyname, or creates a new one if it doesn't exist'''

        self.keypair = self.ec2.KeyPair(key_name)

        try:
            self.keypair.load()
        except Exception as exc:
            print 'Key was not found... creating new one.'
            self.keypair = self.ec2.create_key_pair(KeyName=key_name)
            self.keypair.load()
            print 'Successfully created new key: {}'.format(key_name)


    def __str__(self):
        return u'Cluster instance: Num Nodes: {}'.format(self.nodes)
