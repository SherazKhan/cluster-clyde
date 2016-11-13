import os
import requests

def get_ip():
    '''
    Helper function get to current external IP Address
    :return: external IP address in string format
    '''
    ip = requests.get('http://whatismyip.org')
    if ip.ok:
        return ip.content.split('<span')[1].split('>')[1].split('<')[0]
    return False


def get_dask_permissions(obj, ip):
    """
    Returns list of permissions required by dask
    :param obj: instance of cluster object which is initialized up to point of configuring security group
    :param ip: external ip address for allowed ip ranges
    :return: list of permissions formatted as required by boto3 for dask distributed
    """
    dask_permissions = [

        # Allow connection to port 22 for client and all nodes
        {'IpProtocol': 'tcp',
         'FromPort': 22,
         'ToPort': 22,
         'UserIdGroupPairs': [{'VpcId': obj.vpc.id,
                               'GroupId': obj.security_group.group_id, },
                              ],
         'IpRanges': [{'CidrIp': ip},
                      ],
         },

        # Allow connection to port 8786 for client and all nodes
        {'IpProtocol': 'tcp',
         'FromPort': 80,
         'ToPort': 8786,
         'UserIdGroupPairs': [{'VpcId': obj.vpc.id,
                               'GroupId': obj.security_group.group_id, },
                              ],
         'IpRanges': [{'CidrIp': ip},
                      ],
         },

        # Allow connection to port 8787 for client and all nodes
        {'IpProtocol': 'tcp',
         'FromPort': 80,
         'ToPort': 8787,
         'UserIdGroupPairs': [{'VpcId': obj.vpc.id,
                               'GroupId': obj.security_group.group_id, },
                              ],
         'IpRanges': [{'CidrIp': ip},
                      ],
         },
    ]
    return dask_permissions
