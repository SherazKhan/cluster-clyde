# Documentation for Cluster class 


**Methods**

---

`
def __init__(self,
              key_name='cclyde_default',
              cluster_name='default',
              n_nodes=2,
              ami='ami-40d28157',
              instance_type='t2.micro',
              python_env='default')
`<br/>

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
                         
---

`
def configure()
`<br/>
Runs all configuration methods, before start_cluster() method.


---

`
def make_credentials_file(aws_access_key_id, aws_secret_access_key)
`<br/>
*static method*
Creates a credential file for user
be careful, this overwrites any existing credential file
@:param aws_access_key_id: str - Access key id given by AWS
@:param aws_secret_access_key: str - secret key provided in association with key id from AWS

---

`
def make_config_file(region)
`<br/>
Creates a config file for user
be careful, this overwrites any existing config file
@param region: str - AWS region ie. us-east-1

---

`
def install_python_packages(packages, method='pip', target='cluster', only_exit_codes=True)
`<br/>

Convienience function to install python package(s)
packages: list - list of packages to install into current python_env environment. ie ['numpy', 'pandas==18.0']
For more control over installation of packages to specific nodes use
run_cluster_command('pip install <package>', target=<node name>, python_env_cmd=True)

---

`
def launch_dask()
`<br/>

Handles the launching of dask distributed on the cluster

---

`
def run_cluster_command(command, target='cluster', python_env_cmd=False, return_output=False)
`
Run a command on the cluster, master, or specific target (node name, public or internal ip)
:param command: str - command to be executed. ie. 'date'
:param target: str - target node(s) to execute command on. cluster, master, exclude-master or the node name,
                     internal ip, or public ip address
:param python_env_cmd: bool - If true, the absolute path to current python_env is used pre-pended to command.
                              ie. "python myscript.py" --> "/home/ubuntu/<python_env_path>/python myscript.py"
:param return_output: bool - Whether to print the stdout which results from the command.
:return: None


---

`
def launch_instances_nonblocking()
`<br/>

Launch instances without blocking the main thread.

---

`
def launch_instances()
`<br/>

Launch instances while blocking the main thread.

---

`
def reconnect_to_cluster()
`<br/>
Given a configured cluster object, reconnect to a cluster with the configured
cluster_name

---

`
def stop_cluster()
`<br/>

Stop a cluster, can later reconnect to it with `cluster.reconnect_to_cluster()`

---

`
def terminate_cluster()
`<br/>

Kill all instances on the current cluster