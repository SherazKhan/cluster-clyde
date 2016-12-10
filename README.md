# cluster-clyde
Easy to use tool for quickly deploying temporary EC2 clusters on AWS completely through Python script/shell
- primarily focused for use with Dask Distributed for now; but should be easily extended.

---

# Ready for Beta use; pull requests welcome!

## Install:

`git clone https://github.com/milesgranger/cluster-clyde.git`
`cd cluster-clyde`
`python setup.py install`

**Note** `pip install git+git://github.com/milesgranger/cluster-clyde.git` does not work because this package requires a modified forked version of Parallel-SSH<br/>
This should be fixed in the near future.

## Uninstall:
`pip uninstall cluster-clyde`


## Usage

**AWS Boto3 Requirements**

You must have a `credentials` and `config` file located in your ~/.aws directory
This is a requirement from AWS / Boto3. Given your aws_access_key_id, aws_secret_access_key from AWS console
you can create these files with the following:

`from cclyde.cluster import Cluster`<br/>
`cluster = Cluster()`

Make credentials file:<br/>
`cluster.make_credentials_file('your_aws_access_key_id', 'your_aws_secret_access_key')`

Make config file:<br/>
`cluster.make_config_file('your_prefered_region')`



---

**Launching a cluster**

1. Create cluster object:<br/>
`from cclyde.cluster import Cluster`<br/>
`cluster = Cluster(key_name='default', 
                   n_nodes=4,
                   cluster_name='default',
                   instance_type='t2.medium')`
                   
2. Configure object:<br/>
This performs a number of checks and configures things like your Virtual Private Cloud,
key pair on AWS (<key_name>.pem), security group permissions, and everything else required
to launch a cluster. All of these will be pre-pended with 'cclyde' in your AWS. ie. *cclyde-security-group*
<br/>`cluster.configure()`


3. Launch instances:<br/>
Here you have two choices, one blocking the other non-blocking incase you want to perform
other tasks while you wait for nodes to become ready to connect to.<br/>
`cluster.launch_instances()` or `cluster.launch_instances_nonblocking()`

You now have a cluster at your fingertips. Run commands on the cluster with the following:<br/>
`cluster.run_cluster_command(command='date',
                             target='cluster',
                             python_env_cmd=False,
                             return_output=True)`

---

**Setting up Dask Distributed on the cluster**

I really, *really* like [Dask Distributed](https://github.com/dask/distributed)<br/>
Please see the examples/Demo.ipynb for a full work-flow example. 

If launched in non-blocking mode, ensure the thread which is launching the instances
has finished:<br/>
`cluster.instance_launching_thread.is_alive()` should be `False`

1. Install Anaconda:<br/>
`cluster.install_anaconda()`

2. Install any wanted packages on the cluster:<br/>
`cluster.install_python_packages(['scikit-learn', 'numpy'], method='conda')`

3. Launch the Scheduler and Workers:<br/>
`cluster.launch_dask()`

This will give you the web UI as well as the scheduler address.
You can use it with standard Dask.Distributed workflow as such:<br/>
`from distributed import Client`<br/>
`client = Client(address='<public_ip_of_master_node>:8786')`<br/>
`futures = client.map(some_function, some_iterable)`
