"""
MIT License

Copyright (c) 2016 Miles Granger

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

from setuptools import setup, find_packages

setup(name='cluster-clyde',
      version='0.0.1',
      author='Miles Granger',
      author_email='miles.granger@outlook.com',
      description='Cluster manager for AWS EC2 instances - Focus with Dask Distributed',
      packages=find_packages('.', exclude=('examples', 'docs', )),
      url='https://github.com/milesgranger/cluster-clyde',
      install_requires=['boto3',
                        'requests',
                        'opt-monkey',
                        ],
      dependency_links=['https://github.com/milesgranger/parallel-ssh/tarball/opt-monkey#egg=opt-monkey', ],
      zip_safe=True
      )
