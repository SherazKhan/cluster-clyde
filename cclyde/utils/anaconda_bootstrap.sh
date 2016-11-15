#!/bin/bash

anaconda=Anaconda2-4.2.0-Linux-x86_64.sh

if [ ! -f $anaconda ]; then
    wget https://repo.continuum.io/archive/$anaconda
fi

chmod +x $anaconda
./$anaconda -b -f -p /opt/anaconda

export PATH="/home/ubuntu/anaconda/bin:$PATH"
echo "export PATH=/home/ubuntu/anaconda/bin:$PATH" >> ~/.bashrc
