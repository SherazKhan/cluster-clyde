#!/bin/bash

anaconda=Miniconda2-latest-Linux-x86_64.sh

if [ ! -f $anaconda ]; then
    wget https://repo.continuum.io/miniconda/$anaconda
fi

chmod +x $anaconda
./$anaconda -b -f -p /home/ubuntu/anaconda

export PATH="/home/ubuntu/anaconda/bin:$PATH"
echo "export PATH=/home/ubuntu/anaconda/bin:$PATH" >> ~/.bashrc
