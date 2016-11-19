#!/bin/bash
anaconda=Miniconda2-latest-Linux-x86_64.sh

if [ ! -f $anaconda ]; then
    echo 'Downloading anaconda...'
    wget https://repo.continuum.io/miniconda/$anaconda

    echo 'Installing default anaconda environment...'
    chmod +x $anaconda
    ./$anaconda -b -f -p /home/ubuntu/anaconda
fi

echo 'Appending /home/ubuntu/anaconda/bin to path in ~/.bashrc file'
export PATH="/home/ubuntu/anaconda/bin:$PATH"
echo "export PATH=/home/ubuntu/anaconda/bin:$PATH" >> ~/.bashrc

echo 'Sourcing .bashrc'
source ~/.bashrc

echo 'Done'