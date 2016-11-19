#!/bin/bash
anaconda=Miniconda2-latest-Linux-x86_64.sh

if [ ! -f $anaconda ]; then
    echo 'Downloading anaconda...'
    wget https://repo.continuum.io/miniconda/$anaconda

    echo 'Installing default anaconda environment...'
    chmod +x $anaconda
    ./$anaconda -b -f -p /opt/anaconda
fi

echo 'Appending /opt/anaconda/bin to path in ~/.bashrc file'
export PATH="/opt/anaconda/bin:$PATH"
echo "export PATH=/opt/anaconda/bin:$PATH" >> ~/.bashrc

echo 'Sourcing .bashrc'
source ~/.bashrc

echo 'Done'