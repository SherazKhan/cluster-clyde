anaconda=Anaconda2-4.2.0-Linux-x86_64.sh

if [[ ! -f $anaconda ]]; then
    wget https://repo.continuum.io/archive/$anaconda
fi

chmod +x $anaconda

./$anaconda -b

cat >> /home/ubuntu/.bashrc << END

PATH=/home/ubuntu/anaconda2/bin:$PATH
END

