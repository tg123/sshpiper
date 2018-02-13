#!/bin/bash

apt-get update
apt-get install -y sshpass 

mkdir -p /local
mkdir -p /workingdir/host{1,2}

ssh-keygen -N '' -f /local/id_rsa
ssh-keygen -N '' -f /workingdir/host1/id_rsa

/bin/cp /local/id_rsa.pub /workingdir/host1/authorized_keys
/bin/cp /workingdir/host1/id_rsa.pub /host1/authorized_keys


echo "root@host1" > /workingdir/host1/sshpiper_upstream
echo "root@host2" > /workingdir/host2/sshpiper_upstream



fail="\033[0;31mFAIL\033[0m"
succ="\033[0;32mSUCC\033[0m"

while true; do

    casename="host1 with public key: "
    rnd=`head -c 6 /dev/urandom | base64`
    echo $rnd > /names/host1
    t=`ssh host1@piper -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i /local/id_rsa cat /names/host1`

    if [ $t != $rnd ];then
        echo -e $casename $fail
    else
        echo -e $casename $succ
    fi

    casename="host2 with password"
    rnd=`head -c 6 /dev/urandom | base64`
    echo $rnd > /names/host2
    t=`sshpass -p root ssh host2@piper -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null cat /names/host2`

    if [ $t != $rnd ];then
        echo -e $casename $fail
    else
        echo -e $casename $succ
    fi

    sleep 1
done
