#!/bin/sh


/wait.sh piper 2222
/wait.sh piper_yaml 2222
#/wait.sh piper_sqlite 2222
/wait.sh piper_mysql 2222
/wait.sh piper_pg 2222
/wait.sh piper_mssql 2222
/wait.sh piper_grpc_remotesigner_host1 2222
/wait.sh piper_grpc_privatekey_host1 2222
/wait.sh piper_grpc_host2 2222


# TODO to python

mkdir -p /local
mkdir -p /workingdir/host{1,2}

ssh-keygen -N '' -f /local/id_rsa
ssh-keygen -N '' -f /workingdir/host1/id_rsa #TODO pipe cmd

ssh-keygen -N '' -f /local/id_rsa2


/bin/cp /local/id_rsa.pub /workingdir/host1/authorized_keys
/bin/cp /workingdir/host1/id_rsa.pub /host1/authorized_keys

fail="\033[0;31mFAIL\033[0m"
succ="\033[0;32mSUCC\033[0m"

runtest(){
    casename=$1
    host=$2
    user=$3
    cmd=$4

    rnd=`head -c 20 /dev/urandom | base64`
    echo $rnd > /names/$host
    rm -f /tmp/$host.stderr
    t=$($cmd 2>/tmp/$host.stderr)

    if [ "$t" != "$rnd" ];then
        echo -e $casename $fail
        exit 1
    else
        echo -e $casename $succ
    fi

    grep $rnd /workingdir/$user/*

    if [ $? -ne 0 ];then
        echo -e "grep typescript logger" $fail
        exit 1
    fi

    grep "hellopiper" /tmp/$host.stderr

    if [ $? -ne 0 ];then
        echo -e "welcome text" $fail
        exit 1
    fi
}

runtest "host1 with public key:" "host1" "host1" "ssh host1@piper -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i /local/id_rsa cat /names/host1"
runtest "host2 with password:" "host2" "host2" "sshpass -p root ssh host2@piper -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null cat /names/host2"

#runtest "sqlite host2 with password:" "host2" "host2" "sshpass -p root ssh host2@piper_sqlite -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null cat /names/host2"
runtest "mysql host2 with password:" "host2" "host2" "sshpass -p root ssh host2@piper_mysql -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null cat /names/host2"
runtest "pg host2 with password:" "host2" "host2" "sshpass -p root ssh host2@piper_pg -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null cat /names/host2"
runtest "msql host2 with password:" "host2" "host2" "sshpass -p root ssh host2@piper_mssql -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null cat /names/host2"


runtest "yaml host2 with password passthrough:" "host2" "passthrough" "sshpass -p root ssh passthrough@piper_yaml -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null cat /names/host2"
runtest "yaml host2 with password mappasspass:" "host2" "mappasspass" "sshpass -p pass ssh mappasspass@piper_yaml -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null cat /names/host2"
runtest "yaml host1 with password mappasskey:" "host1" "mappasskey" "sshpass -p pass ssh mappasskey@piper_yaml -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null cat /names/host1"
runtest "yaml host2 with password mapkeypass:" "host2" "mapkeypass" "ssh mapkeypass@piper_yaml -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i /local/id_rsa2 cat /names/host2"
runtest "yaml host2 with key mapkeykey:" "host1" "mapkeykey" "ssh mapkeykey@piper_yaml -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i /local/id_rsa2 cat /names/host1"
runtest "yaml host2 with key mapkeykey2:" "host1" "mapkeykey2" "ssh mapkeykey2@piper_yaml -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i /local/id_rsa2 cat /names/host1"
runtest "yaml host2 with password regex:" "host2" "regex000" "sshpass -p root ssh regex000@piper_yaml -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null cat /names/host2"
runtest "yaml host1 with none host1:" "host1" "host1" "ssh host1@piper_yaml -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null cat /names/host1"

runtest "grpc host1 with remotesigner:" "host1" "host1" "ssh host1@piper_grpc_remotesigner_host1 -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no -o PasswordAuthentication=no  cat /names/host1"
runtest "grpc host1 with privatekey:" "host1" "host1" "ssh host1@piper_grpc_privatekey_host1 -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no -o PasswordAuthentication=no  cat /names/host1"
runtest "grpc host2 with password:" "host2" "host2" "sshpass -p wrongpassword ssh host2@piper_grpc_host2 -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null cat /names/host2"