#!/usr/bin/env bash

CONTROL_NODE_IP=192.168.77.100
declare -a WORK_NODE_IPS=(192.168.77.101)

function patch {
   sed -i s/"#proxyAll: false"/"proxyAll: true"/g /root/antrea.yml
   sed -i s/"\#kubeAPIServerOverride: \"\""/"kubeAPIServerOverride: \"$CONTROL_NODE_IP:6443\""/g /root/antrea.yml
   docker save -o /tmp/antrea.tar projects.registry.vmware.com/antrea/antrea-ubuntu:latest
   for IP in "${WORK_NODE_IPS[@]}"; do
      scp /tmp/antrea.tar root@$IP:/tmp/
      ssh root@$IP "docker image load < /tmp/antrea.tar && rm -rf /tmp/antrea.tar"
   done
   rm -rf /tmp/antrea.tar
}

_usage="Usage: $0 [-u] [-s (version)] [--help|-h]
Reset Antrea.
       -u                 Reinstall Antrea with latest built image
       -s                 Switch to an old version Antrea
       --help, -h         Print this message and exit
"

function echoerr {
    >&2 echo "$@"
}

function print_usage {
    echoerr "$_usage"
}

UPDATE=false
SWITCH=false
SWITCH_TO=""

while [[ $# -gt 0 ]];
do
    key="$1"
    case $key in
        -u)
            UPDATE=true
            shift
            ;;
        -s)
            SWITCH=true
            SWITCH_TO="$2"
            shift 2
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        *)    # unknown option
            echoerr "Unknown option $key"
            exit 1
            ;;
    esac
done

if [ "$UPDATE" == true ] && [ "$SWITCH" == true ]; then
   echoerr "-u and -s cannot be used together"
   print_help
   exit 1
fi

if [ "$UPDATE" == false ] && [ "$SWITCH" == false ]; then
   echo "Reinstall Antrea!"
   kubectl delete -f /root/antrea.yml
   kubectl apply -f /root/antrea.yml
fi

if [ "$UPDATE" == true ]; then
   kubectl delete -f /root/antrea.yml
   rm -rf /root/antrea.yml
   cp /root/antrea/build/yamls/antrea.yml /root/antrea-latest.yml
   ln -s /root/antrea-latest.yml /root/antrea.yml
   patch
   kubectl apply -f /root/antrea.yml
fi

if [ "$SWITCH" == true ]; then
  kubectl delete -f /root/antrea.yml
  rm -rf /root/antrea.yml
  ln -s /root/antrea-v"${SWITCH_TO}".yml /root/antrea.yml
  kubectl apply -f /root/antrea.yml
fi
