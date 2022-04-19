#!/usr/bin/env bash

# Define your aliases for namespace
declare -A NS_ALIAS_MAP=(
    [k]="kube-system"
    [t]="antrea-test"
    [it]="antrea-ipam-test"
)

function print_aliases {
    printf "All aliases for namespaces are listed below:\n"
    for ALIAS in "${!NS_ALIAS_MAP[@]}"; do
        printf "       %-10s         %s\n" "$ALIAS" "${NS_ALIAS_MAP[$ALIAS]}"
    done
}

_usage="Usage: $0 [arg1] [--namespace|-n (namespace string or alias)] [--shell|-s (shell name)] [-c (container name)] [--help|-h]
Watch a source of K8s.
       arg1               String to match one or multiple Pods
       --shell, -s        Shell name, such as sh, zsh or bash
       -c                 Container name
       --help, -h         Print this message and exit

$(print_aliases)
"

function echoerr {
    >&2 echo "$@"
}

function print_usage {
    echoerr "$_usage"
}

if [[ $# -lt 1 ]]; then
    print_usage
    exit 0
fi

POD_INFO=$1
NS_ARG="-A"
SHELL_ARG="/bin/bash"
CONTAINER_ARG=""
while [[ $# -gt 1 ]];
do
    key="$2"
    case $key in
        --namespace|-n)
            NS_ARG="-n $3"
            if [ "${NS_ALIAS_MAP[$3]}" ]; then
                NS_ARG="-n ${NS_ALIAS_MAP[$3]}"
            fi
            shift 2
            ;;
        --shell|-s)
            SHELL_ARG="/bin/$3"
            shift 2
            ;;
         -c)
            CONTAINER_ARG="-c $3"
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

NUM=$(kubectl get pods -o wide $NS_ARG --no-headers |  grep -c $POD_INFO)
if [ "$NUM" -gt 1 ]; then
    echo "Multiple Antrea Agent Pods are match."
    PODS=()

    for ((i=0; i<NUM; i++))
    do
        POD=$(kubectl get pods -o wide $NS_ARG --no-headers | grep $POD_INFO | awk '{print $1, $2, $4, $(NF-3), $(NF-2)}'| head -n $((i + 1)) | tail -n 1)
        PODS[$i]=$POD
        echo -e "[$i] => \c"
        echo $POD | awk '{printf ("%-50s %-5s %-10s %-20s %-30s\n", $1, $2, $3, $4, $5)}'
    done
    echo -e "Please select a Antrea Agent Pod:\c"
    read -r INDEX

    SELECTED_POD=$(echo ${PODS[$INDEX]} | awk '{print $2}')
    NS=$(echo ${PODS[$INDEX]} | awk '{print $1}')
    NS_ARG="-n $NS"
    kubectl exec -it $NS_ARG $SELECTED_POD $CONTAINER_ARG -- $SHELL_ARG
elif [ $NUM -eq 0 ]; then
    echo "No Antrea Agent Pod is matched"
    exit 1
else
    SELECTED_POD=$(kubectl get pods -o wide $NS_ARG | grep $POD_INFO | awk '{print $1}')
    kubectl exec -it $NS_ARG $SELECTED_POD $CONTAINER_ARG -- $SHELL_ARG
fi
