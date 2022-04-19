#!/bin/bash

declare -A POD_ALIAS_MAP=(
	[aa]="antrea-agent"
	[ac]="antrea-controller"
	[ka]="kube-controller"
	[kp]="kube-proxy"
)

# Define your aliases for namespace
declare -A NODE_ALIAS_MAP=(
    [co]="k8s-node-control-plane"
    [w1]="k8s-node-worker-1"
)


function print_aliases {
    printf "All aliases for general Pod names are listed below:\n"
    for ALIAS in "${!POD_ALIAS_MAP[@]}"; do
        printf "       %-10s         %s\n" "$ALIAS" "${POD_ALIAS_MAP[$ALIAS]}"
    done

     printf "\nAll aliases for Node names are listed below:\n"
    for ALIAS in "${!NODE_ALIAS_MAP[@]}"; do
        printf "       %-10s         %s\n" "$ALIAS" "${NODE_ALIAS_MAP[$ALIAS]}"
    done
}

_usage="Usage: $0 [arg1] [arg2]
Watch a source of K8s.
       arg1               String or alias of a general Pod name
       arg2               String or alias of one or more Node names

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
POD_ARG=$1
if [ "${POD_ALIAS_MAP[$POD_INFO]}" ]; then
    POD_ARG=${POD_ALIAS_MAP[$POD_INFO]}
fi

NODE_INFO=$2
NODE_ARG=""
if [ "$NODE_INFO" ]; then
	if [ "${NODE_ALIAS_MAP[$NODE_INFO]}" ]; then
   		NODE_ARG="${NODE_ALIAS_MAP[$NODE_INFO]}"
   	else
		NODE_ARG="${NODE_INFO}"
	fi
fi

NUM=$(kubectl get pods -n kube-system --no-headers -owide | grep $POD_ARG | grep "$NODE_ARG" | wc -l)
if [ "$NUM" -gt 1 ]; then
    echo "Multiple Pods are match."
    PODS=()

    for ((i=0; i<NUM; i++))
    do
        POD=$(kubectl get pods -n kube-system --no-headers -owide | grep $POD_ARG $NODE_ARG | awk '{print $1, $2, $3, $6, $7}'| head -n $((i + 1)) | tail -n 1)
        PODS[$i]=$POD
        echo -e "[$i] => \c"
        echo $POD | awk '{printf ("%-50s %-5s %-10s %-20s %-30s\n", $1, $2, $3, $4, $5)}'
    done
    echo -e "Please select one:\c"
    read -r INDEX

    SELECTED_POD=$(echo ${PODS[$INDEX]} | awk '{print $1}')
    kubectl -n kube-system logs -f $SELECTED_POD
elif [ $NUM -eq 0 ]; then
    echo "No Pod is matched"
    exit 1
else
   SELECTED_POD=$(kubectl get pods -n kube-system --no-headers -owide | grep $POD_ARG | grep "$NODE_ARG" | awk '{print $1}')
   echo $SELECTED_POD
   kubectl -n kube-system logs -f $SELECTED_POD
fi
