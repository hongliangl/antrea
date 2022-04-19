#!/usr/bin/env bash

if [ $# != 1 ] ; then
	    echo "USAGE: $0 [string to match Antrea Agent Pod]"
        exit
fi

CMD_DUMP_TABLES='ovs-ofctl dump-tables br-int'
POD_INFO=$1
NUM=$(kubectl get pods -o wide -n kube-system --no-headers | grep "antrea-agent-" | grep -c $POD_INFO)
if [ "$NUM" -gt 1 ]; then
    echo "Multiple Antrea Agent Pods are match."
    PODS=()

    for ((i=0; i<NUM; i++))
    do
        POD=$(kubectl get pods -o wide -n kube-system --no-headers | grep $POD_INFO | awk '{print $1, $2, $3, $6, $7}'| head -n $((i + 1)) | tail -n 1)
        PODS[$i]=$POD
        echo -e "[$i] => \c"
        echo $POD | awk '{printf ("%-50s %-5s %-10s %-20s %-30s\n", $1, $2, $3, $4, $5)}'
    done
    echo -e "Please select one:\c"
    read -r INDEX

    SELECTED_POD=$(echo ${PODS[$INDEX]} | awk '{print $1}')
    kubectl exec -it -n kube-system $SELECTED_POD -c antrea-ovs -- $CMD_DUMP_TABLES | grep -E " [0-9]* \(\"" | awk -F\" '{print $1 $2}' | awk -F\( '{printf("%-12s %s\n", $1,$2)}'
elif [ $NUM -eq 0 ]; then
    echo "No Antrea Agent Pod is matched"
    exit 1
else
    SELECTED_POD=$(kubectl get pods -o wide -n kube-system | grep antrea-agent- | grep $POD_INFO | awk '{print $1}')
    kubectl exec -it -n kube-system $SELECTED_POD -c antrea-ovs -- $CMD_DUMP_TABLES | grep -E " [0-9]* \(\"" | awk -F\" '{print $1 $2}' | awk -F\( '{printf("%-12s %s\n", $1,$2)}'
fi



