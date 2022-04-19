#!/usr/bin/env bash

# Define your aliases for K8s resources
declare -A RS_ALIAS_MAP=(
    [p]="pods"
    [s]="svc"
    [n]="node"
    [dp]="deploy"
    [da]="daemonset"
    [ep]="endpoint"
)

# Define your aliases for namespace
declare -A NS_ALIAS_MAP=(
    [k]="kube-system"
    [t]="antrea-test"
    [it]="antrea-ipam-test"
)

function print_aliases {
    printf "All aliases for K8s resources are listed below:\n"
    for ALIAS in "${!RS_ALIAS_MAP[@]}"; do
        printf "       %-10s         %s\n" "$ALIAS" "${RS_ALIAS_MAP[$ALIAS]}"
    done

    printf "\nAll aliases for namespaces are listed below:\n"
    for ALIAS in "${!NS_ALIAS_MAP[@]}"; do
        printf "       %-10s         %s\n" "$ALIAS" "${NS_ALIAS_MAP[$ALIAS]}"
    done
}

_usage="Usage: $0 [arg1] [--namespace|-n (namespace string or alias)] [--wide|-w] [--show-labels|-l] [--help|-h] [-g (grep -E string)] [-gv (grep -v -E string)]
Watch a source of K8s.
       arg1               Name or alias for a K8s resource, like svc, pod, node, etc
       --namespace, -n    Namespace or alias of namespace
       --wide, -w         Equal to --o wide
       --show-labels, -l  Equal to --show-labels
       -g                 Equal to grep -E
       -gv                Equal to grep -v -E
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

RESOURCE_INFO="$1"
RESOURCE=$1
if [ "${RS_ALIAS_MAP[$RESOURCE_INFO]}" ]; then
    RESOURCE=${RS_ALIAS_MAP[$RESOURCE_INFO]}
fi

NS_ARG="-A"
WIDE_ARG=""
LABEL_ARG=""
GREP_ARG=""

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
        -wl|-lw)
            WIDE_ARG="-owide"
            LABEL_ARG="--show-labels"
            shift
            ;;
        --wide|-w)
            WIDE_ARG="-owide"
            shift
            ;;
        --show-labels|-l)
            LABEL_ARG="--show-labels"
            shift
            ;;
        -g)
            GREP_ARG="|grep -E $3"
            shift 2
            ;;
        -gv)
            GREP_ARG="|grep -v -E $3"
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

echo $RESOURCE $NS_ARG $LABEL_ARG $WIDE_ARG

watch -n1 kubectl get $RESOURCE --no-headers $NS_ARG $WIDE_ARG $LABEL_ARG $GREP_ARG
