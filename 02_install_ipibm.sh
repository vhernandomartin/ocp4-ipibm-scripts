#!/bin/bash

## VARS ##

IPIBM_IPV4_API_IP=192.168.119.10
IPIBM_IPV4_INGRESS_IP=192.168.119.11
IPIBM_IPV6_API_IP=2620:52:0:1001::10
IPIBM_IPV6_INGRESS_IP=2620:52:0:1001::11
export KUBECONFIG=/root/ocp/auth/kubeconfig
export OPENSHIFT_INSTALL_RELEASE_IMAGE_OVERRIDE=$(cat /root/version.txt)

## VARS ##

## FUNCTIONS ##

function set_vars () {
  IP_TYPE=$1
  if [ "${IP_TYPE}" = "ipv4" ]; then
    echo -e "+ Setting vars for a ipv4 cluster."
    NET_TYPE=inet
    IPIBM_INGRESS_IP=$IPIBM_IPV4_INGRESS_IP
    IPIBM_API_IP=$IPIBM_IPV4_API_IP
  elif [ "${IP_TYPE}" = "ipv6" ]; then
    echo -e "+ Setting vars for a ipv6 cluster."
    NET_TYPE=inet6
    IPIBM_INGRESS_IP=$IPIBM_IPV6_INGRESS_IP
    IPIBM_API_IP=$IPIBM_IPV6_API_IP
  else
    echo -e "+ A valid network type value should be provided: ipv4/ipv6."
  fi
}

function deploy_openshift () {
  mkdir -p /root/ocp/openshift
  cd /root
  cp install-config.yaml ocp

  openshift-baremetal-install --dir ocp --log-level debug create manifests
  cp /root/manifests/*.*ml /root/ocp/openshift/.

  echo ${IPIBM_INGRESS_IP} apps console-openshift-console.apps.${CLUSTER_NAME}.${DOMAIN} oauth-openshift.apps.${CLUSTER_NAME}.${DOMAIN} prometheus-k8s-openshift-monitoring.apps.${CLUSTER_NAME}.${DOMAIN} >> /etc/hosts
  echo ${IPIBM_API_IP} api api.${CLUSTER_NAME}.${DOMAIN} api-int.${CLUSTER_NAME}.${DOMAIN} >> /etc/hosts

  openshift-baremetal-install --dir ocp --log-level debug create cluster
  openshift-baremetal-install --dir ocp --log-level debug wait-for install-complete || openshift-baremetal-install --dir ocp --log-level debug wait-for install-complete
}
## FUNCTIONS ##

## MENU ##
if [[ -z "$@" ]]; then
  echo -e "Missing arguments, run the following for help: $0 --help "
  exit 1
fi

for i in "$@"; do
  case $i in
    -h|--help)
    echo -e "+ Usage: $0 -n=<IP_TYPE> -d=<DOMAIN_NAME> -c=<CLUSTER_NAME>"
    echo -e "Valid IP_TYPE values: ipv4/ipv6"
    echo -e "Provide a valid domain name, if not present example.com will be set as the default domain"
    echo -e "Provide a valid cluster name, if not present lab will be set as the default cluster name"
    exit 0
    ;;
    -n=*|--net=*)
    IP_TYPE="${i#*=}"
    shift
    ;;
    -d=*|--domain=*)
    DOMAIN="${i#*=}"
    shift
    ;;
    -c=*|--clustername=*)
    CLUSTER_NAME="${i#*=}"
    shift
    ;;
    *)
    echo -e "+ Usage: $0 -n=<IP_TYPE> -d=<DOMAIN_NAME> -c=<CLUSTER_NAME>"
    echo -e "Valid IP_TYPE values: ipv4/ipv6"
    echo -e "Provide a valid domain name, if not present example.com will be set as the default domain"
    echo -e "Provide a valid cluster name, if not present lab will be set as the default cluster name"
    exit 1
  esac
done

if [[ -z "$DOMAIN" ]]; then
  DOMAIN=example.com
fi
if [[ -z "$CLUSTER_NAME" ]]; then
  CLUSTER_NAME=lab
fi

## MENU ##

## MAIN ##

set_vars ${IP_TYPE}
deploy_openshift

## MAIN ##
