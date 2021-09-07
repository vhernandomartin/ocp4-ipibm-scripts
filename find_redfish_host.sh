#/bin/bash

## FUNCTIONS ##
function get_host_ip () {
  IP_TYPE=$1
  if [ "${IP_TYPE}" = "ipv4" ]; then
    NET_TYPE=inet
    IP=$(ip addr show eth1|grep -w $NET_TYPE|grep "scope global"|awk '{print $2}'|cut -d "/" -f 1)
  elif [ "${IP_TYPE}" = "ipv6" ]; then
    NET_TYPE=inet6
    IP=[$(ip addr show eth1|grep -w $NET_TYPE|grep "scope global"|awk '{print $2}'|cut -d "/" -f 1)]
  else
    echo -e "+ A valid network type value should be provided: ipv4/ipv6."
  fi

}

function find_redfish_urls () {
for server in $(curl -s http://${IP}:8000/redfish/v1/Systems/|jq -r '.Members[]."@odata.id"')
  do
    SERVERNAME=$(curl -s http://${IP}:8000$server|jq -r '.Name')
    if [ "$SERVERNAME" = "$1" ]; then
      SERVERSYS=$server
      MANAGEID=$(curl -s http://${IP}:8000$server|jq -r '.Links.ManagedBy[]."@odata.id"')
      VIRTUALMEDIA=$(curl -s http://${IP}:8000$MANAGEID|jq -r '.VirtualMedia."@odata.id"')
      echo "redfish-virtualmedia+http://${IP}:8000$server"
    else
      continue
    fi
  done
}
## FUNCTIONS ##

## MENU ##
if [[ -z "$@" ]]; then
  echo -e "Missing arguments, run the following for help: $0 --help "
  exit 1
fi

for i in "$@"; do
  case $i in
    -h=*|--help=*)
    echo -e "\n+ Usage: $0 -n=[IP_TYPE]"
    echo -e "Valid IP_TYPE values: ipv4/ipv6"
    exit 0
    ;;
    -n=*|--net=*)
    IP_TYPE="${i#*=}"
    shift
    ;;
    -s=*|server=*)
    SERVER="${i#*=}"
    shift
    ;;
    *)
    echo -e "\n+ Usage: $0 -n=[IP_TYPE]"
    echo -e "Valid IP_TYPE values: ipv4/ipv6"
    exit 1
  esac
done
## MENU ##

## MAIN ##
get_host_ip ${IP_TYPE}
find_redfish_urls ${SERVER}
## MAIN ##
