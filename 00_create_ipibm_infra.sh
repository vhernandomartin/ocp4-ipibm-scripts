#!/bin/bash

## ENV VARS ##
LIBVIRT_HOME=/var/lib/libvirt
LIBVIRT_IMGS=$LIBVIRT_HOME/images
INSTALLER_VM=ipibm-installer
IPIBM_VM=ipibm-master
IPIBM_NET=lab-ipibm
IPIBM_CIDR_IPV4=192.168.119.1/24
IPIBM_IPV4_IPROUTE=192.168.119.1
IPIBM_IPV4_PREFIX=24
IPIBM_IPV4_INSTALLER_IP=192.168.119.100
IPIBM_IPV4_API_IP=192.168.119.10
IPIBM_IPV4_INGRESS_IP=192.168.119.11
IPIBM_CIDR_IPV6=2620:52:0:1001::1/64
IPIBM_IPV6_IPROUTE=2620:52:0:1001::1
IPIBM_IPV6_PREFIX=64
IPIBM_IPV6_INSTALLER_IP=2620:52:0:1001::100
IPIBM_IPV6_API_IP=2620:52:0:1001::10
IPIBM_IPV6_INGRESS_IP=2620:52:0:1001::11
IPV4_RANGE_START=192.168.119.2
IPV4_RANGE_END=192.168.119.254
IPV6_RANGE_START=2620:52:0:1001::2
IPV6_RANGE_END=2620:52:0:1001::ffff
ID_RSA_PUB=$(cat /root/.ssh/id_rsa.pub)
MASTERS=(ipibm-master-01 ipibm-master-02 ipibm-master-03)
MASTERS_IPV4=(192.168.119.20 192.168.119.21 192.168.119.22)
MASTERS_IPV6=(2620:52:0:1001::20 2620:52:0:1001::21 2620:52:0:1001::22)
MASTERS_MAC_IPV4=(aa:aa:aa:aa:bc:01 aa:aa:aa:aa:bc:02 aa:aa:aa:aa:bc:03)
MASTERS_MAC_IPV6=(00:03:00:01:aa:aa:aa:aa:bc:01 00:03:00:01:aa:aa:aa:aa:bc:02 00:03:00:01:aa:aa:aa:aa:bc:03)
INSTALLER_MAC_IPV4=aa:aa:aa:aa:bc:00
INSTALLER_MAC_IPV6=00:03:00:01:aa:aa:aa:aa:bc:00
WORKER_MAC_IPV4=aa:aa:aa:aa:bd:0
WORKER_MAC_IPV6=00:03:00:01:aa:aa:aa:aa:bd:0
WORKER_IPV4=192.168.119.3
WORKER_IPV6=2620:52:0:1001::3
WORKER_NAME=ipibm-worker
RADVD_PREFIX=$(echo $IPIBM_CIDR_IPV6|sed 's/1\//\//g')
## ENV VARS ##

function set_vars () {
  OCP_DOMAIN=${CLUSTER_NAME}.${DOMAIN}
  IP_TYPE=$1
  if [ "${IP_TYPE}" = "ipv4" ]; then
    echo -e "+ Setting vars for a ipv4 cluster."
    echo -e "+ The network range configured is: ${IPIBM_CIDR_IPV4}"
    IPV="ip4"
    IPFAMILY="ipv4"
    IPIBM_CIDR=${IPIBM_CIDR_IPV4}
    IPV4_METHOD="manual"
    IPV6_METHOD="disabled"
    IPROUTE=${IPIBM_IPV4_IPROUTE}
    IPPREFIX=${IPIBM_IPV4_PREFIX}
    INSTALLER_IP=${IPIBM_IPV4_INSTALLER_IP}
    API_IP=${IPIBM_IPV4_API_IP}
    INGRESS_IP=${IPIBM_IPV4_INGRESS_IP}
    HOSTIDMAC="host mac"
    IP_RANGE_START=${IPV4_RANGE_START}
    IP_RANGE_END=${IPV4_RANGE_END}
    MASTERS_IP=("${MASTERS_IPV4[@]}")
    MASTERS_MAC=("${MASTERS_MAC_IPV4[@]}")
    INSTALLER_MAC=${INSTALLER_MAC_IPV4}
    WORKER_MAC_IP=${WORKER_MAC_IPV4}
    WORKER_IP=${WORKER_IPV4}
  elif [ "${IP_TYPE}" = "ipv6" ]; then
    echo -e "+ Setting vars for a ipv6 cluster."
    echo -e "+ The network range configured is: ${IPIBM_CIDR_IPV6}"
    IPV="ip6"
    IPFAMILY="ipv6"
    IPIBM_CIDR=${IPIBM_CIDR_IPV6}
    IPV4_METHOD="disabled"
    IPV6_METHOD="manual"
    IPROUTE=${IPIBM_IPV6_IPROUTE}
    IPPREFIX=${IPIBM_IPV6_PREFIX}
    INSTALLER_IP=${IPIBM_IPV6_INSTALLER_IP}
    API_IP=${IPIBM_IPV6_API_IP}
    INGRESS_IP=${IPIBM_IPV6_INGRESS_IP}
    HOSTIDMAC="host id"
    IP_RANGE_START=${IPV6_RANGE_START}
    IP_RANGE_END=${IPV6_RANGE_END}
    MASTERS_IP=("${MASTERS_IPV6[@]}")
    MASTERS_MAC=("${MASTERS_MAC_IPV6[@]}")
    INSTALLER_MAC=${INSTALLER_MAC_IPV6}
    WORKER_MAC_IP=${WORKER_MAC_IPV6}
    WORKER_IP=${WORKER_IPV6}
    echo -e "+ Setting net.ipv6 required values..."
    sysctl -w net.ipv6.conf.all.accept_ra=2
    sysctl -w net.ipv6.conf.all.forwarding=1
  else
    echo -e "+ A valid network type value should be provided: ipv4/ipv6."
  fi
}

## FUNCTIONS ##
function check_binary () {
  BINARY=$1
  # Check whether a specific binary exists or not
  if [ "$(which $BINARY)" = "" ]; then
    echo -e "\n+ $BINARY is not present in the $PATH or it is not installed"
    echo -e "+ Look for $BINARY in custom PATHs or try to install it with dnf or yum"
    exit 1
  else
    echo -e "\n+ $BINARY is already installed: $(which $BINARY)"
  fi
}

function create_installer_image () {
  # First of all check if the CentOS 8 Generic Cloud image is already downloaded
  CENTOS_IMGS=$(ls $LIBVIRT_IMGS/CentOS-8-GenericCloud-8.*)
  if [ -f "$CENTOS_IMGS" ]; then
    echo "+ There is already an image, proceeding with that image..."
    echo -e "\t\__>$CENTOS_IMGS"
  else
    echo "+ No CentOS image found, downloading a new image..."
    curl https://cloud.centos.org/centos/8/x86_64/images/CentOS-8-GenericCloud-8.4.2105-20210603.0.x86_64.qcow2 > $LIBVIRT_IMGS/CentOS-8-GenericCloud-8.4.2105-20210603.0.x86_64.qcow2
    chown qemu:qemu $LIBVIRT_IMGS/CentOS-8-GenericCloud-8.4.2105-20210603.0.x86_64.qcow2
  fi

  # Creating disk images for installer and master/worker node for SNO
  check_binary qemu-img
  qemu-img create -f qcow2 -F qcow2 -b ${LIBVIRT_IMGS}/CentOS-8-GenericCloud-8.4.2105-20210603.0.x86_64.qcow2 ${LIBVIRT_IMGS}/${INSTALLER_VM}.qcow2 500G
}

function create_image () {
  SERVERNAME=$1
  # Creating qcow images for server $SERVERNAME
  check_binary qemu-img
  qemu-img create -f qcow2 ${LIBVIRT_IMGS}/${SERVERNAME}.qcow2 100G
}

function create_cloud_init_config () {
  # We need to create a temp dir to make the custom cloud init scripts and iso
  echo -e "\n+ Creating temp dir and cloud-init config..."
  mkdir /root/$INSTALLER_VM && cd /root/$INSTALLER_VM

# meta-data file
cat << EOF > meta-data
instance-id: ${INSTALLER_VM}
local-hostname: ${INSTALLER_VM}
EOF

#user-data file
cat << EOF > user-data
#cloud-config
preserve_hostname: False
hostname: ${INSTALLER_VM}
fqdn: ${INSTALLER_VM}.${OCP_DOMAIN}
user: test
password: test
chpasswd: {expire: False}
ssh_pwauth: True
ssh_authorized_keys:
  - ${ID_RSA_PUB}
chpasswd:
  list: |
     root:test
     test:test
  expire: False
network:
  config: disabled
runcmd:
- sed -i -e 's/^.*\(ssh-rsa.*\).*$/\1/' /root/.ssh/authorized_keys
EOF

  # Time to create the new image including user-data and meta-data, this will be used to inject the cloud-init customizations.
  genisoimage -output ${INSTALLER_VM}.iso -volid cidata -joliet -rock user-data meta-data
  cp ${INSTALLER_VM}.iso ${LIBVIRT_IMGS}
}

function networks () {
echo -e "\n+ Defining virsh network and applying configuration..."
cat << EOF > ${IPIBM_NET}-network.xml
<network>
  <name>${IPIBM_NET}</name>
  <forward mode='nat'>
    <nat>
      <port start='1024' end='65535'/>
    </nat>
  </forward>
  <bridge name='${IPIBM_NET}' stp='on' delay='0'/>
  <mac address='52:54:00:eb:3a:aa'/>
  <domain name='${IPIBM_NET}'/>
  <dns>
    <host ip='${API_IP}'>
      <hostname>api</hostname>
      <hostname>api-int.${OCP_DOMAIN}</hostname>
      <hostname>api.${OCP_DOMAIN}</hostname>
    </host>
    <host ip='${INGRESS_IP}'>
      <hostname>apps</hostname>
      <hostname>console-openshift-console.apps.${OCP_DOMAIN}</hostname>
      <hostname>oauth-openshift.apps.${OCP_DOMAIN}</hostname>
      <hostname>prometheus-k8s-openshift-monitoring.apps.${OCP_DOMAIN}</hostname>
      <hostname>canary-openshift-ingress-canary.apps.${OCP_DOMAIN}</hostname>
      <hostname>assisted-service-open-cluster-management.apps.${OCP_DOMAIN}</hostname>
      <hostname>assisted-service-assisted-installer.apps.${OCP_DOMAIN}</hostname>
    </host>
  </dns>
  <ip family='${IPFAMILY}' address='${IPROUTE}' prefix='${IPPREFIX}'>
    <dhcp>
      <range start='${IP_RANGE_START}' end='${IP_RANGE_END}'/>
      <${HOSTIDMAC}='${MASTERS_MAC[0]}' name='${MASTERS[0]}' ip='${MASTERS_IP[0]}'/>
      <${HOSTIDMAC}='${MASTERS_MAC[1]}' name='${MASTERS[1]}' ip='${MASTERS_IP[1]}'/>
      <${HOSTIDMAC}='${MASTERS_MAC[2]}' name='${MASTERS[2]}' ip='${MASTERS_IP[2]}'/>
    </dhcp>
  </ip>
</network>
EOF

  virsh net-define ${IPIBM_NET}-network.xml
  virsh net-autostart ${IPIBM_NET}
  virsh net-start ${IPIBM_NET}
}

function create_workers () {
  if [ ${NUM_WORKERS} -gt 0 ]; then
    echo -e "\n+ ${NUM_WORKERS} workers will be deployed at installation time."
    w=1
    while [ "${w}" -le "${NUM_WORKERS}" ];
    do
      WORKER_VM=${WORKER_NAME}-0${w}
      WORKER_MAC="aa:aa:aa:aa:bd:0${w}"
      WORKER_MAC_DHCP="${WORKER_MAC_IP}${w}"
      WORKER_IP_DHCP="${WORKER_IP}${w}"
      virsh net-update ${IPIBM_NET} add ip-dhcp-host "<${HOSTIDMAC}='${WORKER_MAC_DHCP}' name='${WORKER_VM}' ip='${WORKER_IP_DHCP}'/>" --live --config
      create_image ${WORKER_VM}
      virt-install --virt-type=kvm --name=${WORKER_VM} --ram 16384 --vcpus 8 --hvm --network network=${IPIBM_NET},model=virtio,mac=${WORKER_MAC} --disk ${LIBVIRT_IMGS}/${WORKER_VM}.qcow2,device=disk,bus=scsi,format=qcow2 --os-type Linux --os-variant rhel8.0 --graphics none --import --noautoconsole
      sleep 2
      virsh destroy ${WORKER_VM}
      let w++
    done

  else
    echo -e "\n+ No workers will be deployed at installation time."
  fi
}

function create_vms () {
  # Check whether virt-install binary exists or not
  check_binary virt-install

  # Masters Installation
  echo -e "\n+ Installing master servers..."
  j=0
  for m in ${MASTERS[@]}
  do
    create_image $m
    virt-install --virt-type=kvm --name=${m} --ram 16384 --vcpus 8 --hvm --network network=${IPIBM_NET},model=virtio,mac=${MASTERS_MAC_IPV4[j]} --disk ${LIBVIRT_IMGS}/${m}.qcow2,device=disk,bus=scsi,format=qcow2 --os-type Linux --os-variant rhel8.0 --graphics none --import --noautoconsole
    sleep 2
    virsh destroy ${m}
    let j++
  done

  # Installer deployment
  echo -e "\n+ Installing installer server..."
  virt-install --virt-type=kvm --name=${INSTALLER_VM} --ram 8192 --vcpus 8 --hvm --network network=default,model=virtio,mac=aa:aa:aa:aa:cc:00 --network network=${IPIBM_NET},model=virtio,mac=${INSTALLER_MAC_IPV4} --disk ${LIBVIRT_IMGS}/${INSTALLER_VM}.qcow2,device=disk,bus=scsi,format=qcow2 --disk ${LIBVIRT_IMGS}/${INSTALLER_VM}.iso,device=cdrom --os-type Linux --os-variant rhel8.0 --graphics none --import --noautoconsole

}

function config_dns_hosts () {
  check_binary virsh
  while [[ ${IP} = "" ]]
  do
    IP=$(virsh net-dhcp-leases ${IPIBM_NET} |grep ${INSTALLER_MAC_IPV4}|tail -1|awk '{print $5}'|cut -d "/" -f 1)
    echo -e "+ Waiting to grab an IP from DHCP..."
    sleep 5
  done
  echo -e "+ IP already assigned: ${IP}"
  virsh net-update ${IPIBM_NET} add dns-host "<host ip='${IP}'> <hostname>${INSTALLER_VM}</hostname> <hostname>${INSTALLER_VM}.${OCP_DOMAIN}</hostname> </host>" --live --config
  copy_id_rsa ${IP}
  copy_install_files ${IP}
}

function copy_id_rsa () {
  IP=$1
  echo -e "\n+ Waiting 90seg to let the ${INSTALLER_VM} boot properly..."
  sleep 90
  scp /root/.ssh/id_rsa* root@[${IP}]:/root/.ssh/.
}

function copy_install_files () {
  IP=$1
  echo -e "\n+ Copying install files to ${INSTALLER_VM} with IP: ${IP} ..."
  scp ${SCRIPT_PATH}/01_pre_reqs_ipibm.sh ${SCRIPT_PATH}/02_install_ipibm.sh ${SCRIPT_PATH}/find_redfish_host.sh root@[${IP}]:/root/.
}

function install_radvd () {
  dnf -y install radvd
  cat << EOF > /etc/radvd.conf
interface ${IPIBM_NET}
{
   AdvManagedFlag on;
   AdvSendAdvert on;
   MinRtrAdvInterval 30;
   MaxRtrAdvInterval 100;
   AdvDefaultLifetime 9000;
   prefix ${RADVD_PREFIX}
   {
        AdvOnLink on;
        AdvAutonomous on;
        AdvRouterAddr on;
   };
   route ::/0 {
        AdvRouteLifetime 9000;
        AdvRoutePreference low;
        RemoveRoute on;
   };
};
EOF
  sysctl -w net.ipv6.conf.all.accept_ra=2
  sysctl -w net.ipv6.conf.all.forwarding=1
  systemctl enable radvd --now
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
    echo -e "+ Usage: $0 -n=<IP_TYPE> -w=<NUM_WORKERS> -d=<DOMAIN_NAME> -c=<CLUSTER_NAME>"
    echo -e "Valid IP_TYPE values: ipv4/ipv6"
    echo -e "Valid number of workers 1-9"
    echo -e "Provide a valid domain name, if not present example.com will be set as the default domain"
    echo -e "Provide a valid cluster name, if not present lab will be set as the default cluster name"
    exit 0
    ;;
    -n=*|--net=*)
    IP_TYPE="${i#*=}"
    shift
    ;;
    -w=*|--workers=*)
    NUM_WORKERS="${i#*=}"
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
    echo -e "+ Usage: $0 -n=<IP_TYPE> -w=<NUM_WORKERS> -d=<DOMAIN_NAME> -c=<CLUSTER_NAME>"
    echo -e "Valid IP_TYPE values: ipv4/ipv6"
    echo -e "Valid number of workers 1-9"
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

SCRIPT_PATH=$(dirname $(realpath $0))
## MENU ##

## MAIN ##

set_vars ${IP_TYPE}
create_installer_image
create_cloud_init_config
networks
create_vms
create_workers
config_dns_hosts

## MAIN ##
