#!/bin/bash

## ENV VARS ##
LIBVIRT_HOME=/var/lib/libvirt
DNSMASQ_HOME=$LIBVIRT_HOME/dnsmasq
LIBVIRT_IMGS=$LIBVIRT_HOME/images
INSTALLER_VM=ipibm-installer
MASTERS=(ipibm-master-01 ipibm-master-02 ipibm-master-03)
WORKERS=(ipibm-worker-01 ipibm-worker-02 ipibm-worker-03)
IPIBM_NET=lab-ipibm
OCP_DOMAIN=lab.example.com
ID_RSA_PUB=$(cat /root/.ssh/id_rsa.pub)
## ENV VARS ##

echo -e "+ Deleting VMs..."
for i in `virsh list --all --name|grep ipibm`; do virsh destroy $i; virsh undefine $i; done

echo -e "\n+ Deleting Networks..."
virsh net-destroy ${IPIBM_NET}
virsh net-undefine ${IPIBM_NET}
nmcli conn delete ${IPIBM_NET}
DNSMASQ_FILES=$(ls $DNSMASQ_HOME/$IPIBM_NET.*|wc -l)
if [ $DNSMASQ_FILES -gt 0 ]; then
  echo -e "\n+ There are some networks already configured in dnsmasq ($DNSMASQ_FILES), deleting those files..."
  rm -fR ${DNSMASQ_HOME}/${IPIBM_NET}.*
else
  echo -e "\n+ No network files for $IPIBM_NET network..."
fi

echo -e "\n+ Removing VM disks..."
for m in ${MASTERS[@]}
do
  rm ${LIBVIRT_IMGS}/${m}.qcow2
done

for w in ${WORKERS[@]}
do
  rm ${LIBVIRT_IMGS}/${w}.qcow2
done

rm ${LIBVIRT_IMGS}/${INSTALLER_VM}.qcow2 && rm ${LIBVIRT_IMGS}/${INSTALLER_VM}.iso

if [ -d /root/${INSTALLER_VM} ]; then
  echo -e "\n+ The path /root/${INSTALLER_VM} exists, deleting it..."
  rm -fR /root/${INSTALLER_VM}
else
  echo -e "\n+ The path /root/${INSTALLER_VM} doesn't exists, nothing to do"
fi
