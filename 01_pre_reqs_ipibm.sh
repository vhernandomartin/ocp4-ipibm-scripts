#!/bin/bash

## VARS ##

MASTERS=(ipibm-master-01 ipibm-master-02 ipibm-master-03)
WORKER_NAME=ipibm-worker
IPIBM_IPV4_IPROUTE=192.168.119.1
IPIBM_IPV6_IPROUTE="[2620:52:0:1001::1]"
IPIBM_IPV4_API_IP=192.168.119.10
IPIBM_IPV4_INGRESS_IP=192.168.119.11
IPIBM_IPV6_API_IP=2620:52:0:1001::10
IPIBM_IPV6_INGRESS_IP=2620:52:0:1001::11
IPIBM_CIDR_IPV4=192.168.119.0/24
IPIBM_CIDR_IPV6=2620:52:0:1001::/64
IPIBM_CNET_CIDR_IPV4=10.132.0.0/14
IPIBM_CNET_CIDR_IPV6=fd01::/48
IPIBM_SNET_CIDR_IPV4=172.30.0.0/16
IPIBM_SNET_CIDR_IPV6=fd02::/112
DEF_CNET_HOST_PREFIX_IPV4=23
DEF_CNET_HOST_PREFIX_IPV6=64
IPIBM_NET=lab-ipibm
PULL_SECRET_FILE="/root/openshift_pull.json"
NEW_PULL_SECRET_FILE="/root/new_openshift_pull.json"

## VARS ##

## FUNCTIONS ##

function install_pkgs () {
  sed -i -e "s|mirrorlist=|#mirrorlist=|g" /etc/yum.repos.d/CentOS-*
  sed -i -e "s|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g" /etc/yum.repos.d/CentOS-*
  dnf swap centos-linux-repos centos-stream-repos -y
  dnf clean all && sleep 30 && dnf -y install pkgconf-pkg-config libvirt-devel gcc python3-libvirt python3 git python3-netifaces bind-utils
  dnf -y install libvirt-libs libvirt-client ipmitool mkisofs tmux make git bash-completion
  dnf -y install python39
  dnf -y install jq
}

function set_vars () {
  OPENSHIFT_RELEASE_IMAGE=$(curl -s https://mirror.openshift.com/pub/openshift-v4/clients/ocp/stable-${OCP4_VER}/release.txt | grep 'Pull From: quay.io' | awk -F ' ' '{print $3}')
  OCP_RELEASE=${OCP4_VER}-x86_64
  MINOR_VERSION=$(echo ${OCP4_VER}|cut -d "." -f 2)
  IP_TYPE=$1
  if [ "${IP_TYPE}" = "ipv4" ]; then
    echo -e "+ Setting vars for a ipv4 cluster."
    NET_TYPE=inet
    IPIBM_INGRESS_IP=$IPIBM_IPV4_INGRESS_IP
    IPIBM_API_IP=$IPIBM_IPV4_API_IP
    IPIBM_IPROUTE=$IPIBM_IPV4_IPROUTE
    SUSHY_EMULATOR_LISTEN_IP="0.0.0.0"
    IPIBM_CIDR=$IPIBM_CIDR_IPV4
    IPIBM_CNET_CIDR=$IPIBM_CNET_CIDR_IPV4
    IPIBM_SNET_CIDR=$IPIBM_SNET_CIDR_IPV4
    DEF_CNET_HOST_PREFIX=$DEF_CNET_HOST_PREFIX_IPV4
    IP=$(ip addr show|grep inet|grep "scope global"|grep -w $NET_TYPE|awk '{print $2}'|cut -d "/" -f 1|tail -1)
    NAMESERVER=$(grep nameserver /etc/resolv.conf |grep -v ":"|awk '{print $2}'|tail -1)
    PTR_RECORD=$(dig -x ${IP} @${NAMESERVER} +short)
  elif [ "${IP_TYPE}" = "ipv6" ]; then
    echo -e "+ Setting vars for a ipv6 cluster."
    NET_TYPE=inet6
    IPIBM_INGRESS_IP=$IPIBM_IPV6_INGRESS_IP
    IPIBM_API_IP=$IPIBM_IPV6_API_IP
    IPIBM_IPROUTE=$IPIBM_IPV6_IPROUTE
    SUSHY_EMULATOR_LISTEN_IP="::"
    IPIBM_CIDR=$IPIBM_CIDR_IPV6
    IPIBM_CNET_CIDR=$IPIBM_CNET_CIDR_IPV6
    IPIBM_SNET_CIDR=$IPIBM_SNET_CIDR_IPV6
    DEF_CNET_HOST_PREFIX=$DEF_CNET_HOST_PREFIX_IPV6
    IP=$(ip addr show|grep inet|grep "scope global"|grep -w $NET_TYPE|awk '{print $2}'|cut -d "/" -f 1)
    NAMESERVER=$(grep nameserver /etc/resolv.conf |grep ":"|grep -v fe80|awk '{print $2}')
    PTR_RECORD=$(dig -6x ${IP} @${NAMESERVER} +short)
  else
    echo -e "+ A valid network type value should be provided: ipv4/ipv6."
  fi
}

function pre_reqs () {
  ssh-keyscan -H ${IPIBM_IPROUTE} >> ~/.ssh/known_hosts
  echo -e "Host=*\nStrictHostKeyChecking=no\n" > ~/.ssh/config

  # Sushy service
  echo -e "+ Configuring Sushy service..."

cat << EOF > /usr/lib/systemd/system/sushy.service
[Unit]
Description=Sushy Libvirt emulator
After=syslog.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sushy-emulator --config /etc/sushy.conf
StandardOutput=syslog
StandardError=syslog
EOF

cat << EOF > /etc/sushy.conf
SUSHY_EMULATOR_LISTEN_IP = u'${SUSHY_EMULATOR_LISTEN_IP}'
SUSHY_EMULATOR_LISTEN_PORT = 8000
SUSHY_EMULATOR_SSL_CERT = None
SUSHY_EMULATOR_SSL_KEY = None
SUSHY_EMULATOR_OS_CLOUD = None
SUSHY_EMULATOR_LIBVIRT_URI = u'qemu+ssh://root@${IPIBM_IPROUTE}/system'
SUSHY_EMULATOR_IGNORE_BOOT_DEVICE = True
SUSHY_EMULATOR_BOOT_LOADER_MAP = {
    u'UEFI': {
        u'x86_64': u'/usr/share/OVMF/OVMF_CODE.secboot.fd',
        u'aarch64': u'/usr/share/AAVMF/AAVMF_CODE.fd'
    },
    u'Legacy': {
        u'x86_64': None,
        u'aarch64': None
    }
}
EOF

  echo -e "\n+ Installing some required packages..."
  pip3 install sushy-tools
  systemctl enable --now sushy && systemctl status sushy

  echo -e "\n+ Creating the install-config.yaml file..."
cat << EOF > install-config.yaml
apiVersion: v1
baseDomain: ${DOMAIN}
networking:
  networkType: OVNKubernetes
  machineNetwork:
  - cidr: ${IPIBM_CIDR}
  clusterNetwork:
  - cidr: ${IPIBM_CNET_CIDR}
    hostPrefix: ${DEF_CNET_HOST_PREFIX}
  serviceNetwork:
  - ${IPIBM_SNET_CIDR}
metadata:
  name: ${CLUSTER_NAME}
compute:
- name: worker
  replicas: ${NUM_WORKERS}
controlPlane:
  name: master
  replicas: 3
platform:
  baremetal:
    apiVIP: ${IPIBM_API_IP}
    ingressVIP: ${IPIBM_INGRESS_IP}
    provisioningNetwork: "Disabled"
    externalBridge: ${IPIBM_NET}
    libvirtURI: qemu+ssh://root@${IPIBM_IPROUTE}/system
    hosts:
    - name: ipibm-master-01
      role: master
      bmc:
        address: ipmi://IPMI_URL:6230
        username: foo
        password: bar
        disableCertificateVerification: True
      bootMACAddress: aa:aa:aa:aa:bc:01
    - name: ipibm-master-02
      role: master
      bmc:
        address: ipmi://IPMI_URL:6230
        username: foo
        password: bar
        disableCertificateVerification: True
      bootMACAddress: aa:aa:aa:aa:bc:02
    - name: ipibm-master-03
      role: master
      bmc:
        address: ipmi://IPMI_URL:6230
        username: foo
        password: bar
        disableCertificateVerification: True
      bootMACAddress: aa:aa:aa:aa:bc:03
EOF

add_workers

echo -e "\n+ Creating the openshift_pull.json file..."
cat << EOF > openshift_pull.json
<INSERT_YOUR_PULL_SECRETS_HERE>
EOF

}

function add_workers () {
  if [ ${NUM_WORKERS} -gt 0 ]; then
    echo -e "\n+ ${NUM_WORKERS} will be deployed at installation time."
    w=1
    while [ "$w" -le "${NUM_WORKERS}" ];
    do
      WORKER_VM=${WORKER_NAME}-0${w}
      cat << EOF >> install-config.yaml
    - name: ${WORKER_VM}
      role: worker
      bmc:
        address: ipmi://IPMI_URL:6230
        username: foo
        password: bar
        disableCertificateVerification: True
      bootMACAddress: aa:aa:aa:aa:bd:0${w}
EOF
      VIRTUALMEDIA_URL=$(/root/find_redfish_host.sh -n=${IP_TYPE} -s=${WORKER_VM})
      counter=1
      while [[ ${VIRTUALMEDIA_URL} = "" ]]
      do
        echo -e "+ Waiting for virtualmedia info..."
        VIRTUALMEDIA_URL=$(/root/find_redfish_host.sh -n=${IP_TYPE} -s=${WORKER_VM})
        echo -e "VIRTUALMEDIA_URL = ${VIRTUALMEDIA_URL}"
        sleep 5
        echo -e "Try $counter..."
        if [ $counter = 12 ]; then
          exit 1
        fi
        let counter++
      done

      patch_install_config ${WORKER_VM} ${VIRTUALMEDIA_URL}
      let w++
    done

  else
    echo -e "\n+ No workers will be deployed at installation time."
  fi
}

function lab_installation () {
  echo -e "\n+ Patching install-config.yaml..."
  PULLSECRET=$(cat /root/openshift_pull.json | tr -d [:space:])
  echo -e "pullSecret: |\n  $PULLSECRET" >> /root/install-config.yaml
  SSHKEY=$(cat /root/.ssh/id_rsa.pub)
  echo -e "sshKey: |\n  $SSHKEY" >> /root/install-config.yaml

  echo -e "\n+ Installing libvirt and other required tools..."

  export CRYPTOGRAPHY_DONT_BUILD_RUST=1
  pip3 install -U pip
  pip3 install python-ironicclient --ignore-installed PyYAML

  echo -e "\n+ Installing httpd and podman..."
  yum install -y httpd podman
  systemctl enable httpd --now

  echo -e "\n+ Downloading oc client and installer..."
  curl -k https://mirror.openshift.com/pub/openshift-v4/clients/ocp/stable-${OCP4_VER}/openshift-client-linux.tar.gz > oc.tar.gz
  tar zxvf oc.tar.gz
  mv oc /usr/bin
  chmod 755 /usr/bin/oc

  echo -e "\n+ Extracting contents from ${OPENSHIFT_RELEASE_IMAGE} payload..."
  oc adm release extract --registry-config $PULL_SECRET_FILE --command=oc --to /tmp $OPENSHIFT_RELEASE_IMAGE
  mkdir /root/bin
  mv /tmp/oc /root/bin
  oc adm release extract --registry-config $PULL_SECRET_FILE --command=openshift-baremetal-install --to /root/bin $OPENSHIFT_RELEASE_IMAGE
  echo $OPENSHIFT_RELEASE_IMAGE > /root/version.txt

}

function redfish_urls () {
  for m in ${MASTERS[@]}
  do
    VIRTUALMEDIA_URL=$(/root/find_redfish_host.sh -n=${IP_TYPE} -s=$m)
    patch_install_config $m $VIRTUALMEDIA_URL
  done

}

function patch_install_config () {
  echo -e "\n+ Patching install-config.yaml file, adding redfish virtual media url for: ${1}"
  sed -i '/'"$1"'/!b;n;n;n;c\        address: '"$2"'' /root/install-config.yaml
}

function installation_images_cache () {
  echo -e "\n+ Downloading RHCOS images and placing them in the httpd web server ready to be served."
  cd /var/www/html
  if [ "${MINOR_VERSION}" -lt "8" ]; then
    echo -e "+ Minor version prior 4.8"
    COMMIT_ID=$(openshift-baremetal-install version|grep "built from commit"|awk '{print $4}')
    RHCOS_PATH=$(curl -s -S https://raw.githubusercontent.com/openshift/installer/$COMMIT_ID/data/data/rhcos.json | jq .baseURI | sed 's/"//g')
    RHCOS_OSP_IMG=$(curl -s -S https://raw.githubusercontent.com/openshift/installer/${COMMIT_ID}/data/data/rhcos.json  | jq .images.openstack.path | sed 's/"//g')
    RHCOS_QEMU_IMG=$(curl -s -S https://raw.githubusercontent.com/openshift/installer/${COMMIT_ID}/data/data/rhcos.json  | jq .images.qemu.path | sed 's/"//g')
    RHCOS_QEMU_SHA=$(curl -s -S https://raw.githubusercontent.com/openshift/installer/$COMMIT_ID/data/data/rhcos.json  | jq -r '.images.qemu["uncompressed-sha256"]')
    RHCOS_OSP_SHA=$(curl -s -S https://raw.githubusercontent.com/openshift/installer/$COMMIT_ID/data/data/rhcos.json  | jq -r '.images.openstack.sha256')
    curl -L ${RHCOS_PATH}${RHCOS_OSP_IMG} > ${RHCOS_OSP_IMG}
    curl -L ${RHCOS_PATH}${RHCOS_QEMU_IMG} > ${RHCOS_QEMU_IMG}
  else
    echo -e "+ Minor version 4.8 or later"
    RHCOS_OSP_URL=$(openshift-baremetal-install coreos print-stream-json | jq -r '.architectures.x86_64.artifacts.openstack.formats["qcow2.gz"].disk.location')
    RHCOS_QEMU_URL=$(openshift-baremetal-install coreos print-stream-json | jq -r '.architectures.x86_64.artifacts.qemu.formats["qcow2.gz"].disk.location')
    RHCOS_QEMU_SHA=$(openshift-baremetal-install coreos print-stream-json | jq -r '.architectures.x86_64.artifacts.qemu.formats["qcow2.gz"].disk["uncompressed-sha256"]')
    RHCOS_OSP_SHA=$(openshift-baremetal-install coreos print-stream-json | jq -r '.architectures.x86_64.artifacts.openstack.formats["qcow2.gz"].disk["sha256"]')
    RHCOS_OSP_IMG=$(basename $RHCOS_OSP_URL)
    RHCOS_QEMU_IMG=$(basename $RHCOS_QEMU_URL)
    curl -L ${RHCOS_OSP_URL} > ${RHCOS_OSP_IMG}
    curl -L ${RHCOS_QEMU_URL} > ${RHCOS_QEMU_IMG}
  fi

  if [ "${IP_TYPE}" = "ipv4" ]; then
    sed -i '/baremetal/a\    clusterOSImage: http://'"${IP}"'/'"${RHCOS_OSP_IMG}"'?sha256='"${RHCOS_OSP_SHA}"'' /root/install-config.yaml
    sed -i '/baremetal/a\    bootstrapOSImage: http://'"${IP}"'/'"${RHCOS_QEMU_IMG}"'?sha256='"${RHCOS_QEMU_SHA}"'' /root/install-config.yaml
  else
    sed -i '/baremetal/a\    clusterOSImage: http://'"[${IP}]"'/'"${RHCOS_OSP_IMG}"'?sha256='"${RHCOS_OSP_SHA}"'' /root/install-config.yaml
    sed -i '/baremetal/a\    bootstrapOSImage: http://'"[${IP}]"'/'"${RHCOS_QEMU_IMG}"'?sha256='"${RHCOS_QEMU_SHA}"'' /root/install-config.yaml
  fi
}

function create_registry () {
  cd /root
  echo -e "\n+ Creating a new disconnected registry..."
  REGISTRY_NAME=$(echo ${PTR_RECORD}|sed 's/.$//')
  echo ${IP} ${REGISTRY_NAME} >> /etc/hosts


  REG_KEY=$(echo -n foo:bar|base64)
  jq ".auths += {\"${REGISTRY_NAME}:5000\": {\"auth\": \"${REG_KEY}\",\"email\": \"test@example.com\"}}" < ${PULL_SECRET_FILE} > ${NEW_PULL_SECRET_FILE}
  mkdir -p /opt/registry/{auth,certs,data,conf}
  cat <<EOF > /opt/registry/conf/config.yml
version: 0.1
log:
  fields:
    service: registry
storage:
  cache:
    blobdescriptor: inmemory
  filesystem:
    rootdirectory: /var/lib/registry
http:
  addr: :5000
  headers:
    X-Content-Type-Options: [nosniff]
health:
  storagedriver:
    enabled: true
    interval: 10s
    threshold: 3
compatibility:
  schema1:
    enabled: true
EOF

  openssl req -newkey rsa:4096 -nodes -sha256 -keyout /opt/registry/certs/domain.key -x509 -days 365 -out /opt/registry/certs/domain.crt -subj "/C=ES/ST=Madrid/L=Madrid/O=test/OU=test/CN=${REGISTRY_NAME}" -addext "subjectAltName=DNS:${REGISTRY_NAME}"
  cp /opt/registry/certs/domain.crt /etc/pki/ca-trust/source/anchors/
  update-ca-trust extract
  htpasswd -bBc /opt/registry/auth/htpasswd foo bar
  echo -e "+ Creating and the registry container..."
  podman create --name registry --net host --security-opt label=disable -v /opt/registry/data:/var/lib/registry:z -v /opt/registry/auth:/auth:z -v /opt/registry/conf/config.yml:/etc/docker/registry/config.yml -e "REGISTRY_AUTH=htpasswd" -e "REGISTRY_AUTH_HTPASSWD_REALM=Registry" -e "REGISTRY_HTTP_SECRET=ALongRandomSecretForRegistry" -e REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd -v /opt/registry/certs:/certs:z -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/domain.crt -e REGISTRY_HTTP_TLS_KEY=/certs/domain.key quay.io/saledort/registry:2
  podman start registry
  mv ${NEW_PULL_SECRET_FILE} ${PULL_SECRET_FILE}
  echo -e "+ Mirroring the release to the new local registry ${REGISTRY_NAME}:5000..."
  oc adm release mirror -a ${PULL_SECRET_FILE} --from=${OPENSHIFT_RELEASE_IMAGE} --to-release-image=${REGISTRY_NAME}:5000/ocp4:${OCP_RELEASE} --to=${REGISTRY_NAME}:5000/ocp4
  echo -e "+ Setting the new imageConentSources in the install-config.yaml file ..."
  sed -i '/pullSecret/,$d' /root/install-config.yaml
  cat << EOF >> /root/install-config.yaml
imageContentSources:
- mirrors:
  - $REGISTRY_NAME:5000/ocp4
  source: quay.io/openshift-release-dev/ocp-v4.0-art-dev
- mirrors:
  - $REGISTRY_NAME:5000/ocp4
  source: quay.io/openshift-release-dev/ocp-release
EOF
  echo -e "+ Adding additionalTrustBundle to the install-config.yaml file to trust the new local registry..."
  echo "additionalTrustBundle: |" >> /root/install-config.yaml
  sed -e 's/^/  /' /opt/registry/certs/domain.crt >>  /root/install-config.yaml

  echo $REGISTRY_NAME:5000/ocp4:$OCP_RELEASE > /root/version.txt

  OCP_PULL_SECRET=$(cat ${PULL_SECRET_FILE} | tr -d [:space:])
  echo -e "pullSecret: |\n  ${OCP_PULL_SECRET}" >> /root/install-config.yaml
  SSHKEY=$(cat /root/.ssh/id_rsa.pub)
  echo -e "sshKey: |\n  $SSHKEY" >> /root/install-config.yaml

  REG_USER_PASSWD=$(cat ${PULL_SECRET_FILE} |jq .auths.\"${REGISTRY_NAME}:5000\".auth -r|base64 -d)
  REG_USER=$(echo ${REG_USER_PASSWD}|cut -d ":" -f 1)
  REG_PASSWD=$(echo ${REG_USER_PASSWD}|cut -d ":" -f 2)
  RH_USER_PASSWD=$(cat ${PULL_SECRET_FILE} | jq .auths.\"registry.redhat.io\".auth -r | base64 -d)
  RH_USER=$(echo ${RH_USER_PASSWD}|cut -d ":" -f 1)
  RH_PASSWD=$(echo ${RH_USER_PASSWD}|cut -d ":" -f 2)
  #OLM_PKGS="advanced-cluster-management,cluster-logging,elasticsearch-operator,kubernetes-nmstate-operator,metering-ocp,performance-addon-operator,rhacs-operator"
  OLM_PKGS="rhacs-operator,local-storage-operator,openshift-gitops-operator,openshift-pipelines-operator-rh,quay-operator"
  PARSED_OLM_PKGS=$(echo $OLM_PKGS|sed 's/,/ /g')

  podman login -u ${REG_USER} -p ${REG_PASSWD} ${REGISTRY_NAME}:5000
  podman login -u ${RH_USER} -p ${RH_PASSWD} registry.redhat.io
  OLM_VERSION=$(curl -s https://api.github.com/repos/operator-framework/operator-registry/releases | grep tag_name | grep -v -- '-rc' | head -1 | awk -F': ' '{print $2}' | sed 's/,//' | xargs)
  curl -Lk https://github.com/operator-framework/operator-registry/releases/download/${OLM_VERSION}/linux-amd64-opm > /usr/bin/opm
  chmod 755 /usr/bin/opm

  OCP_VERSION=$(echo ${OCP_RELEASE}|cut -d "-" -f 1)
  echo -e "\+ pruning the source index of all but the specified packages..."

  if [ "${MINOR_VERSION}" -lt "11" ]; then
    opm index prune -f registry.redhat.io/redhat/redhat-operator-index:v${OCP_VERSION} -p ${OLM_PKGS} -t ${REGISTRY_NAME}:5000/olm-index/redhat-operator-index:v${OCP_VERSION}
  else
    mkdir -p pruned-catalog/configs
    for olmpkg in ${PARSED_OLM_PKGS[@]}
    do
      opm render registry.redhat.io/redhat/redhat-operator-index:v${OCP_VERSION} | jq 'select( .package == "'"$olmpkg"'" or .name == "'"$olmpkg"'")' >> pruned-catalog/configs/index.json
    done

    opm generate dockerfile pruned-catalog/configs && cd pruned-catalog/
    podman build -t ${REGISTRY_NAME}:5000/olm-index/redhat-operator-index:v${OCP_VERSION} -f configs.Dockerfile .
  fi

  echo -e "\n+ Pushing the new image ${REGISTRY_NAME}:5000/olm-index/redhat-operator-index:v${OCP_VERSION} ..."
  podman push ${REGISTRY_NAME}:5000/olm-index/redhat-operator-index:v${OCP_VERSION} --authfile ${PULL_SECRET_FILE}
  echo -e "\n+ Mirroring the operator catalog..."
  oc adm catalog mirror ${REGISTRY_NAME}:5000/olm-index/redhat-operator-index:v${OCP_VERSION} ${REGISTRY_NAME}:5000 --registry-config=${PULL_SECRET_FILE}
  echo -e "\n+ New manifests have been created and placed in :"
  ls -l /root/manifests-redhat-operator-index*
  echo -e "\n+ Moving these manifests to /root/manifests :"
  mkdir /root/manifests && cp /root/manifests-redhat-operator-index-*/imageContentSourcePolicy.yaml /root/manifests ; cp /root/manifests-redhat-operator-index-*/catalogSource.yaml /root/manifests
  ls -l /root/manifests/*

  echo -e "\n+ Creating a new manifest for OperatorHub, disabling AllDefaultSources..."
  cat << EOF > /root/manifests/99-operatorhub.yaml
apiVersion: config.openshift.io/v1
kind: OperatorHub
metadata:
  name: cluster
spec:
  disableAllDefaultSources: true
EOF

}

function configure_chrony () {
  echo -e "\n+ Creating a new MachineConfigs for chrony service..."
  export NTP_DATA=$((cat << EOF
    pool 0.rhel.pool.ntp.org iburst
    driftfile /var/lib/chrony/drift
    makestep 1.0 3
    rtcsync
    logdir /var/log/chrony
EOF
) | base64 -w0)

  cat << EOF > /root/manifests/99-openshift-worker-chrony.yaml
apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  labels:
    machineconfiguration.openshift.io/role: worker
  name: worker-chrony-configuration
spec:
  config:
    ignition:
      config: {}
      security:
        tls: {}
      timeouts: {}
      version: 3.1.0
    networkd: {}
    passwd: {}
    storage:
      files:
      - contents:
          source: data:text/plain;charset=utf-8;base64,${NTP_DATA}
        mode: 420
        overwrite: true
        path: /etc/chrony.conf
EOF

  cat << EOF > /root/manifests/99-openshift-master-chrony.yaml
apiVersion: machineconfiguration.openshift.io/v1
kind: MachineConfig
metadata:
  labels:
    machineconfiguration.openshift.io/role: master
  name: master-chrony-configuration
spec:
  config:
    ignition:
      config: {}
      security:
        tls: {}
      timeouts: {}
      version: 3.1.0
    networkd: {}
    passwd: {}
    storage:
      files:
      - contents:
          source: data:text/plain;charset=utf-8;base64,${NTP_DATA}
        mode: 420
        overwrite: true
        path: /etc/chrony.conf
EOF

  ls -l /root/manifests/*
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
    echo -e "+ Usage: $0 -n=<IP_TYPE> -w=<NUM_WORKERS> -d=<DOMAIN_NAME> -c=<CLUSTER_NAME> -v=<OCP4_VERSION>"
    echo -e "Valid IP_TYPE values: ipv4/ipv6"
    echo -e "Valid number of workers 1-9"
    echo -e "Provide a valid domain name, if not present example.com will be set as the default domain"
    echo -e "Provide a valid cluster name, if not present lab will be set as the default cluster name"
    echo -e "OpenShift 4 minor version only allowed, i.e. 4.6, 4.7, 4.8... "
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
    -v=*|--version=*)
    OCP4_VER="${i#*=}"
    shift
    ;;
    *)
    echo -e "+ Usage: $0 -n=<IP_TYPE> -w=<NUM_WORKERS> -d=<DOMAIN_NAME> -c=<CLUSTER_NAME> -v=<OCP4_VERSION>"
    echo -e "Valid IP_TYPE values: ipv4/ipv6"
    echo -e "Valid number of workers 1-9"
    echo -e "Provide a valid domain name, if not present example.com will be set as the default domain"
    echo -e "Provide a valid cluster name, if not present lab will be set as the default cluster name"
    echo -e "OpenShift 4 minor version only allowed, i.e. 4.6, 4.7, 4.8... "
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

install_pkgs
set_vars ${IP_TYPE}
pre_reqs
lab_installation
redfish_urls
installation_images_cache
create_registry
configure_chrony

## MAIN ##
