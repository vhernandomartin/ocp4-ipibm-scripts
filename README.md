# ocp4-ipibm-scripts
## Description

**Disclaimer: This procedure is not officially supported, it has been written just for testing purposes.**

This repository contains a set of scripts to deploy OpenShift 4 Installer-Provisioned installation (IPI) on Baremetal.
Since it may be difficult to count on having many bare metal servers to deploy OpenShift, this procedure helps with the IPI bare metal deployment on a virtualized environment.
Many of the steps and requirements were gotten from this lab: https://ocp-baremetal-ipi-lab.readthedocs.io/en/latest/

## Requirements
Basically, the requirements to be successful in deploying IPI baremetal on a hypervisor, are:
* Large hypervisor, it is required to deploy as many VMs as you need to deploy your OpenShift cluster.
* Libvirt and qemu-kvm installed on that hypervisor.
* Pull secret from cloud.openshift.com, it will be included afterwards in the installation script.
* Libvirt uses dnsmasq to service virtual networks, if you have your own dnsmasq deployed, take this into consideration: https://wiki.libvirt.org/page/Libvirtd_and_dnsmasq

## Procedure details
1. 00_create_ipibm_infra.sh - Create IPI bare metal infrastructure on the hypervisor. On this first stage the following assets will be created:
   - Virtual Machines, you have to specify how many workers you want to deploy (1-9).
   - Virtual Networks, based on your network type (ipv4/ipv6) a new virtual network will be deployed, network name is hardcoded, but you can edit the scripts and change the network name. Network ranges can be changed as well editing the corresponding parameters.
   - Install the installer server, this is the VM we'll use to deploy the whole cluster, avoiding messing the hypervisor. This VM is installed with a CentOS image downloaded by this same process.
   - Qemu disk images for master and workers are created and virtual machines configured with specific MAC addresses.
   - DNS records and DHCP reservations are set up in dnsmasq.
   - This is the only script that needs to be executed on the hypervisor, the other scripts are automatically copied to the installer VM, so the next steps will run on that installer VM.
   - At execution time you can provide custom domain name and cluster name, in order to set up these values use `-d` and `-c` options.

2. 01_pre_reqs_ipibm.sh - Install the required packages and finish the set up to deploy OpenShift IPI correctly **on the installer VM**. The following tasks are done under the hood:
   - Install some required packages, like libvirt libs and client, ironicclient, some other python modules, httpd, podman, etc.
   - Install and configure the sushy service - Virtual Redfish, to emulate bare metal machines by means of virtual machines. That way the installer will be able to power on, power off and manipulate the VMs as if it were bare metal servers.
   - Create the install-config.yaml file, based on the specified parameters, number of workers, whether ipv4 or ipv6 was selected, etc. **It is required to paste your own pull secret, replace it with <INSERT_YOUR_PULL_SECRETS_HERE> line**
   - Downloads oc and OpenShift installer client based on the OpenShift release.
   - Downloads RHCOS images, and places them in the httpd server to act as a cache, that way we reduce the installation time.
   - Creates a internal registry for disconnected installations, all required images for installation are placed in that registry, the install-config.yaml file is patched accordingly, so there is no need to go to the Red Hat external registry at the installation time.
   - A new Operator Catalog is created and pushed to the internal registry, to enable the OLM in disconnected environments. In order to build your own Operator Catalog set the variable `OLM_PKGS` accordingly.
   - New machineconfigs created for chrony.
   - At execution time you can provide custom domain name and cluster name, in order to set up these values use `-d` , `-c` and `-v` options.

3. 02_install_ipibm.sh - OpenShift 4 IPI Installation.
   - The installation is launched, there is no need of doing any extra step, just wait.
   - At execution time you can provide custom domain name and cluster name, in order to set up these values use `-d` and `-c` options.

## Procedure Execution
1. Run 00_create_ipibm_infra.sh on the hypervisor.
Here you can find some examples:

   * ipv6 deployments with 1 worker node.

   `/root/00_create_ipibm_infra.sh -n=ipv6 -w=1 -d=domtest.com -c=testlab`

   * ipv4 deployments with 4 worker node.

   `/root/00_create_ipibm_infra.sh -n=ipv4 -w=4 -d=domtest.com -c=testlab`

2. ssh to the installer VM and run 01_pre_reqs_ipibm.sh.

   * ipv6 deployments with 1 worker node, deploying OpenShift 4.7.

   `/root/01_pre_reqs_ipibm.sh -n=ipv6 -w=1 -d=domtest.com -c=testlab -v=4.7`

   * ipv4 deployments with 4 worker node, deploying OpenShift 4.8.

   `/root/01_pre_reqs_ipibm.sh -n=ipv4 -w=4 -d=domtest.com -c=testlab -v=4.8`

3. From the installer VM run 02_install_ipibm.sh

   * ipv6 deployments.

   `/root/02_install_ipibm.sh -n=ipv6 -d=domtest.com -c=testlab`

   * ipv4 deployments.

   `/root/02_install_ipibm.sh -n=ipv4 -d=domtest.com -c=testlab`
