# Development

## Prerequisites

* Build and install the [Rancher Docker Machine](https://github.com/rancher/machine) binary (fork of docker/machine).

## Build the OCI Plugin

```bash
go get github.com/rancher-plugins/rancher-machine-driver-oci
cd $GOPATH/src/github.com/rancher-plugins/rancher-machine-driver-oci
make install
```

## Install rancher-machine CLI binary locally

```bash
go get github.com/rancher/machine
cd $GOPATH/src/github.com/rancher/machine
make binary-build
sudo cp dist/docker-machine-driver-oci-darwin /usr/local/bin/docker-machine-driver-oci
```

## Provision a node using OCI plugin for rancher-machine CLI

```bash
$ rancher-machine create -d oci --engine-install-url https://releases.rancher.com/install-docker/18.09.sh --oci-region us-phoenix-1 --oci-subnet-id ocid1.subnet.oc1.phx.aaaaaaaaaaaaaaaaaaaaaaaa --oci-tenancy-id ocid1.tenancy.oc1..aaaaaaaaaaaaaaaaaaaaaaaa --oci-vcn-id ocid1.vcn.oc1.phx.aaaaaaaaaaaaaaaaaaaaaaaa --oci-fingerprint xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx --oci-node-availability-domain jGnV:PHX-AD-2 --oci-node-image Oracle-Linux-7.7 --oci-user-id ocid1.user.oc1..aaaaaaaaaaaaaaaaaaaaaaaa --oci-vcn-compartment-id ocid1.compartment.oc1..aaaaaaaaaaaaaaaaaaaaaaaa --oci-node-compartment-id ocid1.compartment.oc1..aaaaaaaaaaaaaaaaaaaaaaaa --oci-private-key-path /path/to/api.key.priv.pem  --oci-node-shape VM.Standard2.1  node

Running pre-create checks...
(node) Verifying node image availability... 
Creating machine...
(node) Using node image Oracle-Linux-7.7-2019.12.18-0
Waiting for machine to be running, this may take a few minutes...
Detecting operating system of created instance...
Waiting for SSH to be available...
Detecting the provisioner...
Provisioning with ol...
Copying certs to the local machine directory...
Copying certs to the remote machine...
Setting Docker configuration on the remote daemon...
Checking connection to Docker...
Docker is up and running!
To see how to connect your Docker Client to the Docker Engine running on this virtual machine, run: docker-machine env node
```
