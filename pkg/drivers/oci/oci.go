// Copyright 2020 Oracle and/or its affiliates. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oci

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/docker/machine/libmachine/drivers"
	"github.com/docker/machine/libmachine/log"
	"github.com/docker/machine/libmachine/mcnflag"
	"github.com/docker/machine/libmachine/state"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

const (
	defaultSSHPort    = 22
	defaultSSHUser    = "opc"
	defaultImage      = "Oracle-Linux-7.9"
	defaultDockerPort = 2376
	sshBitLen         = 4096
)

// Driver is the implementation of BaseDriver interface
type Driver struct {
	*drivers.BaseDriver
	AvailabilityDomain   string
	DockerPort           int
	Fingerprint          string
	Image                string
	NodeCompartmentID    string
	OCPUs                int
	MemoryInGBs          int
	PrivateIPAddress     string
	PrivateKeyContents   string
	PrivateKeyPassphrase string
	PrivateKeyPath       string
	Region               string
	Shape                string
	SubnetID             string
	TenancyID            string
	UserID               string
	UsePrivateIP         bool
	VCNCompartmentID     string
	VCNID                string
	// Runtime values
	InstanceID string
}

// NewDriver creates a new driver
func NewDriver(hostName, storePath string) *Driver {
	return &Driver{
		BaseDriver: &drivers.BaseDriver{
			SSHUser:     defaultSSHUser,
			MachineName: hostName,
			StorePath:   storePath,
		},
	}
}

// Create a host using the driver's config
func (d *Driver) Create() error {
	log.Debug("oci.Create()")

	oci, err := d.initOCIClient()
	if err != nil {
		return err
	}

	// Create SSH key-pair
	privateKey, err := generatePrivateKey(sshBitLen)
	if err != nil {
		return err
	}
	privateKeyBytes := encodePEM(privateKey)

	publicKeyBytes, err := generatePublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}

	if _, err := os.Stat(d.GetSSHKeyPath()); os.IsNotExist(err) {
		err = os.MkdirAll(filepath.Dir(d.GetSSHKeyPath()), 0750)
		if err != nil {
			return err
		}
	}

	err = ioutil.WriteFile(d.GetSSHKeyPath(), privateKeyBytes, 0600)
	if err != nil {
		return err
	}

	d.InstanceID, err = oci.CreateInstance(d.MachineName, d.AvailabilityDomain, d.NodeCompartmentID, d.Shape, d.Image, d.SubnetID, string(publicKeyBytes), d.OCPUs, d.MemoryInGBs)
	if err != nil {
		return err
	}

	ip, _ := d.GetIP()
	log.Infof("created instance ID %s, IP address %s", d.InstanceID, ip)

	return nil
}

// DriverName returns the name of the driver
func (d *Driver) DriverName() string {
	log.Debug("oci.DriverName()")
	return "oci"
}

// GetCreateFlags returns the mcnflag.Flag slice representing the flags
// that can be set, their descriptions and defaults.
func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	log.Debug("oci.GetCreateFlags()")
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			Name:   "oci-node-availability-domain",
			Usage:  "Specify availability domain the node(s) should use",
			EnvVar: "OCI_NODE_AVAILABILITY_DOMAIN",
		},
		mcnflag.StringFlag{
			Name:   "oci-fingerprint",
			Usage:  "Specify fingerprint corresponding to the specified user's private API Key",
			EnvVar: "OCI_FINGERPRINT",
		},
		mcnflag.StringFlag{
			Name:   "oci-node-image",
			Usage:  "Specify Oracle-Linux image the node(s) should use",
			Value:  defaultImage,
			EnvVar: "OCI_NODE_IMAGE",
		},
		mcnflag.StringFlag{
			Name:   "oci-node-compartment-id",
			Usage:  "Specify OCID of the compartment in which to create node(s)",
			EnvVar: "OCI_NODE_COMPARTMENT_ID",
		},
		mcnflag.BoolFlag{
			Name:   "oci-node-use-private-ip",
			Usage:  "Use private IP address of the node to connect and for communication",
			EnvVar: "OCI_NODE_USE_PRIVATE_IP",
		},
		mcnflag.StringFlag{
			Name:   "oci-private-key-contents",
			Usage:  "Specify private API key contents for the specified OCI user, in PEM format",
			EnvVar: "OCI_PRIVATE_KEY_CONTENTS",
		},
		mcnflag.StringFlag{
			Name:   "oci-private-key-path",
			Usage:  "Specify private API key path for the specified OCI user, in PEM format",
			EnvVar: "OCI_PRIVATE_KEY_PATH",
		},
		mcnflag.StringFlag{
			Name:   "oci-private-key-passphrase",
			Usage:  "Specify passphrase (if any) that protects private key file the specified OCI user",
			EnvVar: "OCI_PRIVATE_KEY_PASSPHRASE",
			Value:  "",
		},
		mcnflag.StringFlag{
			Name:   "oci-region",
			Usage:  "Specify region in which to create node(s)",
			EnvVar: "OCI_REGION",
		},
		mcnflag.StringFlag{
			Name:   "oci-node-shape",
			Usage:  "Specify instance shape of the node(s)",
			EnvVar: "OCI_NODE_SHAPE",
		},
		mcnflag.IntFlag{
			Name:   "oci-node-ocpus",
			Usage:  "Specify number of OCPUs for a flexible node shape",
			EnvVar: "OCI_NODE_OCPUS",
		},
		mcnflag.IntFlag{
			Name:   "oci-node-memory-in-gb",
			Usage:  "Specify the amount of memory in GB for a flexible node shape",
			EnvVar: "OCI_NODE_MEMORY_GB",
		},
		mcnflag.StringFlag{
			Name:   "oci-subnet-id",
			Usage:  "Specify pre-existing subnet id in which you want to create the node(s)",
			EnvVar: "OCI_SUBNET_ID",
		},
		mcnflag.StringFlag{
			Name:   "oci-tenancy-id",
			Usage:  "Specify OCID of the tenancy in which to create node(s)",
			EnvVar: "OCI_TENANCY_ID",
			Value:  "",
		},
		mcnflag.StringFlag{
			Name:   "oci-user-id",
			Usage:  "Specify OCID of a user who has access to the specified tenancy/compartment",
			EnvVar: "OCI_USER_ID",
			Value:  "",
		},
		mcnflag.StringFlag{
			Name:   "oci-vcn-compartment-id",
			Usage:  "Specify OCID of the compartment in which the VCN exists",
			EnvVar: "OCI_VCN_COMPARTMENT_ID",
		},
		mcnflag.StringFlag{
			Name:   "oci-vcn-id",
			Usage:  "Specify pre-existing VCN id in which you want to create the node(s)",
			EnvVar: "OCI_VCN_ID",
		},
	}
}

// GetIP returns an IP or hostname that this host is available at
// e.g. 1.2.3.4 or docker-host-d60b70a14d3a.cloudapp.net
func (d *Driver) GetIP() (string, error) {
	log.Debug("oci.GetIP()")

	if d.IPAddress == "" || d.PrivateIPAddress == "" {
		oci, err := d.initOCIClient()
		if err != nil {
			return "", err
		}
		ip, err := oci.GetIPAddress(d.InstanceID, d.NodeCompartmentID)
		if err != nil {
			return "", err
		}
		privateIP, err := oci.GetPrivateIP(d.InstanceID, d.NodeCompartmentID)
		if err != nil {
			return "", err
		}
		d.IPAddress = ip
		d.PrivateIPAddress = privateIP
	}
	if d.UsePrivateIP {
		return d.PrivateIPAddress, nil
	}

	return d.IPAddress, nil
}

// GetMachineName returns the name of the machine
func (d *Driver) GetMachineName() string {
	log.Debug("oci.GetMachineName()")
	return d.MachineName
}

// GetSSHHostname returns hostname for use with ssh
func (d *Driver) GetSSHHostname() (string, error) {
	log.Debug("oci.GetSSHHostname()")
	return d.GetIP()
}

// GetSSHPort returns port for use with ssh
func (d *Driver) GetSSHPort() (int, error) {
	log.Debug("oci.GetSSHPort()")

	return defaultSSHPort, nil
}

// GetSSHUsername returns username for use with ssh
func (d *Driver) GetSSHUsername() string {
	log.Debug("oci.GetSSHUsername()")

	return defaultSSHUser
}

// GetURL returns a Docker compatible host URL for connecting to this host
// e.g. tcp://1.2.3.4:2376
func (d *Driver) GetURL() (string, error) {
	log.Debug("oci.GetURL()")
	ip, err := d.GetIP()
	if err != nil {
		return "", err
	}
	if ip == "" {
		return "", nil
	}

	return fmt.Sprintf("tcp://%s:%d", ip, defaultDockerPort), nil
}

// GetState returns the state that the host is in (running, stopped, etc)
func (d *Driver) GetState() (state.State, error) {
	log.Debug("oci.GetState()")

	oci, err := d.initOCIClient()
	if err != nil {
		return state.None, err
	}

	instance, err := oci.GetInstance(d.InstanceID)
	if err != nil {
		return state.None, err
	}

	switch instance.LifecycleState {
	case core.InstanceLifecycleStateRunning:
		return state.Running, nil
	case core.InstanceLifecycleStateStopped, core.InstanceLifecycleStateTerminated:
		return state.Stopped, nil
	case core.InstanceLifecycleStateStopping, core.InstanceLifecycleStateTerminating:
		return state.Stopping, nil
	case core.InstanceLifecycleStateStarting, core.InstanceLifecycleStateProvisioning, core.InstanceLifecycleStateCreatingImage:
		return state.Starting, nil
	}

	// deleting, migrating, rebuilding, cloning, restoring ...
	return state.None, nil

}

// Kill stops a host forcefully
func (d *Driver) Kill() error {
	log.Debug("oci.Kill()")
	return d.Remove()
}

// PreCreateCheck allows for pre-create operations to make sure a driver is ready for creation
func (d *Driver) PreCreateCheck() error {
	log.Debug("oci.PreCreateCheck()")

	// Check the number of availability domain, which will also validate the credentials.
	log.Infof("Verifying number of availability domains... ")

	oci, err := d.initOCIClient()
	if err != nil {
		return err
	}

	ads, err := oci.getNumAvailabilityDomains(d.NodeCompartmentID)
	if err != nil {
		return err
	}
	if ads <= 0 {
		return fmt.Errorf("could not retrieve availability domain info from OCI")
	}

	// TODO, verify VCN and subnet

	return nil
}

// Remove a host
func (d *Driver) Remove() error {
	log.Debug("oci.Remove()")
	log.Info("NOTICE: Please check Oracle Cloud Console or CLI to ensure there are no leftover resources.")

	oci, err := d.initOCIClient()
	if err != nil {
		return err
	}

	log.Infof("terminating instance ID %s", d.InstanceID)
	return oci.TerminateInstance(d.InstanceID)
}

// Restart a host. This may just call Stop(); Start() if the provider does not
// have any special restart behaviour.
func (d *Driver) Restart() error {
	log.Debug("oci.Restart()")
	oci, err := d.initOCIClient()
	if err != nil {
		return err
	}

	return oci.RestartInstance(d.InstanceID)
}

// SetConfigFromFlags configures the driver with the object that was returned
// by RegisterCreateFlags
func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	log.Debug("oci.SetConfigFromFlags(...)")
	d.VCNID = flags.String("oci-vcn-id")
	if d.VCNID == "" {
		return errors.New("no OCI VCNID specified (--oci-vcn-id)")
	}
	d.SubnetID = flags.String("oci-subnet-id")
	if d.SubnetID == "" {
		return errors.New("no OCI subnetId specified (--oci-subnet-id)")
	}
	d.TenancyID = flags.String("oci-tenancy-id")
	if d.TenancyID == "" {
		return errors.New("no OCI tenancy specified (--oci-tenancy-id)")
	}
	d.NodeCompartmentID = flags.String("oci-node-compartment-id")
	if d.NodeCompartmentID == "" {
		return errors.New("no OCI compartment specified for node (--oci-node-compartment-id)")
	}
	d.VCNCompartmentID = flags.String("oci-vcn-compartment-id")
	if d.VCNCompartmentID == "" {
		return errors.New("no OCI compartment specified for VCN (--oci-vcn-compartment-id)")
	}
	d.UserID = flags.String("oci-user-id")
	if d.UserID == "" {
		return errors.New("no OCI user id specified (--oci-user-id)")
	}
	d.Region = flags.String("oci-region")
	if d.Region == "" {
		return errors.New("no OCI oci-region specified (--oci-region)")
	}
	d.AvailabilityDomain = flags.String("oci-node-availability-domain")
	if d.AvailabilityDomain == "" {
		return errors.New("no OCI node availability domain specified (--oci-node-availability-domain)")
	}
	d.Shape = flags.String("oci-node-shape")
	if d.Shape == "" {
		return errors.New("no OCI node shape specified (--oci-node-shape)")
	}
	if strings.Contains(strings.ToLower(d.Shape), "flex") {
		d.OCPUs = flags.Int("oci-node-ocpus")
		if d.OCPUs <= 0 {
			return errors.New("both the number of OCPUs and memory (in GBs) must be specified for a flexible node shape with --oci-node-ocpus and --oci-node-memory-in-gb")
		} else if d.OCPUs > 64 {
			return errors.New("number of OCPUs must not be larger than 64")
		}

		d.MemoryInGBs = flags.Int("oci-node-memory-in-gb")
		if d.MemoryInGBs <= 0 {
			return errors.New("both the number of OCPUs and memory (in GBs) must be specified for a flexible node shape with --oci-node-ocpus and --oci-node-memory-in-gb")
		}
	}

	d.Fingerprint = flags.String("oci-fingerprint")
	if d.Fingerprint == "" {
		return errors.New("no OCI oci-fingerprint specified (--oci-fingerprint)")
	}
	d.PrivateKeyPath = flags.String("oci-private-key-path")
	d.PrivateKeyContents = flags.String("oci-private-key-contents")
	if d.PrivateKeyPath == "" && d.PrivateKeyContents == "" {
		return errors.New("no private key path or content specified (--oci-private-key-path || --oci-private-key-contents)")
	}
	if d.PrivateKeyContents == "" && d.PrivateKeyPath != "" {
		privateKeyBytes, err := ioutil.ReadFile(d.PrivateKeyPath)
		if err == nil {
			d.PrivateKeyContents = string(privateKeyBytes)
		}
	}

	d.UsePrivateIP = flags.Bool("oci-node-use-private-ip")
	d.Image = flags.String("oci-node-image")
	if !strings.Contains(d.Image, "Oracle-Linux") {
		log.Warnf("node image %s is not supported. Driver currently supports Oracle Linux images", d.Image)
		d.Image = defaultImage
	}
	d.SSHUser = defaultSSHUser
	d.SSHPort = defaultSSHPort

	return nil
}

// Start a host
func (d *Driver) Start() error {
	log.Debug("oci.Start()")
	oci, err := d.initOCIClient()
	if err != nil {
		return err
	}

	return oci.StartInstance(d.InstanceID)
}

// Stop a host gracefully
func (d *Driver) Stop() error {
	log.Debug("oci.Stop()")
	oci, err := d.initOCIClient()
	if err != nil {
		return err
	}

	return oci.StopInstance(d.InstanceID)
}

// initOCIClient is a helper function that constructs a new
// oci.Client based on config values.
func (d *Driver) initOCIClient() (Client, error) {
	configurationProvider := common.NewRawConfigurationProvider(
		d.TenancyID,
		d.UserID,
		d.Region,
		d.Fingerprint,
		d.PrivateKeyContents,
		&d.PrivateKeyPassphrase)

	ociClient, err := newClient(configurationProvider)
	if err != nil {
		return Client{}, err
	}

	return *ociClient, nil
}

func generatePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	// Validate RSA Private Key
	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func generatePublicKey(publicKey *rsa.PublicKey) ([]byte, error) {
	publicRsaKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	return ssh.MarshalAuthorizedKey(publicRsaKey), nil
}

func encodePEM(privateKey *rsa.PrivateKey) []byte {

	block := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   x509.MarshalPKCS1PrivateKey(privateKey),
	}

	return pem.EncodeToMemory(&block)
}
