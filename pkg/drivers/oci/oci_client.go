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
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/oracle/oci-go-sdk/example/helpers"
	"github.com/rancher/machine/libmachine/log"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/common"
	"github.com/oracle/oci-go-sdk/core"
	"github.com/oracle/oci-go-sdk/identity"
)

// Client defines / contains the OCI/Identity clients and operations.
type Client struct {
	configuration        common.ConfigurationProvider
	computeClient        core.ComputeClient
	virtualNetworkClient core.VirtualNetworkClient
	identityClient       identity.IdentityClient
	sleepDuration        time.Duration
	// TODO we could also include the retry settings here
}

func newClient(configuration common.ConfigurationProvider) (*Client, error) {

	computeClient, err := core.NewComputeClientWithConfigurationProvider(configuration)
	if err != nil {
		log.Debugf("create new Compute client failed with err %v", err)
		return nil, err
	}
	vNetClient, err := core.NewVirtualNetworkClientWithConfigurationProvider(configuration)
	if err != nil {
		log.Debugf("create new VirtualNetwork client failed with err %v", err)
		return nil, err
	}
	identityClient, err := identity.NewIdentityClientWithConfigurationProvider(configuration)
	if err != nil {
		log.Debugf("create new Identity client failed with err %v", err)
		return nil, err
	}
	c := &Client{
		configuration:        configuration,
		computeClient:        computeClient,
		virtualNetworkClient: vNetClient,
		identityClient:       identityClient,
		sleepDuration:        5,
	}
	return c, nil
}

// CreateInstance creates a new compute instance.
func (c *Client) CreateInstance(displayName, availabilityDomain, compartmentID, nodeShape, nodeImageName, nodeSubnetID, authorizedKeys string) (string, error) {

	req := identity.ListAvailabilityDomainsRequest{}
	req.CompartmentId = &compartmentID
	ads, err := c.identityClient.ListAvailabilityDomains(context.Background(), req)
	if err != nil {
		return "", err
	}

	// Just in case shortened or lower-case availability domain name was used
	log.Debugf("Resolving availability domain from %s", availabilityDomain)
	for _, ad := range ads.Items {
		if strings.Contains(*ad.Name, strings.ToUpper(availabilityDomain)) {
			log.Debugf("Availability domain %s", *ad.Name)
			availabilityDomain = *ad.Name
		}
	}

	imageID, err := c.getImageID(compartmentID, nodeImageName)
	if err != nil {
		return "", err
	}
	// Create the launch compute instance request
	request := core.LaunchInstanceRequest{
		LaunchInstanceDetails: core.LaunchInstanceDetails{
			AvailabilityDomain: &availabilityDomain,
			CompartmentId:      &compartmentID,
			Shape:              &nodeShape,
			CreateVnicDetails: &core.CreateVnicDetails{
				SubnetId: &nodeSubnetID,
			},
			DisplayName: &displayName,
			Metadata: map[string]string{
				"ssh_authorized_keys": authorizedKeys,
				"user_data":           base64.StdEncoding.EncodeToString(createCloudInitScript()),
			},
			SourceDetails: core.InstanceSourceViaImageDetails{
				ImageId: imageID,
			},
		},
	}

	createResp, err := c.computeClient.LaunchInstance(context.Background(), request)
	if err != nil {
		return "", err
	}

	// wait until lifecycle status is Running
	pollUntilRunning := func(r common.OCIOperationResponse) bool {
		if converted, ok := r.Response.(core.GetInstanceResponse); ok {
			return converted.LifecycleState != core.InstanceLifecycleStateRunning
		}
		return true
	}

	// create get instance request with a retry policy which takes a function
	// to determine shouldRetry or not
	pollingGetRequest := core.GetInstanceRequest{
		InstanceId:      createResp.Instance.Id,
		RequestMetadata: helpers.GetRequestMetadataWithCustomizedRetryPolicy(pollUntilRunning),
	}

	instance, pollError := c.computeClient.GetInstance(context.Background(), pollingGetRequest)
	if pollError != nil {
		return "", err
	}

	return *instance.Id, nil
}

// GetInstance gets a compute instance by id.
func (c *Client) GetInstance(id string) (core.Instance, error) {
	instanceResp, err := c.computeClient.GetInstance(context.Background(), core.GetInstanceRequest{InstanceId: &id})
	if err != nil {
		return core.Instance{}, err
	}
	return instanceResp.Instance, err
}

// TerminateInstance terminates a compute instance by id (does not wait).
func (c *Client) TerminateInstance(id string) error {
	_, err := c.computeClient.TerminateInstance(context.Background(), core.TerminateInstanceRequest{InstanceId: &id})
	return err
}

// StopInstance stops a compute instance by id and waits for it to reach the Stopped state.
func (c *Client) StopInstance(id string) error {

	actionRequest := core.InstanceActionRequest{}
	actionRequest.Action = core.InstanceActionActionStop
	actionRequest.InstanceId = &id

	stopResp, err := c.computeClient.InstanceAction(context.Background(), actionRequest)
	if err != nil {
		return err
	}

	// wait until lifecycle status is Stopped
	pollUntilStopped := func(r common.OCIOperationResponse) bool {
		if converted, ok := r.Response.(core.GetInstanceResponse); ok {
			return converted.LifecycleState != core.InstanceLifecycleStateStopped
		}
		return true
	}

	pollingGetRequest := core.GetInstanceRequest{
		InstanceId:      stopResp.Instance.Id,
		RequestMetadata: helpers.GetRequestMetadataWithCustomizedRetryPolicy(pollUntilStopped),
	}

	_, err = c.computeClient.GetInstance(context.Background(), pollingGetRequest)

	return err
}

// StartInstance starts a compute instance by id and waits for it to reach the Running state.
func (c *Client) StartInstance(id string) error {

	actionRequest := core.InstanceActionRequest{}
	actionRequest.Action = core.InstanceActionActionStart
	actionRequest.InstanceId = &id

	startResp, err := c.computeClient.InstanceAction(context.Background(), actionRequest)
	if err != nil {
		return err
	}

	// wait until lifecycle status is Running
	pollUntilRunning := func(r common.OCIOperationResponse) bool {
		if converted, ok := r.Response.(core.GetInstanceResponse); ok {
			return converted.LifecycleState != core.InstanceLifecycleStateRunning
		}
		return true
	}

	pollingGetRequest := core.GetInstanceRequest{
		InstanceId:      startResp.Instance.Id,
		RequestMetadata: helpers.GetRequestMetadataWithCustomizedRetryPolicy(pollUntilRunning),
	}

	_, err = c.computeClient.GetInstance(context.Background(), pollingGetRequest)

	return err
}

// RestartInstance stops and starts a compute instance by id and waits for it to be running again
func (c *Client) RestartInstance(id string) error {
	err := c.StopInstance(id)
	if err != nil {
		return err
	}
	return c.StartInstance(id)
}

// GetIPAddress returns the public IP of the compute instance, or private IP if there is no public address.
func (c *Client) GetIPAddress(id, compartmentID string) (string, error) {
	vnics, err := c.computeClient.ListVnicAttachments(context.Background(), core.ListVnicAttachmentsRequest{
		InstanceId:    &id,
		CompartmentId: &compartmentID,
	})
	if err != nil {
		return "", err
	}

	if len(vnics.Items) == 0 {
		return "", errors.New("instance does not have any configured VNICs")
	}

	vnic, err := c.virtualNetworkClient.GetVnic(context.Background(), core.GetVnicRequest{VnicId: vnics.Items[0].VnicId})
	if err != nil {
		return "", err
	}

	if vnic.PublicIp == nil {
		return *vnic.PrivateIp, nil
	}

	return *vnic.PublicIp, nil
}

// GetPrivateIP returns the private IP.
func (c *Client) GetPrivateIP(id, compartmentID string) (string, error) {
	vnics, err := c.computeClient.ListVnicAttachments(context.Background(), core.ListVnicAttachmentsRequest{
		InstanceId:    &id,
		CompartmentId: &compartmentID,
	})
	if err != nil {
		return "", err
	}

	if len(vnics.Items) == 0 {
		return "", errors.New("instance does not have any configured VNICs")
	}

	vnic, err := c.virtualNetworkClient.GetVnic(context.Background(), core.GetVnicRequest{VnicId: vnics.Items[0].VnicId})
	if err != nil {
		return "", err
	}

	return *vnic.PrivateIp, nil
}

// Create the cloud init script
func createCloudInitScript() []byte {
	cloudInit := []string{
		"#!/bin/sh",
		"#echo \"Disabling OS firewall...\"",
		"sudo /usr/sbin/ethtool --offload $(/usr/sbin/ip -o -4 route show to default | awk '{print $5}') tx off",
		"sudo iptables -F",
		"",
		"# Update to sellinux that fixes write permission error",
		"sudo yum install -y http://mirror.centos.org/centos/7/extras/x86_64/Packages/container-selinux-2.99-1.el7_6.noarch.rpm",
		"#sudo sed -i  s/SELINUX=enforcing/SELINUX=permissive/ /etc/selinux/config",
		"sudo setenforce 0",
		"sudo systemctl stop firewalld.service",
		"sudo systemctl disable firewalld.service",
		"",
		"# Elasticsearch requirement",
		"sudo sysctl -w vm.max_map_count=262144",
	}
	return []byte(strings.Join(cloudInit, "\n"))
}

// getImageID gets the most recent ImageId for the node image name
func (c *Client) getImageID(compartmentID, nodeImageName string) (*string, error) {

	if nodeImageName == "" || compartmentID == "" {
		return nil, errors.New("cannot retrieve image ID without a compartment and image name")
	}

	// Get list of images
	log.Debugf("Resolving image ID from %s", nodeImageName)
	request := core.ListImagesRequest{
		CompartmentId: &compartmentID,
		SortBy:        core.ListImagesSortByTimecreated,
		RequestMetadata: common.RequestMetadata{
			RetryPolicy: &common.RetryPolicy{
				MaximumNumberAttempts: 3,
				ShouldRetryOperation: func(r common.OCIOperationResponse) bool {
					return !(r.Error == nil && r.Response.HTTPResponse().StatusCode/100 == 2)
				},

				NextDuration: func(response common.OCIOperationResponse) time.Duration {
					return 3 * time.Second
				},
			},
		},
	}
	r, err := c.computeClient.ListImages(context.Background(), request)
	if err != nil {
		return nil, err
	}

	// Loop through the items to find an image to use.  The list is sorted by time created in descending order
	for _, image := range r.Items {
		if strings.HasPrefix(*image.DisplayName, nodeImageName) {
			if !strings.Contains(*image.DisplayName, "GPU") {
				log.Debugf("Using node image %s", *image.DisplayName)
				return image.Id, nil
			}
		}
	}

	return nil, fmt.Errorf("could not retrieve image id for an image named %s", nodeImageName)
}
