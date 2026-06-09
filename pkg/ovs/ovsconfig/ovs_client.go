// Copyright 2019 Antrea Authors
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

package ovsconfig

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/gofrs/uuid/v5"

	"github.com/cenkalti/backoff/v4"

	"github.com/ovn-kubernetes/libovsdb/client"
	"github.com/ovn-kubernetes/libovsdb/model"
	"github.com/ovn-kubernetes/libovsdb/ovsdb"
	"k8s.io/klog/v2"
)

const defaultOVSDBFile = "db.sock"

type OVSBridge struct {
	ovsdb                    client.Client
	name                     string
	datapathType             OVSDatapathType
	mcastSnoopingEnable      bool
	uuid                     string
	isHardwareOffloadEnabled bool
	requiredPortExternalIDs  []string
}

type OVSPortData struct {
	UUID   string
	Name   string
	VLANID uint16
	// Interface type.
	IFType      string
	IFName      string
	OFPort      int32
	ExternalIDs map[string]string
	Options     map[string]string
	MAC         net.HardwareAddr
}

const (
	// Openflow protocol version 1.0.
	openflowProtoVersion10 = "OpenFlow10"
	// Openflow protocol version 1.5.
	openflowProtoVersion15 = "OpenFlow15"
	// Maximum allowed value of ofPortRequest.
	ofPortRequestMax = 65279
	hardwareOffload  = "hw-offload"
)

// NewOVSDBConnectionUDS connects to the OVSDB server on the UNIX domain socket
// or named pipe (on Windows) specified by address, never using any SSL connection option.
// If address is set to "", the default UNIX domain socket path
// "/run/openvswitch/db.sock" will be used.
// Returns the OVSDB struct on success.
func NewOVSDBConnectionUDS(address string) (client.Client, Error) {
	klog.Infof("Connecting to OVSDB at address %s", address)

	const maxBackoffTime = 8 * time.Second
	retryBackoff := 1 * time.Second
	var db client.Client

	for {
		dbModel, err := model.NewClientDBModel("Open_vSwitch", map[string]model.Model{
			"Open_vSwitch": &Open_vSwitch{},
			"Bridge":       &Bridge{},
			"Port":         &Port{},
			"Interface":    &Interface{},
		})
		if err != nil {
			return nil, newInvalidArgumentsError(err.Error())
		}

		endpoint := address
		if endpoint != "" {
			endpoint = "unix:" + endpoint
		}

		db, err = client.NewOVSDBClient(dbModel, client.WithEndpoint(endpoint), client.WithReconnect(2*time.Second, backoff.NewConstantBackOff(1*time.Second)))
		if err != nil {
			return nil, newInvalidArgumentsError(err.Error())
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err = db.Connect(ctx)
		cancel()
		if err == nil {
			break
		}

		klog.Infof("Not connected yet (%v), will try again in %v", err, retryBackoff)
		time.Sleep(retryBackoff)
		retryBackoff *= 2
		if retryBackoff > maxBackoffTime {
			retryBackoff = maxBackoffTime
		}
	}

	_, err := db.MonitorAll(context.Background())
	if err != nil {
		return nil, NewTransactionError(err, true)
	}

	return db, nil
}

type OVSBridgeOption func(*OVSBridge)

func WithRequiredPortExternalIDs(keys ...string) OVSBridgeOption {
	return func(br *OVSBridge) {
		br.requiredPortExternalIDs = append(br.requiredPortExternalIDs, keys...)
	}
}

func WithMcastSnooping() OVSBridgeOption {
	return func(br *OVSBridge) {
		br.mcastSnoopingEnable = true
	}
}

// NewOVSBridge creates and returns a new OVSBridge struct.
func NewOVSBridge(bridgeName string, ovsDatapathType OVSDatapathType, ovsdb client.Client, options ...OVSBridgeOption) OVSBridgeClient {
	br := &OVSBridge{
		ovsdb:        ovsdb,
		name:         bridgeName,
		datapathType: ovsDatapathType,
	}
	for _, option := range options {
		option(br)
	}
	return br
}

func namedUUID() string {
	return "row" + strings.ReplaceAll(uuid.Must(uuid.NewV4()).String(), "-", "")
}

// Create looks up or creates the bridge. If the bridge with name bridgeName
// does not exist, it will be created. Openflow protocol version 1.0 and 1.5
// will be enabled for the bridge.
func (br *OVSBridge) Create() Error {
	var err Error
	var exists bool
	if exists, err = br.lookupByName(); err != nil {
		return err
	} else if exists {
		klog.Info("Bridge exists: ", br.uuid)
		// Update OpenFlow protocol versions and datapath type on existent bridge.
		if err := br.updateBridgeConfiguration(); err != nil {
			return err
		}
	} else if err = br.create(); err != nil {
		return err
	} else {
		klog.Info("Created bridge: ", br.uuid)
	}
	br.isHardwareOffloadEnabled, err = br.getHardwareOffload()
	if err != nil {
		klog.ErrorS(err, "Failed to get hardware offload")
	}
	return nil
}

func (br *OVSBridge) lookupByName() (bool, Error) {
	ctx := context.Background()
	bridge := &Bridge{Name: br.name}
	err := br.ovsdb.Get(ctx, bridge)
	if err == client.ErrNotFound {
		return false, nil
	}
	if err != nil {
		klog.Error("Get failed: ", err)
		return false, NewTransactionError(err, true)
	}

	br.uuid = bridge.UUID
	return true, nil
}

func (br *OVSBridge) updateBridgeConfiguration() Error {
	ctx := context.Background()
	bridge := &Bridge{
		UUID:                br.uuid,
		Name:                br.name,
		Protocols:           []string{openflowProtoVersion10, openflowProtoVersion15},
		DatapathType:        string(br.datapathType),
		McastSnoopingEnable: br.mcastSnoopingEnable,
	}
	ops, err := br.ovsdb.Where(&Bridge{UUID: bridge.UUID}).Update(bridge)
	if err != nil {
		return NewTransactionError(err, false)
	}
	_, err = br.ovsdb.Transact(ctx, ops...)
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return NewTransactionError(err, true)
	}
	return nil
}

func (br *OVSBridge) create() Error {
	ctx := context.Background()
	bridge := &Bridge{
		UUID: namedUUID(),
		Name: br.name,
		// Use Openflow protocol version 1.0 and 1.5.
		Protocols:           []string{openflowProtoVersion10, openflowProtoVersion15},
		DatapathType:        string(br.datapathType),
		McastSnoopingEnable: br.mcastSnoopingEnable,
	}
	ops, err := br.ovsdb.Create(bridge)
	if err != nil {
		return NewTransactionError(fmt.Errorf("Create bridge failed: %v", err), false)
	}

	var ovsList []Open_vSwitch
	err = br.ovsdb.List(ctx, &ovsList)
	if err != nil {
		return NewTransactionError(fmt.Errorf("List Open_vSwitch failed: %v", err), false)
	}
	if len(ovsList) == 0 {
		return NewTransactionError(fmt.Errorf("Open_vSwitch record not found"), false)
	}
	ovs := &ovsList[0]
	mutation := model.Mutation{
		Field:   &ovs.Bridges,
		Mutator: ovsdb.MutateOperationInsert,
		Value:   []string{ops[0].UUIDName},
	}
	ops2, err := br.ovsdb.Where(&Open_vSwitch{UUID: ovs.UUID}).Mutate(ovs, mutation)
	if err != nil {
		return NewTransactionError(fmt.Errorf("Mutate Open_vSwitch failed: %v", err), false)
	}
	ops = append(ops, ops2...)

	res, err := br.ovsdb.Transact(ctx, ops...)
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return NewTransactionError(err, true)
	}

	br.uuid = res[0].UUID.GoUUID
	return nil
}

func (br *OVSBridge) Delete() Error {
	ctx := context.Background()
	bridge := &Bridge{UUID: br.uuid, Name: br.name}
	ops, err := br.ovsdb.Where(bridge).Delete()
	if err != nil {
		return NewTransactionError(fmt.Errorf("Delete bridge failed: %v", err), false)
	}

	var ovsList []Open_vSwitch
	err = br.ovsdb.List(ctx, &ovsList)
	if err == nil && len(ovsList) > 0 {
		ovs := &ovsList[0]
		mutation := model.Mutation{
			Field:   &ovs.Bridges,
			Mutator: ovsdb.MutateOperationDelete,
			Value:   []string{br.uuid},
		}
		ops2, err := br.ovsdb.Where(&Open_vSwitch{UUID: ovs.UUID}).Mutate(ovs, mutation)
		if err == nil {
			ops = append(ops, ops2...)
		}
	}

	_, err = br.ovsdb.Transact(ctx, ops...)
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return NewTransactionError(err, true)
	}
	return nil
}

// GetExternalIDs returns the external IDs of the bridge.
func (br *OVSBridge) getModel(ctx context.Context, m model.Model) error {
	var err error
	for i := 0; i < 10; i++ {
		err = br.ovsdb.Get(ctx, m)
		if err != client.ErrNotFound {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return err
}

func (br *OVSBridge) GetExternalIDs() (map[string]string, Error) {
	ctx := context.Background()
	bridge := &Bridge{Name: br.name}
	err := br.getModel(ctx, bridge)
	if err != nil {
		klog.Error("Get failed: ", err)
		return nil, NewTransactionError(err, true)
	}

	return bridge.ExternalIDs, nil
}

// SetExternalIDs sets the provided external IDs to the bridge.
func (br *OVSBridge) SetExternalIDs(externalIDs map[string]interface{}) Error {
	ctx := context.Background()
	bridge := &Bridge{Name: br.name}
	err := br.getModel(ctx, bridge)
	if err != nil {
		klog.Error("Get failed: ", err)
		return NewTransactionError(err, true)
	}

	bridge.ExternalIDs = make(map[string]string)
	for k, v := range externalIDs {
		if val, ok := v.(string); ok {
			bridge.ExternalIDs[k] = val
		}
	}

	ops, err := br.ovsdb.Where(&Bridge{UUID: bridge.UUID}).Update(bridge)
	if err != nil {
		return NewTransactionError(err, false)
	}
	_, err = br.ovsdb.Transact(ctx, ops...)
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return NewTransactionError(err, true)
	}
	return nil
}

// SetDatapathID sets the provided datapath ID to the bridge.
// If datapath ID is not configured, reconfigure bridge(add/delete port or set different Mac address for local port)
// will change its datapath ID. And the change of datapath ID and interrupt OpenFlow connection.
// See question "My bridge disconnects from my controller on add-port/del-port" in：
// http://openvswitch.org/support/dist-docs-2.5/FAQ.md.html
func (br *OVSBridge) SetDatapathID(datapathID string) Error {
	ctx := context.Background()
	bridge := &Bridge{Name: br.name}
	err := br.getModel(ctx, bridge)
	if err != nil {
		klog.Error("Get failed", err)
		return NewTransactionError(err, true)
	}

	if bridge.OtherConfig == nil {
		bridge.OtherConfig = make(map[string]string)
	}
	bridge.OtherConfig[OVSOtherConfigDatapathIDKey] = datapathID

	ops, err := br.ovsdb.Where(&Bridge{UUID: bridge.UUID}).Update(bridge)
	if err != nil {
		return NewTransactionError(err, false)
	}

	_, err = br.ovsdb.Transact(ctx, ops...)
	if err != nil {
		klog.Error("Transaction failed", err)
		return NewTransactionError(err, true)
	}
	return nil
}

func (br *OVSBridge) GetDatapathID() (string, Error) {
	ctx := context.Background()
	bridge := &Bridge{Name: br.name}
	err := br.getModel(ctx, bridge)
	if err != nil {
		klog.Error("Get failed: ", err)
		return "", NewTransactionError(err, true)
	}
	if bridge.DatapathID == nil {
		return "", nil
	}
	return *bridge.DatapathID, nil
}

func (br *OVSBridge) WaitForDatapathID(timeout time.Duration) (string, Error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return "", NewTransactionError(fmt.Errorf("timeout waiting for datapath_id"), false)
		default:
		}

		bridge := &Bridge{Name: br.name}
		err := br.getModel(ctx, bridge)
		if err != nil {
			klog.Error("Get failed: ", err)
			return "", NewTransactionError(err, true)
		}

		if bridge.DatapathID != nil && *bridge.DatapathID != "" {
			return *bridge.DatapathID, nil
		}

		time.Sleep(500 * time.Millisecond)
	}
}

// GetPortUUIDList returns UUIDs of all ports on the bridge.
func (br *OVSBridge) GetPortUUIDList() ([]string, Error) {
	ctx := context.Background()
	bridge := &Bridge{Name: br.name}
	err := br.getModel(ctx, bridge)
	if err != nil {
		klog.Error("Get failed: ", err)
		return nil, NewTransactionError(err, true)
	}

	return bridge.Ports, nil
}

// DeletePorts deletes ports in portUUIDList on the bridge
func (br *OVSBridge) DeletePorts(portUUIDList []string) Error {
	if len(portUUIDList) == 0 {
		return nil
	}
	ctx := context.Background()
	bridge := &Bridge{UUID: br.uuid}
	mutation := model.Mutation{
		Field:   &bridge.Ports,
		Mutator: ovsdb.MutateOperationDelete,
		Value:   portUUIDList,
	}
	ops, err := br.ovsdb.Where(bridge).Mutate(bridge, mutation)
	if err != nil {
		return NewTransactionError(fmt.Errorf("Mutate bridge failed: %v", err), false)
	}

	_, err = br.ovsdb.Transact(ctx, ops...)
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return NewTransactionError(err, true)
	}
	return nil
}

// DeletePort deletes the port with the provided portUUID.
// If the port does not exist no change will be done.
func (br *OVSBridge) DeletePort(portUUID string) Error {
	return br.DeletePorts([]string{portUUID})
}

// CreateInternalPort creates an internal port with the specified name on the
// bridge.
// If externalIDs is not empty, the map key/value pairs will be set to the
// port's external_ids.
// If ofPortRequest is not zero, it will be passed to the OVS port creation.
func (br *OVSBridge) CreateInternalPort(name string, ofPortRequest int32, mac string, externalIDs map[string]interface{}) (string, Error) {
	if ofPortRequest < 0 || ofPortRequest > ofPortRequestMax {
		return "", newInvalidArgumentsError(fmt.Sprint("invalid ofPortRequest value: ", ofPortRequest))
	}
	return br.createPort(name, name, "internal", ofPortRequest, 0, mac, externalIDs, nil)
}

// CreateTunnelPort creates a tunnel port with the specified name and type on
// the bridge.
// If ofPortRequest is not zero, it will be passed to the OVS port creation.
func (br *OVSBridge) CreateTunnelPort(name string, tunnelType TunnelType, ofPortRequest int32) (string, Error) {
	return br.createTunnelPort(name, tunnelType, ofPortRequest, false, "", "", "", "", nil, nil)
}

// CreateTunnelPortExt creates a tunnel port with the specified name and type
// on the bridge.
// If ofPortRequest is not zero, it will be passed to the OVS port creation.
// If remoteIP is not empty, it will be set to the tunnel port interface
// options; otherwise flow based tunneling will be configured.
// psk is for the pre-shared key of IPsec ESP tunnel. If it is not empty, it
// will be set to the tunnel port interface options. Flow based IPsec tunnel is
// not supported, so remoteIP must be provided too when psk is not empty.
// If externalIDs is not nil, the IDs in it will be added to the port's
// external_ids.
func (br *OVSBridge) CreateTunnelPortExt(
	name string,
	tunnelType TunnelType,
	ofPortRequest int32,
	csum bool,
	localIP string,
	remoteIP string,
	remoteName string,
	psk string,
	extraOptions map[string]interface{},
	externalIDs map[string]interface{}) (string, Error) {
	if psk != "" && remoteIP == "" {
		return "", newInvalidArgumentsError("IPsec tunnel can not be flow based. remoteIP must be set")
	}
	if psk != "" && remoteName != "" {
		return "", newInvalidArgumentsError("Cannot set psk and remoteName together")
	}
	return br.createTunnelPort(name, tunnelType, ofPortRequest, csum, localIP, remoteIP, remoteName, psk, extraOptions, externalIDs)
}

func (br *OVSBridge) createTunnelPort(
	name string,
	tunnelType TunnelType,
	ofPortRequest int32,
	csum bool,
	localIP string,
	remoteIP string,
	remoteName string,
	psk string,
	extraOptions map[string]interface{},
	externalIDs map[string]interface{}) (string, Error) {

	if tunnelType != VXLANTunnel &&
		tunnelType != GeneveTunnel &&
		tunnelType != GRETunnel &&
		tunnelType != STTTunnel &&
		tunnelType != ERSPANTunnel {
		return "", newInvalidArgumentsError("unsupported tunnel type: " + string(tunnelType))
	}
	if ofPortRequest < 0 || ofPortRequest > ofPortRequestMax {
		return "", newInvalidArgumentsError(fmt.Sprint("invalid ofPortRequest value: ", ofPortRequest))
	}

	options := make(map[string]interface{})
	for k, v := range extraOptions {
		options[k] = v
	}

	if remoteIP != "" {
		options["remote_ip"] = remoteIP
	} else {
		// Flow based tunnel.
		options["key"] = "flow"
		options["remote_ip"] = "flow"
	}
	if localIP != "" {
		options["local_ip"] = localIP
	}
	if remoteName != "" {
		options["remote_name"] = remoteName
	}
	if psk != "" {
		options["psk"] = psk
	}
	if csum {
		options["csum"] = "true"
	}

	return br.createPort(name, name, string(tunnelType), ofPortRequest, 0, "", externalIDs, options)
}

// GetInterfaceOptions returns the options of the provided interface.
func (br *OVSBridge) GetInterfaceOptions(name string) (map[string]string, Error) {
	ctx := context.Background()
	intf := &Interface{Name: name}
	err := br.getModel(ctx, intf)
	if err != nil {
		klog.Error("Get failed: ", err)
		return nil, NewTransactionError(err, true)
	}
	return intf.Options, nil
}

// SetInterfaceOptions sets the specified options of the provided interface.
func (br *OVSBridge) SetInterfaceOptions(name string, options map[string]interface{}) Error {
	ctx := context.Background()
	intf := &Interface{Name: name}
	err := br.getModel(ctx, intf)
	if err != nil {
		klog.Error("Get failed: ", err)
		return NewTransactionError(err, true)
	}

	intf.Options = make(map[string]string)
	for k, v := range options {
		if val, ok := v.(string); ok {
			intf.Options[k] = val
		}
	}

	ops, err := br.ovsdb.Where(&Interface{UUID: intf.UUID}).Update(intf)
	if err != nil {
		return NewTransactionError(err, false)
	}
	_, err = br.ovsdb.Transact(ctx, ops...)
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return NewTransactionError(err, true)
	}
	return nil
}

// ParseTunnelInterfaceOptions reads remote IP, local IP, IPsec PSK, and csum
// from the tunnel interface options and returns them.
func ParseTunnelInterfaceOptions(portData *OVSPortData) (net.IP, net.IP, int32, string, string, bool) {
	if portData.Options == nil {
		return nil, nil, 0, "", "", false
	}

	var ok bool
	var remoteIPStr, localIPStr, psk, remoteName string
	var remoteIP, localIP net.IP
	var csum bool
	var destinationPort int64

	if remoteIPStr, ok = portData.Options["remote_ip"]; ok {
		if remoteIPStr != "flow" {
			remoteIP = net.ParseIP(remoteIPStr)
		}
	}
	if localIPStr, ok = portData.Options["local_ip"]; ok {
		localIP = net.ParseIP(localIPStr)
	}
	psk = portData.Options["psk"]
	if csumStr, ok := portData.Options["csum"]; ok {
		csum, _ = strconv.ParseBool(csumStr)
	}
	remoteName = portData.Options["remote_name"]
	if destinationPortStr, ok := portData.Options["dst_port"]; ok {
		destinationPort, _ = strconv.ParseInt(destinationPortStr, 10, 32)
	}
	return remoteIP, localIP, int32(destinationPort), psk, remoteName, csum
}

// CreateUplinkPort creates uplink port.
func (br *OVSBridge) CreateUplinkPort(name string, ofPortRequest int32, externalIDs map[string]interface{}) (string, Error) {
	return br.createPort(name, name, "", ofPortRequest, 0, "", externalIDs, nil)
}

// CreatePort creates a port with the specified name on the bridge, and connects
// the interface specified by ifDev to the port.
// If externalIDs is not empty, the map key/value pairs will be set to the
// port's external_ids.
func (br *OVSBridge) CreatePort(name, ifDev string, externalIDs map[string]interface{}) (string, Error) {
	return br.createPort(name, ifDev, "", 0, 0, "", externalIDs, nil)
}

// CreateAccessPort creates a port with the specified name and VLAN ID on the bridge, and connects
// the interface specified by ifDev to the port.
// If externalIDs is not empty, the map key/value pairs will be set to the
// port's external_ids.
// vlanID=0 will perform same behavior as CreatePort.
func (br *OVSBridge) CreateAccessPort(name, ifDev string, externalIDs map[string]interface{}, vlanID uint16) (string, Error) {
	return br.createPort(name, ifDev, "", 0, vlanID, "", externalIDs, nil)
}

func (br *OVSBridge) createPort(name, ifName, ifType string, ofPortRequest int32, vlanID uint16, mac string, externalIDs, options map[string]interface{}) (string, Error) {
	ctx := context.Background()

	for _, id := range br.requiredPortExternalIDs {
		if _, ok := externalIDs[id]; !ok {
			return "", newInvalidArgumentsError(fmt.Sprintf("missing required externalID '%s' for port '%s'", id, name))
		}
	}

	intf := &Interface{
		UUID: namedUUID(),
		Name: ifName,
		Type: ifType,
	}
	if mac != "" {
		intf.MAC = &mac
	}
	if ofPortRequest != 0 {
		ofp := int(ofPortRequest)
		intf.OFPortRequest = &ofp
	}
	if options != nil {
		intf.Options = make(map[string]string)
		for k, v := range options {
			if val, ok := v.(string); ok {
				intf.Options[k] = val
			}
		}
	}

	ops, err := br.ovsdb.Create(intf)
	if err != nil {
		return "", NewTransactionError(fmt.Errorf("Create intf failed: %v", err), false)
	}
	ifNamedUUID := ops[0].UUIDName

	port := &Port{
		UUID:       namedUUID(),
		Name:       name,
		Interfaces: []string{ifNamedUUID},
	}
	if externalIDs != nil {
		port.ExternalIDs = make(map[string]string)
		for k, v := range externalIDs {
			if val, ok := v.(string); ok {
				port.ExternalIDs[k] = val
			}
		}
	}
	if vlanID > 0 {
		tag := int(vlanID)
		port.Tag = &tag
	}

	ops2, err := br.ovsdb.Create(port)
	if err != nil {
		return "", NewTransactionError(fmt.Errorf("Create port failed: %v", err), false)
	}
	ops = append(ops, ops2...)
	portNamedUUID := ops2[0].UUIDName

	bridge := &Bridge{UUID: br.uuid}
	mutation := model.Mutation{
		Field:   &bridge.Ports,
		Mutator: ovsdb.MutateOperationInsert,
		Value:   []string{portNamedUUID},
	}
	ops3, err := br.ovsdb.Where(bridge).Mutate(bridge, mutation)
	if err != nil {
		return "", NewTransactionError(fmt.Errorf("Mutate bridge failed: %v", err), false)
	}
	ops = append(ops, ops3...)

	res, err := br.ovsdb.Transact(ctx, ops...)
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return "", NewTransactionError(fmt.Errorf("Transact failed: %v", err), true)
	}

	return res[1].UUID.GoUUID, nil
}

// GetOFPort retrieves the ofport value of an interface given the interface name.
// The function will invoke OVSDB "wait" operation with 5 seconds timeout to
// wait the ofport is set on the interface, and so could be blocked for 5
// seconds. If the "wait" operation times out or the interface is not found, or
// the ofport is invalid, value 0 and an error will be returned.
// If waitUntilValid is true, the function will wait the ofport is not -1 with
// 5 seconds timeout. This parameter is used after the interface type is changed
// by the client.
func (br *OVSBridge) GetOFPort(ifName string, waitUntilValid bool) (int32, Error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultGetPortTimeout)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return 0, NewTransactionError(fmt.Errorf("timeout waiting for ofport for %s", ifName), false)
		default:
		}

		intf := &Interface{Name: ifName}
		err := br.ovsdb.Get(ctx, intf)
		if err != nil {
			if err == client.ErrNotFound {
				return 0, NewTransactionError(fmt.Errorf("interface %s not found", ifName), false)
			}
			klog.Error("Get failed: ", err)
			return 0, NewTransactionError(err, true)
		}

		if intf.OFPort != nil {
			ofport := *intf.OFPort
			if waitUntilValid {
				if ofport > 0 {
					return int32(ofport), nil
				}
			} else {
				if ofport > 0 {
					return int32(ofport), nil
				} else if ofport < 0 {
					return 0, NewTransactionError(fmt.Errorf("invalid ofport %d", ofport), false)
				}
			}
		}

		time.Sleep(500 * time.Millisecond)
	}
}

func buildPortDataCommon(port *Port, intf *Interface, portData *OVSPortData) {
	portData.Name = port.Name
	portData.ExternalIDs = port.ExternalIDs
	if port.Tag != nil {
		portData.VLANID = uint16(*port.Tag)
	}
	portData.Options = intf.Options
	portData.IFType = intf.Type
	if intf.OFPort != nil {
		portData.OFPort = int32(*intf.OFPort)
	} else { // ofport not assigned by OVS yet
		portData.OFPort = 0
	}
	if intf.MAC != nil && *intf.MAC != "" {
		if mac, err := net.ParseMAC(*intf.MAC); err == nil {
			portData.MAC = mac
		}
	}
}

// GetPortData retrieves port data given the OVS port UUID and interface name.
// nil is returned, if the port or interface could not be found, or the
// interface is not attached to the port.
// The port's OFPort will be set to 0, if its ofport is not assigned by OVS yet.
func (br *OVSBridge) GetPortData(portUUID, ifName string) (*OVSPortData, Error) {
	ctx := context.Background()

	port := &Port{UUID: portUUID}
	err := br.getModel(ctx, port)
	if err != nil {
		if err == client.ErrNotFound {
			return nil, NewTransactionError(fmt.Errorf("port %s not found", portUUID), false)
		}
		return nil, NewTransactionError(err, true)
	}

	intf := &Interface{Name: ifName}
	err = br.getModel(ctx, intf)
	if err != nil {
		if err == client.ErrNotFound {
			return nil, NewTransactionError(fmt.Errorf("interface %s not found", ifName), false)
		}
		return nil, NewTransactionError(err, true)
	}

	found := false
	for _, uuid := range port.Interfaces {
		if uuid == intf.UUID {
			found = true
			break
		}
	}
	if !found {
		return nil, NewTransactionError(fmt.Errorf("interface %s not attached to port %s", ifName, portUUID),
			false)
	}

	portData := OVSPortData{UUID: portUUID, IFName: ifName}
	buildPortDataCommon(port, intf, &portData)
	return &portData, nil
}

// GetPortList returns all ports on the bridge.
// A port's OFPort will be set to 0, if its ofport is not assigned by OVS yet.
func (br *OVSBridge) GetPortList() ([]OVSPortData, Error) {
	ctx := context.Background()

	bridge := &Bridge{Name: br.name}
	err := br.getModel(ctx, bridge)
	if err != nil {
		klog.InfoS("Could not find bridge")
		return []OVSPortData{}, nil
	}

	portList := make([]OVSPortData, 0, len(bridge.Ports))
	for _, portUUID := range bridge.Ports {
		port := &Port{UUID: portUUID}
		err = br.getModel(ctx, port)
		if err != nil {
			klog.Warningf("Failed to get port %s: %v", portUUID, err)
			continue
		}
		if len(port.Interfaces) == 0 {
			continue
		}
		intf := &Interface{UUID: port.Interfaces[0]}
		err = br.getModel(ctx, intf)
		if err != nil {
			klog.Warningf("Failed to get interface %s: %v", port.Interfaces[0], err)
			continue
		}

		portData := OVSPortData{UUID: portUUID, IFName: intf.Name}
		buildPortDataCommon(port, intf, &portData)
		portList = append(portList, portData)
	}

	return portList, nil
}

// GetOVSVersion either returns the version of OVS, or an error.
func (br *OVSBridge) GetOVSVersion() (string, Error) {
	ctx := context.Background()

	var ovsList []Open_vSwitch
	err := br.ovsdb.List(ctx, &ovsList)
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return "", NewTransactionError(err, true)
	}

	if len(ovsList) == 0 {
		klog.ErrorS(nil, "Could not find ovs_version in the OVS query result")
		return "", NewTransactionError(fmt.Errorf("no results from OVS query"), false)
	}
	if ovsList[0].OvsVersion != nil {
		return *ovsList[0].OvsVersion, nil
	}
	return "", nil
}

// AddOVSOtherConfig adds the given configs to the "other_config" column of
// the single record in the "Open_vSwitch" table.
// For each config, it will only be added if its key doesn't already exist.
// No error is returned if configs already exist.
func (br *OVSBridge) AddOVSOtherConfig(configs map[string]interface{}) Error {
	ctx := context.Background()

	var ovsList []Open_vSwitch
	err := br.ovsdb.List(ctx, &ovsList)
	if err != nil || len(ovsList) == 0 {
		return NewTransactionError(err, true)
	}
	ovs := &ovsList[0]

	mutateMap := make(map[string]string)
	for k, v := range configs {
		if val, ok := v.(string); ok {
			mutateMap[k] = val
		}
	}

	if len(mutateMap) > 0 {
		mutation := model.Mutation{
			Field:   &ovs.OtherConfig,
			Mutator: ovsdb.MutateOperationInsert,
			Value:   mutateMap,
		}
		ops, err := br.ovsdb.Where(&Open_vSwitch{UUID: ovs.UUID}).Mutate(ovs, mutation)
		if err != nil {
			return NewTransactionError(err, false)
		}
		_, err = br.ovsdb.Transact(ctx, ops...)
		if err != nil {
			klog.Error("Transaction failed: ", err)
			return NewTransactionError(err, true)
		}
	}
	return nil
}

func (br *OVSBridge) GetOVSOtherConfig() (map[string]string, Error) {
	ctx := context.Background()

	var ovsList []Open_vSwitch
	err := br.ovsdb.List(ctx, &ovsList)
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return nil, NewTransactionError(err, true)
	}
	if len(ovsList) == 0 {
		klog.InfoS("Could not find other_config")
		return nil, nil
	}
	return ovsList[0].OtherConfig, nil
}

// UpdateOVSOtherConfig updates the given configs to the "other_config" column of
// the single record in the "Open_vSwitch" table.
// For each config, it will be updated if the existing value does not match the given one,
// and it will be added if its key does not exist.
// It the configs are already up to date, this function will be a no-op.
func (br *OVSBridge) UpdateOVSOtherConfig(configs map[string]interface{}) Error {
	ctx := context.Background()

	var ovsList []Open_vSwitch
	err := br.ovsdb.List(ctx, &ovsList)
	if err != nil || len(ovsList) == 0 {
		return NewTransactionError(err, true)
	}
	ovs := &ovsList[0]

	mutateMap := make(map[string]string)
	var keys []string
	for k, v := range configs {
		if val, ok := v.(string); ok {
			mutateMap[k] = val
			keys = append(keys, k)
		}
	}

	if len(mutateMap) > 0 {
		mutations := []model.Mutation{
			{
				Field:   &ovs.OtherConfig,
				Mutator: ovsdb.MutateOperationDelete,
				Value:   keys,
			},
			{
				Field:   &ovs.OtherConfig,
				Mutator: ovsdb.MutateOperationInsert,
				Value:   mutateMap,
			},
		}
		ops, err := br.ovsdb.Where(&Open_vSwitch{UUID: ovs.UUID}).Mutate(ovs, mutations...)
		if err != nil {
			return NewTransactionError(err, false)
		}
		_, err = br.ovsdb.Transact(ctx, ops...)
		if err != nil {
			klog.Error("Transaction failed: ", err)
			return NewTransactionError(err, true)
		}
	}
	return nil
}

// DeleteOVSOtherConfig deletes the given configs from the "other_config" column of
// the single record in the "Open_vSwitch" table.
// For each config, it will be deleted if its key exists and the given value is empty string or
// its value matches the given one. No error is returned if configs don't exist or don't match.
func (br *OVSBridge) DeleteOVSOtherConfig(configs map[string]interface{}) Error {
	ctx := context.Background()

	var ovsList []Open_vSwitch
	err := br.ovsdb.List(ctx, &ovsList)
	if err != nil || len(ovsList) == 0 {
		return NewTransactionError(err, true)
	}
	ovs := &ovsList[0]

	if ovs.OtherConfig == nil {
		return nil
	}

	var deleteList []string
	deleteMap := make(map[string]string)
	for k, v := range configs {
		if val, ok := v.(string); ok {
			if val == "" {
				deleteList = append(deleteList, k)
			} else {
				deleteMap[k] = val
			}
		}
	}

	var mutations []model.Mutation
	if len(deleteList) > 0 {
		mutations = append(mutations, model.Mutation{
			Field:   &ovs.OtherConfig,
			Mutator: ovsdb.MutateOperationDelete,
			Value:   deleteList,
		})
	}
	if len(deleteMap) > 0 {
		mutations = append(mutations, model.Mutation{
			Field:   &ovs.OtherConfig,
			Mutator: ovsdb.MutateOperationDelete,
			Value:   deleteMap,
		})
	}

	if len(mutations) > 0 {
		ops, err := br.ovsdb.Where(&Open_vSwitch{UUID: ovs.UUID}).Mutate(ovs, mutations...)
		if err != nil {
			return NewTransactionError(err, false)
		}
		_, err = br.ovsdb.Transact(ctx, ops...)
		if err != nil {
			klog.Error("Transaction failed: ", err)
			return NewTransactionError(err, true)
		}
	}
	return nil
}

// AddBridgeOtherConfig adds the given configs to the "other_config" column of
// the single record in the "Bridge" table.
// For each config, it will only be added if its key doesn't already exist.
// No error is returned if configs already exist.
func (br *OVSBridge) AddBridgeOtherConfig(configs map[string]interface{}) Error {
	ctx := context.Background()

	bridge := &Bridge{Name: br.name}
	err := br.getModel(ctx, bridge)
	if err != nil {
		klog.Error("Get failed: ", err)
		return NewTransactionError(err, true)
	}

	mutateMap := make(map[string]string)
	for k, v := range configs {
		if val, ok := v.(string); ok {
			mutateMap[k] = val
		}
	}

	if len(mutateMap) > 0 {
		mutation := model.Mutation{
			Field:   &bridge.OtherConfig,
			Mutator: ovsdb.MutateOperationInsert,
			Value:   mutateMap,
		}
		ops, err := br.ovsdb.Where(&Bridge{UUID: bridge.UUID}).Mutate(bridge, mutation)
		if err != nil {
			return NewTransactionError(err, false)
		}
		_, err = br.ovsdb.Transact(ctx, ops...)
		if err != nil {
			klog.Error("Transaction failed: ", err)
			return NewTransactionError(err, true)
		}
	}
	return nil
}

func (br *OVSBridge) GetBridgeName() string {
	return br.name
}

func (br *OVSBridge) IsHardwareOffloadEnabled() bool {
	return br.isHardwareOffloadEnabled
}

func (br *OVSBridge) getHardwareOffload() (bool, Error) {
	otherConfig, err := br.GetOVSOtherConfig()
	if err != nil {
		return false, err
	}
	for configKey, configValue := range otherConfig {
		if configKey == hardwareOffload {
			boolConfigVal, err := strconv.ParseBool(configValue)
			if err != nil {
				return boolConfigVal, newInvalidArgumentsError(fmt.Sprint("invalid hardwareOffload value: ", boolConfigVal))
			}
			return boolConfigVal, nil
		}
	}
	return false, nil
}

func (br *OVSBridge) GetOVSDatapathType() OVSDatapathType {
	return br.datapathType
}

// SetInterfaceType modifies the OVS Interface type to the given ifType.
// This function is used on Windows when the Pod interface is created after the OVS port creation.
func (br *OVSBridge) SetInterfaceType(name, ifType string) Error {
	ctx := context.Background()
	intf := &Interface{Name: name}
	err := br.getModel(ctx, intf)
	if err != nil {
		klog.Error("Get failed: ", err)
		return NewTransactionError(err, true)
	}

	intf.Type = ifType
	ops, err := br.ovsdb.Where(&Interface{UUID: intf.UUID}).Update(intf)
	if err != nil {
		return NewTransactionError(err, false)
	}

	_, err = br.ovsdb.Transact(ctx, ops...)
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return NewTransactionError(err, true)
	}
	return nil
}

func (br *OVSBridge) SetPortExternalIDs(portName string, externalIDs map[string]interface{}) Error {
	ctx := context.Background()
	port := &Port{Name: portName}
	err := br.getModel(ctx, port)
	if err != nil {
		klog.Error("Get failed", err)
		return NewTransactionError(err, true)
	}

	port.ExternalIDs = make(map[string]string)
	for k, v := range externalIDs {
		if val, ok := v.(string); ok {
			port.ExternalIDs[k] = val
		}
	}

	ops, err := br.ovsdb.Where(&Port{UUID: port.UUID}).Update(port)
	if err != nil {
		return NewTransactionError(err, false)
	}
	_, err = br.ovsdb.Transact(ctx, ops...)
	if err != nil {
		klog.Error("Transaction failed", err)
		return NewTransactionError(err, true)
	}
	return nil
}

func (br *OVSBridge) GetPortExternalIDs(portName string) (map[string]string, Error) {
	ctx := context.Background()
	port := &Port{Name: portName}
	err := br.getModel(ctx, port)
	if err != nil {
		klog.Error("Get failed", err)
		return nil, NewTransactionError(err, true)
	}
	return port.ExternalIDs, nil
}

func (br *OVSBridge) SetInterfaceMTU(name string, MTU int) error {
	ctx := context.Background()
	intf := &Interface{Name: name}
	err := br.getModel(ctx, intf)
	if err != nil {
		klog.Error("Get failed: ", err)
		return NewTransactionError(err, true)
	}

	mtu := int(MTU)
	intf.MTURequest = &mtu
	ops, err := br.ovsdb.Where(&Interface{UUID: intf.UUID}).Update(intf)
	if err != nil {
		return NewTransactionError(err, false)
	}

	_, err = br.ovsdb.Transact(ctx, ops...)
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return NewTransactionError(err, true)
	}

	return nil
}

func (br *OVSBridge) SetInterfaceMAC(name string, mac net.HardwareAddr) Error {
	ctx := context.Background()
	intf := &Interface{Name: name}
	err := br.getModel(ctx, intf)
	if err != nil {
		klog.Error("Get failed: ", err)
		return NewTransactionError(err, true)
	}

	macStr := mac.String()
	intf.MAC = &macStr
	ops, err := br.ovsdb.Where(&Interface{UUID: intf.UUID}).Update(intf)
	if err != nil {
		return NewTransactionError(err, false)
	}

	_, err = br.ovsdb.Transact(ctx, ops...)
	if err != nil {
		klog.Error("Transaction failed: ", err)
		return NewTransactionError(err, true)
	}

	return nil

}

func (br *OVSBridge) GetBridgeMcastSnoopingEnable() (bool, Error) {
	ctx := context.Background()
	bridge := &Bridge{Name: br.name}
	err := br.getModel(ctx, bridge)
	if err != nil {
		klog.Error("Get failed: ", err)
		return false, NewTransactionError(err, true)
	}

	return bridge.McastSnoopingEnable, nil
}
