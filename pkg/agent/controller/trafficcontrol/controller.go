// Copyright 2022 Antrea Authors
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

package trafficcontrol

import (
	"crypto/sha1" // #nosec G505: not used for security purposes
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	"antrea.io/antrea/pkg/agent/interfacestore"
	"antrea.io/antrea/pkg/agent/openflow"
	"antrea.io/antrea/pkg/agent/types"
	"antrea.io/antrea/pkg/agent/util"
	"antrea.io/antrea/pkg/apis/crd/v1alpha2"
	crdinformers "antrea.io/antrea/pkg/client/informers/externalversions/crd/v1alpha2"
	crdlisters "antrea.io/antrea/pkg/client/listers/crd/v1alpha2"
	"antrea.io/antrea/pkg/ovs/ovsconfig"
	"antrea.io/antrea/pkg/util/channel"
	"antrea.io/antrea/pkg/util/k8s"
	utilsets "antrea.io/antrea/pkg/util/sets"
)

const (
	controllerName = "TrafficControlController"
	// How long to wait before retrying the processing of a TrafficControl change.
	minRetryDelay = 5 * time.Second
	maxRetryDelay = 300 * time.Second
	// Default number of workers processing a TrafficControl change.
	defaultWorkers = 4
	// Disable resyncing.
	resyncPeriod time.Duration = 0

	// Default VXLAN tunnel destination port.
	defaultVXLANTunnelDestinationPort = int32(4789)
	// Default Geneve tunnel destination port.
	defaultGENEVETunnelDestinationPort = int32(6081)

	portNamePrefixVXLAN  = "vxlan"
	portNamePrefixGENEVE = "geneve"
	portNamePrefixGRE    = "gre"
	portNamePrefixERSPAN = "erspan"

	maxRetryForHostLink = 5

	targetPortIndexName = "targetPort"
	returnPortIndexName = "returnPort"
)

// trafficControlState keeps the actual state of a TrafficControl that has been realized.
type trafficControlState struct {
	// TrafficControl name.
	name string
	// The actual target port of a TrafficControl.
	targetPort uint32
	// The actual return port of a TrafficControl.
	returnPort uint32
	// The actual action of a TrafficControl.
	action v1alpha2.TrafficControlAction
	// The actual direction of a TrafficControl.
	direction v1alpha2.Direction
	// The actual openflow ports for which we have installed flows for a TrafficControl. Note that, flows are only installed
	// for the Pods whose effective TrafficControl is the current TrafficControl, and the openflow ports are these Pods'.
	ofPorts sets.Int32
	// The actual Pods applying to the TrafficControl. Note that, a TrafficControl can be either effective TrafficControl
	// or alternative TrafficControl for these Pods.
	pods sets.String
}

type Controller struct {
	ofClient openflow.Client

	ovsBridgeClient    ovsconfig.OVSBridgeClient
	ovsPortUpdateMutex sync.Mutex

	interfaceStore interfacestore.InterfaceStore

	podInformer     cache.SharedIndexInformer
	podLister       corelisters.PodLister
	podListerSynced cache.InformerSynced

	namespaceInformer     cache.SharedIndexInformer
	namespaceLister       corelisters.NamespaceLister
	namespaceListerSynced cache.InformerSynced

	podToTCBindings          map[string]*podToTCBinding
	podToTCBindingsMutex     sync.RWMutex
	installedTrafficControls cache.Indexer

	trafficControlInformer     cache.SharedIndexInformer
	trafficControlLister       crdlisters.TrafficControlLister
	trafficControlListerSynced cache.InformerSynced
	queue                      workqueue.RateLimitingInterface
}

// podToTCBinding keeps the TrafficControls applying to a Pod. There is only one effective TrafficControl for a Pod at any
// given time.
type podToTCBinding struct {
	effectiveTC    string
	alternativeTCs sets.String
}

func NewTrafficControlController(ofClient openflow.Client,
	interfaceStore interfacestore.InterfaceStore,
	ovsBridgeClient ovsconfig.OVSBridgeClient,
	tcInformer crdinformers.TrafficControlInformer,
	podInformer cache.SharedIndexInformer,
	namespaceInformer coreinformers.NamespaceInformer,
	podUpdateSubscriber channel.Subscriber) *Controller {
	c := &Controller{
		ofClient:                   ofClient,
		ovsBridgeClient:            ovsBridgeClient,
		interfaceStore:             interfaceStore,
		trafficControlInformer:     tcInformer.Informer(),
		trafficControlLister:       tcInformer.Lister(),
		trafficControlListerSynced: tcInformer.Informer().HasSynced,
		podInformer:                podInformer,
		podLister:                  corelisters.NewPodLister(podInformer.GetIndexer()),
		podListerSynced:            podInformer.HasSynced,
		namespaceInformer:          namespaceInformer.Informer(),
		namespaceLister:            namespaceInformer.Lister(),
		namespaceListerSynced:      namespaceInformer.Informer().HasSynced,
		podToTCBindings:            map[string]*podToTCBinding{},
		installedTrafficControls:   cache.NewIndexer(tcInfoKeyFunc, cache.Indexers{targetPortIndexName: tcTargetPortIndexFunc, returnPortIndexName: tcReturnPortIndexFunc}),
		queue:                      workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "trafficControlGroup"),
	}
	c.trafficControlInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addTC,
			UpdateFunc: c.updateTC,
			DeleteFunc: c.deleteTC,
		},
		resyncPeriod,
	)
	c.podInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addPod,
			UpdateFunc: c.updatePod,
			DeleteFunc: c.deletePod,
		},
		resyncPeriod,
	)
	c.namespaceInformer.AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addNamespace,
			UpdateFunc: c.updateNamespace,
			DeleteFunc: nil,
		},
		resyncPeriod,
	)
	podUpdateSubscriber.Subscribe(c.processPodUpdate)
	return c
}

func tcInfoKeyFunc(obj interface{}) (string, error) {
	return obj.(trafficControlState).name, nil
}

func tcTargetPortIndexFunc(obj interface{}) ([]string, error) {
	tcState := obj.(trafficControlState)
	return []string{strconv.Itoa(int(tcState.targetPort))}, nil
}

func tcReturnPortIndexFunc(obj interface{}) ([]string, error) {
	tcState := obj.(trafficControlState)
	return []string{strconv.Itoa(int(tcState.returnPort))}, nil
}

// processPodUpdate will be called when CNIServer publishes a Pod update event. It triggers the event for the effective
// TrafficControl of the Pod.
func (c *Controller) processPodUpdate(e interface{}) {
	c.podToTCBindingsMutex.RLock()
	defer c.podToTCBindingsMutex.RUnlock()
	podEvent := e.(types.PodUpdate)
	pod := k8s.NamespacedName(podEvent.PodNamespace, podEvent.PodName)
	binding, exists := c.podToTCBindings[pod]
	if !exists {
		return
	}
	c.queue.Add(binding.effectiveTC)
}

func (c *Controller) matchedPod(pod *v1.Pod, to *v1alpha2.AppliedTo) bool {
	if to.NamespaceSelector == nil && to.PodSelector == nil {
		return false
	}
	if to.NamespaceSelector != nil {
		namespace, _ := c.namespaceLister.Get(pod.Namespace)
		if namespace == nil {
			return false
		}
		nsSelector, _ := metav1.LabelSelectorAsSelector(to.NamespaceSelector)
		if !nsSelector.Matches(labels.Set(namespace.Labels)) {
			return false
		}
	}
	if to.PodSelector != nil {
		podSelector, _ := metav1.LabelSelectorAsSelector(to.PodSelector)
		if !podSelector.Matches(labels.Set(pod.Labels)) {
			return false
		}
	}

	return true
}

func (c *Controller) filterAffectedTCsByPod(pod *v1.Pod) sets.String {
	affectedTCs := sets.NewString()
	allTCs, _ := c.trafficControlLister.List(labels.Everything())
	for _, tc := range allTCs {
		if c.matchedPod(pod, &tc.Spec.AppliedTo) {
			affectedTCs.Insert(tc.GetName())
		}
	}
	return affectedTCs
}

func (c *Controller) addPod(obj interface{}) {
	pod := obj.(*v1.Pod)
	if pod.Spec.HostNetwork {
		return
	}
	affectedTCs := c.filterAffectedTCsByPod(pod)
	if len(affectedTCs) == 0 {
		return
	}
	klog.V(2).InfoS("Processing Pod ADD event", "Pod", klog.KObj(pod))
	for affectedTC := range affectedTCs {
		c.queue.Add(affectedTC)
	}
}

func (c *Controller) updatePod(oldObj interface{}, obj interface{}) {
	oldPod := oldObj.(*v1.Pod)
	pod := obj.(*v1.Pod)
	if pod.Spec.HostNetwork {
		return
	}
	if reflect.DeepEqual(pod.GetLabels(), oldPod.GetLabels()) {
		return
	}
	oldAffectedTCs := c.filterAffectedTCsByPod(oldPod)
	nowAffectedTCs := c.filterAffectedTCsByPod(pod)
	affectedTCs := utilsets.SymmetricDifferenceString(oldAffectedTCs, nowAffectedTCs)
	if len(affectedTCs) == 0 {
		return
	}
	klog.V(2).InfoS("Processing Pod UPDATE event", "Pod", klog.KObj(pod))
	for affectedTC := range affectedTCs {
		c.queue.Add(affectedTC)
	}
}

func (c *Controller) deletePod(obj interface{}) {
	pod := obj.(*v1.Pod)
	if pod.Spec.HostNetwork {
		return
	}
	affectedTCs := c.filterAffectedTCsByPod(pod)
	if len(affectedTCs) == 0 {
		return
	}
	klog.V(2).InfoS("Processing Pod DELETE event", "Pod", klog.KObj(pod))
	for affectedTC := range affectedTCs {
		c.queue.Add(affectedTC)
	}
}

func matchedNamespace(namespace *v1.Namespace, to *v1alpha2.AppliedTo) bool {
	if to.NamespaceSelector != nil {
		nsSelector, _ := metav1.LabelSelectorAsSelector(to.NamespaceSelector)
		if !nsSelector.Matches(labels.Set(namespace.Labels)) {
			return false
		}
	}
	return true
}

func (c *Controller) filterAffectedTCsByNS(namespace *v1.Namespace) sets.String {
	affectedTCs := sets.NewString()
	allTCs, _ := c.trafficControlLister.List(labels.Everything())
	for _, tc := range allTCs {
		if matchedNamespace(namespace, &tc.Spec.AppliedTo) {
			affectedTCs.Insert(tc.GetName())
		}
	}
	return affectedTCs
}

func (c *Controller) addNamespace(obj interface{}) {
	ns := obj.(*v1.Namespace)
	affectedTCs := c.filterAffectedTCsByNS(ns)
	if len(affectedTCs) == 0 {
		return
	}
	klog.V(2).InfoS("Processing Namespace ADD event", "Namespace", klog.KObj(ns))
	for tc := range affectedTCs {
		c.queue.Add(tc)
	}
}

func (c *Controller) updateNamespace(oldObj, obj interface{}) {
	oldNS := oldObj.(*v1.Namespace)
	ns := obj.(*v1.Namespace)
	if reflect.DeepEqual(oldNS.GetLabels(), ns.GetLabels()) {
		return
	}
	oldAffectedTCs := c.filterAffectedTCsByNS(oldNS)
	nowAffectedTCs := c.filterAffectedTCsByNS(ns)
	affectedTCs := utilsets.SymmetricDifferenceString(oldAffectedTCs, nowAffectedTCs)
	if len(affectedTCs) == 0 {
		return
	}
	klog.V(2).InfoS("Processing Namespace UPDATE event", "Namespace", klog.KObj(ns))
	for tc := range affectedTCs {
		c.queue.Add(tc)
	}
}

func (c *Controller) addTC(obj interface{}) {
	tc := obj.(*v1alpha2.TrafficControl)
	klog.V(2).InfoS("Processing TrafficControl ADD event", "TrafficControl", klog.KObj(tc))
	c.queue.Add(tc.Name)
}

func (c *Controller) updateTC(oldObj interface{}, obj interface{}) {
	oldTC := oldObj.(*v1alpha2.TrafficControl)
	tc := obj.(*v1alpha2.TrafficControl)
	if tc.GetGeneration() != oldTC.GetGeneration() {
		klog.V(2).InfoS("Processing TrafficControl UPDATE event", "TrafficControl", klog.KObj(tc))
		c.queue.Add(tc.Name)
	}
}

func (c *Controller) deleteTC(obj interface{}) {
	tc := obj.(*v1alpha2.TrafficControl)
	klog.V(2).InfoS("Processing TrafficControl DELETE event", "TrafficControl", klog.KObj(tc))
	c.queue.Add(tc.Name)
}

func (c *Controller) Run(stopCh <-chan struct{}) {
	defer c.queue.ShutDown()

	klog.InfoS("Starting", "controllerName", controllerName)
	defer klog.InfoS("Shutting down", "controllerName", controllerName)

	if !cache.WaitForNamedCacheSync(controllerName, stopCh, c.trafficControlListerSynced, c.podListerSynced, c.namespaceListerSynced) {
		return
	}

	for i := 0; i < defaultWorkers; i++ {
		go wait.Until(c.worker, time.Second, stopCh)
	}

	<-stopCh
}

func (c *Controller) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *Controller) processNextWorkItem() bool {
	obj, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(obj)

	if key, ok := obj.(string); !ok {
		// As the item in the work queue is actually invalid, we call Forget here else we'd
		// go into a loop of attempting to process a work item that is invalid.
		// This should not happen.
		c.queue.Forget(obj)
		klog.Errorf("Expected string in work queue but got %#v", obj)
		return true
	} else if err := c.syncTrafficControl(key); err == nil {
		// If no error occurs we Forget this item, so it does not get queued again until
		// another change happens.
		c.queue.Forget(key)
	} else {
		// Put the item back on the work queue to handle any transient errors.
		c.queue.AddRateLimited(key)
		klog.ErrorS(err, "Syncing TrafficControl failed, requeue", "TrafficControl", key)
	}
	return true
}

func (c *Controller) newTrafficControlState(tc string, action v1alpha2.TrafficControlAction, direction v1alpha2.Direction) trafficControlState {
	state := trafficControlState{
		name:      tc,
		pods:      sets.NewString(),
		ofPorts:   sets.NewInt32(),
		action:    action,
		direction: direction,
	}
	c.installedTrafficControls.Add(state)
	return state
}

func (c *Controller) getTrafficControlState(tc string) (trafficControlState, bool) {
	state, exists, _ := c.installedTrafficControls.GetByKey(tc)
	if exists {
		return state.(trafficControlState), exists
	}
	return trafficControlState{}, false
}

func (c *Controller) filterPods(appliedTo *v1alpha2.AppliedTo) ([]*v1.Pod, error) {
	// If both selector are nil, no Pod should be selected.
	if appliedTo.PodSelector == nil && appliedTo.NamespaceSelector == nil {
		return nil, nil
	}
	var podSelector, nsSelector labels.Selector
	var err error
	var selectedPods []*v1.Pod

	if appliedTo.PodSelector != nil {
		// If Pod selector is not nil, use it to select Pods.
		podSelector, err = metav1.LabelSelectorAsSelector(appliedTo.PodSelector)
		if err != nil {
			return nil, err
		}
	} else {
		// If Pod selector is nil, then Namespace selector will be not nil, select all Pods in the namespaces selected by
		// Namespace selector.
		podSelector = labels.Everything()
	}

	if appliedTo.NamespaceSelector != nil {
		// If Namespace selector is not nil, use it to select namespaces.
		var namespaces []*v1.Namespace
		nsSelector, err = metav1.LabelSelectorAsSelector(appliedTo.NamespaceSelector)
		if err != nil {
			return nil, err
		}
		namespaces, err = c.namespaceLister.List(nsSelector)
		if err != nil {
			return nil, err
		}
		// Select Pods with Pod selector from all selected namespaces.
		for _, ns := range namespaces {
			pods, err := c.podLister.Pods(ns.Name).List(podSelector)
			if err != nil {
				return nil, err
			}
			selectedPods = append(selectedPods, pods...)
		}
	} else {
		// If Namespace selector is nil, use Pod selector to select Pods from all namespaces.
		selectedPods, err = c.podLister.List(podSelector)
		if err != nil {
			return nil, err
		}
	}

	var nonHostNetworkPods []*v1.Pod
	// TrafficControl does not support host network Pods.
	for _, pod := range selectedPods {
		if !pod.Spec.HostNetwork {
			nonHostNetworkPods = append(nonHostNetworkPods, pod)
		}
	}

	return nonHostNetworkPods, nil
}

func genTunnelPortName(portNamePrefix string, config interface{}) string {
	hash := sha1.New() // #nosec G401: not used for security purposes
	buf := make([]byte, 4)

	writeUint32 := func(val uint32) {
		binary.BigEndian.PutUint32(buf, val)
		hash.Write(buf)
	}
	writeIP := func(ip string) {
		hash.Write(net.ParseIP(ip))
	}

	switch config.(type) {
	case *v1alpha2.UDPTunnel:
		tunnelConfig := config.(*v1alpha2.UDPTunnel)
		writeIP(tunnelConfig.RemoteIP)
		writeUint32(uint32(*tunnelConfig.DestinationPort))
		var vni uint32
		if tunnelConfig.VNI != nil {
			vni = uint32(*tunnelConfig.VNI)
		}
		writeUint32(vni)

	case *v1alpha2.GRETunnel:
		tunnelConfig := config.(*v1alpha2.GRETunnel)
		writeIP(tunnelConfig.RemoteIP)
		if tunnelConfig.Key != nil {
			writeUint32(uint32(*tunnelConfig.Key))
		}

	case *v1alpha2.ERSPANTunnel:
		tunnelConfig := config.(*v1alpha2.ERSPANTunnel)
		version := tunnelConfig.Version
		writeIP(tunnelConfig.RemoteIP)
		writeUint32(uint32(tunnelConfig.Version))
		var sessionID uint32
		if tunnelConfig.SessionID != nil {
			sessionID = uint32(*tunnelConfig.SessionID)
		}
		writeUint32(sessionID)
		if version == 1 {
			var index uint32
			if tunnelConfig.Index != nil {
				index = uint32(*tunnelConfig.Index)
			}
			writeUint32(index)
		} else if version == 2 {
			var dir, hardwareID uint32
			if tunnelConfig.Dir != nil {
				dir = uint32(*tunnelConfig.Dir)
			}
			if tunnelConfig.HardwareID != nil {
				hardwareID = uint32(*tunnelConfig.HardwareID)
			}
			writeUint32(dir)
			writeUint32(hardwareID)
		}
	}
	return fmt.Sprintf("%s-%s", portNamePrefix, hex.EncodeToString(hash.Sum(nil))[:6])
}

func ParseTrafficControlInterfaceConfig(portData *ovsconfig.OVSPortData, portConfig *interfacestore.OVSPortConfig) *interfacestore.InterfaceConfig {
	intf := &interfacestore.InterfaceConfig{
		Type:          interfacestore.TrafficControlInterface,
		InterfaceName: portData.Name,
		OVSPortConfig: portConfig}
	if portData.IFType != "" {
		remoteIP, _, dstPort, _, _, extraOptions := ovsconfig.ParseTunnelInterfaceOptions(portData)
		tunnelConfig := &interfacestore.TunnelInterfaceConfig{Type: ovsconfig.TunnelType(portData.IFType), RemoteIP: remoteIP, DestinationPort: dstPort, ExtraOptions: extraOptions}
		intf.TunnelInterfaceConfig = tunnelConfig
	}
	return intf
}

func setOVSInternalLinkUp(portName string) error {
	// Host link might not be queried at once after creating OVS internal port; retry max 5 times with 1s
	// delay each time to ensure the link is ready.
	var err error
	for retry := 0; retry < maxRetryForHostLink; retry++ {
		//_, _, err := util.SetLinkUp(portName)
		if err == nil {
			break
		}
		if _, ok := err.(util.LinkNotFound); ok {
			klog.V(2).Infof("Not found host link for interface %s, retry after 1s", portName)
			time.Sleep(1 * time.Second)
			continue
		}
		return err
	}

	if err != nil {
		klog.Errorf("Failed to find host link for interface %s: %v", portName, err)
		return err
	}
	return nil
}

func (c *Controller) createTrafficControlPort(port *v1alpha2.TrafficControlPort) (uint32, error) {
	externalIDs := map[string]interface{}{
		interfacestore.AntreaInterfaceTypeKey: interfacestore.AntreaTrafficControl,
	}

	var portName, portUUID string
	var err ovsconfig.Error
	var isTunnel bool
	var tunnelType string
	var remoteIP string
	var dstPort int32
	var extraOptions map[string]interface{}
	switch {
	case port.OVSInternal != nil:
		portName = port.OVSInternal.Name
		portUUID, err = c.ovsBridgeClient.CreateInternalPort(portName, 0, externalIDs)
		if err == nil {
			if err := setOVSInternalLinkUp(portName); err != nil {
				return 0, err
			}
		}

	case port.Device != nil:
		portName = port.Device.Name
		portUUID, err = c.ovsBridgeClient.CreatePort(portName, portName, externalIDs)

	case port.VXLAN != nil:
		isTunnel = true
		tunnelType = ovsconfig.VXLANTunnel
		tunnelConfig := port.VXLAN.DeepCopy()
		remoteIP = tunnelConfig.RemoteIP
		dstPort = defaultVXLANTunnelDestinationPort
		dstPortStr := ""
		if tunnelConfig.DestinationPort != nil && *tunnelConfig.DestinationPort != defaultVXLANTunnelDestinationPort {
			dstPort = *tunnelConfig.DestinationPort
			// If field DestinationPort is not nil and its value is not the default VXLAN port, that value must be passed to
			// the OVS method CreateTunnelPortExt to build VXLAN tunnel.
			dstPortStr = strconv.Itoa(int(dstPort))
		} else if tunnelConfig.DestinationPort == nil {
			tunnelConfig.DestinationPort = &dstPort
		}
		if tunnelConfig.VNI != nil && *tunnelConfig.VNI != 0 {
			// If the VNI is not 0, that VNI should be passed to the OVS method CreateTunnelPortExt to build VXLAN tunnel.
			extraOptions = map[string]interface{}{"key": strconv.Itoa(int(*tunnelConfig.VNI))}
		}
		portName = genTunnelPortName(portNamePrefixVXLAN, tunnelConfig)
		portUUID, err = c.ovsBridgeClient.CreateTunnelPortExt(portName,
			ovsconfig.TunnelType(tunnelType),
			0,
			false,
			"",
			remoteIP,
			dstPortStr,
			"",
			extraOptions,
			externalIDs)

	case port.GENEVE != nil:
		isTunnel = true
		tunnelType = ovsconfig.GeneveTunnel
		tunnelConfig := port.GENEVE.DeepCopy()
		remoteIP = tunnelConfig.RemoteIP
		dstPort = defaultGENEVETunnelDestinationPort
		dstPortStr := ""
		if tunnelConfig.DestinationPort != nil && *tunnelConfig.DestinationPort != defaultGENEVETunnelDestinationPort {
			dstPort = *tunnelConfig.DestinationPort
			// If field DestinationPort is not nil and its value is not the default GENEVE port, that value must be passed to
			// the OVS method CreateTunnelPortExt to build GENEVE tunnel.
			dstPortStr = strconv.Itoa(int(dstPort))
		} else if tunnelConfig.DestinationPort == nil {
			tunnelConfig.DestinationPort = &dstPort
		}
		if tunnelConfig.VNI != nil && *tunnelConfig.VNI != 0 {
			// If the VNI is not 0, that VNI should be passed to the OVS method CreateTunnelPortExt to build GENEVE tunnel.
			extraOptions = map[string]interface{}{"key": strconv.Itoa(int(*tunnelConfig.VNI))}
		}
		portName = genTunnelPortName(portNamePrefixGENEVE, tunnelConfig)
		portUUID, err = c.ovsBridgeClient.CreateTunnelPortExt(portName,
			ovsconfig.TunnelType(tunnelType),
			0,
			false,
			"",
			remoteIP,
			dstPortStr,
			"",
			extraOptions,
			externalIDs)

	case port.GRE != nil:
		isTunnel = true
		tunnelType = ovsconfig.GRETunnel
		tunnelConfig := port.GRE
		remoteIP = tunnelConfig.RemoteIP
		portName = genTunnelPortName(portNamePrefixGRE, tunnelConfig)
		if tunnelConfig.Key != nil {
			extraOptions = map[string]interface{}{"key": strconv.Itoa(int(*tunnelConfig.Key))}
		}
		portUUID, err = c.ovsBridgeClient.CreateTunnelPortExt(portName,
			ovsconfig.TunnelType(tunnelType),
			0,
			false,
			"",
			remoteIP,
			"",
			"",
			extraOptions,
			externalIDs)

	case port.ERSPAN != nil:
		isTunnel = true
		tunnelType = ovsconfig.ERSPANTunnel
		tunnelConfig := port.ERSPAN
		remoteIP = tunnelConfig.RemoteIP
		version := tunnelConfig.Version
		portName = genTunnelPortName(portNamePrefixERSPAN, tunnelConfig)
		extraOptions = make(map[string]interface{})
		extraOptions["erspan_ver"] = strconv.Itoa(int(version))
		if tunnelConfig.SessionID != nil && *tunnelConfig.SessionID != 0 {
			extraOptions["key"] = strconv.Itoa(int(*tunnelConfig.SessionID))
		}
		if version == 1 {
			if tunnelConfig.Index != nil && *tunnelConfig.Index != 0 {
				extraOptions["erspan_idx"] = strconv.FormatInt(int64(*tunnelConfig.Index), 16)
			}
		} else if version == 2 {
			if tunnelConfig.Dir != nil && *tunnelConfig.Dir != 0 {
				extraOptions["erspan_dir"] = strconv.Itoa(int(*tunnelConfig.Dir))
			}
			if tunnelConfig.HardwareID != nil && *tunnelConfig.HardwareID != 0 {
				extraOptions["erspan_hwid"] = strconv.Itoa(int(*tunnelConfig.HardwareID))
			}
		}
		portUUID, err = c.ovsBridgeClient.CreateTunnelPortExt(portName,
			ovsconfig.TunnelType(tunnelType),
			0,
			false,
			"",
			remoteIP,
			"",
			"",
			extraOptions,
			externalIDs)
	}

	if err != nil {
		return 0, err
	}

	ofPort, err := c.ovsBridgeClient.GetOFPort(portName, false)
	if err != nil {
		return 0, err
	}

	itf := interfacestore.NewTrafficControlInterface(portName, isTunnel, ovsconfig.TunnelType(tunnelType), net.ParseIP(remoteIP), dstPort, extraOptions)
	itf.OVSPortConfig = &interfacestore.OVSPortConfig{PortUUID: portUUID, OFPort: ofPort}
	c.interfaceStore.AddInterface(itf)

	return uint32(ofPort), nil
}

func (c *Controller) getTrafficControlPort(port *v1alpha2.TrafficControlPort) (uint32, bool) {
	var portName string
	var defaultPort, defaultVNI int32
	switch {
	case port.OVSInternal != nil:
		portName = port.OVSInternal.Name
	case port.Device != nil:
		portName = port.Device.Name
	case port.VXLAN != nil:
		tunnelConfig := port.VXLAN.DeepCopy()
		if tunnelConfig.DestinationPort == nil {
			defaultPort = defaultVXLANTunnelDestinationPort
			tunnelConfig.DestinationPort = &defaultPort
		}
		if tunnelConfig.VNI == nil {
			tunnelConfig.VNI = &defaultVNI
		}
		portName = genTunnelPortName(portNamePrefixVXLAN, tunnelConfig)
	case port.GENEVE != nil:
		tunnelConfig := port.GENEVE.DeepCopy()
		if tunnelConfig.DestinationPort == nil {
			defaultPort = defaultGENEVETunnelDestinationPort
			tunnelConfig.DestinationPort = &defaultPort
		}
		if tunnelConfig.VNI == nil {
			tunnelConfig.VNI = &defaultVNI
		}
		portName = genTunnelPortName(portNamePrefixGENEVE, tunnelConfig)
	case port.GRE != nil:
		portName = genTunnelPortName(portNamePrefixGRE, port.GRE)
	case port.ERSPAN != nil:
		portName = genTunnelPortName(portNamePrefixERSPAN, port.ERSPAN)
	}
	if itf, ok := c.interfaceStore.GetInterfaceByName(portName); ok {
		return uint32(itf.OFPort), true
	}
	return 0, false
}

func (c *Controller) deleteTrafficControlPort(port uint32) error {
	if itf, ok := c.interfaceStore.GetInterfaceByOFPort(port); ok {
		if err := c.ovsBridgeClient.DeletePort(itf.PortUUID); err != nil {
			return err
		}
		c.interfaceStore.DeleteInterface(itf)
	}
	return nil
}

func (c *Controller) syncTrafficControl(tcName string) error {
	startTime := time.Now()
	defer func() {
		klog.V(2).InfoS("Finished syncing TrafficControl", "TrafficControl", tcName, "durationTime", time.Since(startTime))
	}()

	var tcUpdated, tcDeleted bool
	var returnPort, targetPort uint32
	var tc *v1alpha2.TrafficControl
	var tcState trafficControlState

	syncFn := func() error {
		// This anonymous function should be protected by a mutex lock. There are operations of adding or delete OVS
		// port in this function, and the operations should be mutual exclusion between multiple workers. In addition,
		// the field of targetPort and returnPort in trafficControlState stored in installedTrafficControls should be
		// also updated, otherwise the stale trafficControlStates may provide unexpected results. For example,
		//  - Update the return port of TrafficControl tc1 from port1 to port2.
		//  - Assuming that port1 is no longer used by any other TrafficControls, then corresponding flow is uninstalled
		//    and the port is deleted in current worker goroutine.
		//  - Without updating the state of TrafficControl tc1 in installedTrafficControls, when syncing another TrafficControl
		//    tc2 using return port port1 in another worker goroutine, the worker function queries the installedTrafficControls
		//    with indices returnPortIndexName. The result of the query shows that port1 is still used by TrafficControl
		//    tc1, then the return port will not be created and corresponding flow will not be uninstalled in that worker
		//    goroutine.
		c.ovsPortUpdateMutex.Lock()
		defer c.ovsPortUpdateMutex.Unlock()

		var err error
		var exists bool

		tc, err = c.trafficControlLister.Get(tcName)
		if err != nil {
			if apierrors.IsNotFound(err) {
				// If the TrafficControl is deleted and the corresponding state doesn't exist, just return.
				tcState, exists = c.getTrafficControlState(tcName)
				if !exists {
					return nil
				}
				// If a TrafficControl is deleted but the corresponding state exists, do some cleanup for the deleted
				// TrafficControl.
				if err = c.uninstallTrafficControl(&tcState); err != nil {
					return err
				}
				// Delete the state of the TrafficControl to be deleted.
				c.installedTrafficControls.Delete(tcState)
				tcDeleted = true
				return nil
			}
			return err
		}

		// Get the state of the TrafficControl.
		tcState, exists = c.getTrafficControlState(tcName)
		// If the TrafficControl exists and corresponding state doesn't exist, create state for the TrafficControl.
		if !exists {
			tcState = c.newTrafficControlState(tcName, tc.Spec.Action, tc.Spec.Direction)
		}

		if tc.Spec.ReturnPort != nil {
			returnPort, exists = c.getTrafficControlPort(tc.Spec.ReturnPort)
			// If the return port doesn't exist, create it.
			if !exists {
				if returnPort, err = c.createTrafficControlPort(tc.Spec.ReturnPort); err != nil {
					return err
				}
			}
			shouldInstallReturnFlow := func() bool {
				tcs, _ := c.installedTrafficControls.ByIndex(returnPortIndexName, strconv.Itoa(int(returnPort)))
				return len(tcs) == 0
			}
			// There are two situations that the return flow should be installed for the return port:
			// - The return port is newly created.
			// - The return port is not newly created (using existing port as return port) and not used by any TrafficControl.
			if !exists || shouldInstallReturnFlow() {
				if err = c.ofClient.InstallTrafficControlReturnPortFlow(returnPort); err != nil {
					return err
				}
			}
			// The return port of the TrafficControl is updated.
			if tcState.returnPort != 0 && returnPort != tcState.returnPort {
				shouldDeleteFlows, shouldDeletePort := c.shouldDeleteFlowsAndPort(tcName, returnPortIndexName, tcState.returnPort)
				// If the stale return port is on longer used by any other TrafficControls, uninstall the return flow for
				// the port.
				if shouldDeleteFlows {
					if err = c.ofClient.UninstallTrafficControlReturnPortFlow(tcState.returnPort); err != nil {
						return err
					}
					// If the stale return port is created by TrafficControl controller, delete the port.
					if shouldDeletePort {
						if err = c.deleteTrafficControlPort(tcState.returnPort); err != nil {
							return err
						}
					}
				}
				tcUpdated = true
			}
		}

		targetPort, exists = c.getTrafficControlPort(&tc.Spec.TargetPort)
		// If the target port doesn't exist, create it.
		if !exists {
			if targetPort, err = c.createTrafficControlPort(&tc.Spec.TargetPort); err != nil {
				return err
			}
		}
		// The target port of the TrafficControl is updated.
		if tcState.targetPort != 0 && targetPort != tcState.targetPort {
			_, shouldDeletePort := c.shouldDeleteFlowsAndPort(tcName, targetPortIndexName, tcState.targetPort)
			// If the stale target port is no longer used by any other TrafficControls, delete the port.
			if shouldDeletePort {
				if err = c.deleteTrafficControlPort(tcState.targetPort); err != nil {
					return err
				}
			}
			tcUpdated = true
		}

		// Update the TrafficControl state and store it to installedTrafficControls.
		tcState.targetPort = targetPort
		tcState.returnPort = returnPort
		c.installedTrafficControls.Update(tcState)

		return nil
	}

	if err := syncFn(); err != nil {
		return err
	}
	// If the TrafficControl is deleted, just return.
	if tcDeleted {
		return nil
	}

	// Update the state of the TrafficControl, these two fields are only relevant to the current worker goroutine.
	if tcState.action != tc.Spec.Action {
		tcState.action = tc.Spec.Action
		tcUpdated = true
	}
	if tcState.direction != tc.Spec.Direction {
		tcState.direction = tc.Spec.Direction
		tcUpdated = true
	}

	// Get the list of Pods applying to the TrafficControl.
	var podObjects []*v1.Pod
	var err error
	if podObjects, err = c.filterPods(&tc.Spec.AppliedTo); err != nil {
		return err
	}

	// Reserve the set of Pods in TrafficControl state as stale, and reinitialize the set in TrafficControl state.
	stalePods := tcState.pods
	tcState.pods = sets.NewString()
	// Reserve the set of OF ports in TrafficControl state as old, and reinitialize the set in TrafficControl state.
	oldOfPorts := tcState.ofPorts
	tcState.ofPorts = sets.NewInt32()
	// Iterate the list of Pods applying to the TrafficControl.
	for _, pod := range podObjects {
		podNN := k8s.NamespacedName(pod.Namespace, pod.Name)
		// Insert the Pod to the reinitialized set in TrafficControl state and remove the Pod from the stale set.
		tcState.pods.Insert(podNN)
		stalePods.Delete(podNN)

		// If the TrafficControl is not the effective TrafficControl for the Pod, do nothing.
		if !c.bindPodToTrafficControl(podNN, tcName) {
			continue
		}

		// If the TrafficControl is the effective TrafficControl for the Pod, insert the port to the new set in
		// TrafficControl state.
		podInterfaces := c.interfaceStore.GetContainerInterfacesByPod(pod.Name, pod.Namespace)
		if len(podInterfaces) == 0 {
			klog.InfoS("Interfaces of Pod not found", "Pod", klog.KObj(pod))
			continue
		}
		tcState.ofPorts.Insert(podInterfaces[0].OFPort)
	}

	// If the target port, direction and action of the TrafficControl is updated, the mark flows should be reinstalled.
	// If the newly generated ofPort set is different from the stale ofPort set, the flows should be reinstalled, the mark
	// flows should be also reinstalled.
	if tcUpdated || len(utilsets.SymmetricDifferenceInt32(tcState.ofPorts, oldOfPorts)) != 0 {
		var ofPorts []uint32
		for _, port := range tcState.ofPorts.List() {
			ofPorts = append(ofPorts, uint32(port))
		}
		if err = c.ofClient.InstallTrafficControlMarkFlows(tc.Name, ofPorts, targetPort, tc.Spec.Direction, tc.Spec.Action); err != nil {
			return err
		}
	}
	if len(stalePods) != 0 {
		// Resync the Pods applying to the TrafficControl to be deleted.
		c.podsResync(stalePods, tcName)
	}

	c.installedTrafficControls.Update(tcState)

	return nil
}

func (c *Controller) uninstallTrafficControl(tcState *trafficControlState) error {
	tcName := tcState.name
	var shouldDeleteFlows, shouldDeletePort bool

	// Uninstall the mark flows of the TrafficControl.
	if err := c.ofClient.UninstallTrafficControlMarkFlows(tcName); err != nil {
		return err
	}
	// If the target port is no longer used by any other TrafficControls and was created by TrafficControl controller,
	// delete the target port.
	_, shouldDeletePort = c.shouldDeleteFlowsAndPort(tcName, targetPortIndexName, tcState.targetPort)
	if shouldDeletePort {
		if err := c.deleteTrafficControlPort(tcState.targetPort); err != nil {
			return err
		}
	}

	if tcState.returnPort != 0 {
		shouldDeleteFlows, shouldDeletePort = c.shouldDeleteFlowsAndPort(tcName, returnPortIndexName, tcState.returnPort)
		if shouldDeleteFlows {
			// If the return port is no longer used by any other TrafficControls, uninstall the return flow for the return
			// port. Note that, the return flow for the return port was installed when it was used by a TrafficControl
			// firstly.
			if err := c.ofClient.UninstallTrafficControlReturnPortFlow(tcState.returnPort); err != nil {
				return err
			}
			// If the return port is created by TrafficControl controller, delete the return port.
			if shouldDeletePort {
				if err := c.deleteTrafficControlPort(tcState.returnPort); err != nil {
					return err
				}
			}
		}
	}
	// Resync the Pods applying to the TrafficControl to be deleted.
	if len(tcState.pods) != 0 {
		c.podsResync(tcState.pods, tcName)
	}
	return nil
}

func (c *Controller) podsResync(pods sets.String, tcName string) {
	// Resync the Pods that have new effective TrafficControl.
	newEffectiveTCs := sets.NewString()
	for pod := range pods {
		newEffectiveTC, exists := c.unbindPodFromTrafficControl(pod, tcName)
		if exists {
			newEffectiveTCs.Insert(newEffectiveTC)
		}
	}
	// Trigger resyncing of the new effective TrafficControls of the Pods.
	for tc := range newEffectiveTCs {
		c.queue.Add(tc)
	}
}

func (c *Controller) shouldDeleteFlowsAndPort(tcName string, indexName string, port uint32) (bool, bool) {
	tcStates, _ := c.installedTrafficControls.ByIndex(indexName, strconv.Itoa(int(port)))
	var shouldDeleteFlows, shouldDeletePort bool
	// If the port is only used by the TrafficControl to be deleted, its related flows should be uninstalled.
	if len(tcStates) == 1 && tcStates[0].(trafficControlState).name == tcName {
		shouldDeleteFlows = true
		// If the port is created by TrafficControl controller, then it should be deleted.
		itf, _ := c.interfaceStore.GetInterfaceByOFPort(port)
		if itf.Type == interfacestore.TrafficControlInterface {
			shouldDeletePort = true
		}
	}
	return shouldDeleteFlows, shouldDeletePort
}

// bindPodToTrafficControl binds the Pod with the TrafficControl and returns whether this TrafficControl is the effective
// one for the Pod.
func (c *Controller) bindPodToTrafficControl(pod, tc string) bool {
	c.podToTCBindingsMutex.Lock()
	defer c.podToTCBindingsMutex.Unlock()

	binding, exists := c.podToTCBindings[pod]
	if !exists {
		// Promote itself as the effective TrafficControl if there was not one.
		c.podToTCBindings[pod] = &podToTCBinding{
			effectiveTC:    tc,
			alternativeTCs: sets.NewString(),
		}
		return true
	}
	if binding.effectiveTC == tc {
		return true
	}
	if !binding.alternativeTCs.Has(tc) {
		binding.alternativeTCs.Insert(tc)
	}
	return false
}

// unbindPodFromTrafficControl unbinds the Pod with the TrafficControl. If the unbound TrafficControl was the effective
// one for the Pod and there are any alternative ones, it will return the new effective TrafficControl and true, otherwise
// it returns empty string and false.
func (c *Controller) unbindPodFromTrafficControl(pod, tc string) (string, bool) {
	c.podToTCBindingsMutex.Lock()
	defer c.podToTCBindingsMutex.Unlock()

	// The binding must exist.
	binding := c.podToTCBindings[pod]
	if binding.effectiveTC == tc {
		var popped bool
		binding.effectiveTC, popped = binding.alternativeTCs.PopAny()
		if !popped {
			// Remove the Pod's binding if there is no alternative.
			delete(c.podToTCBindings, pod)
			return "", false
		}
		return binding.effectiveTC, true
	}
	binding.alternativeTCs.Delete(tc)
	return "", false
}
