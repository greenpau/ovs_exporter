// Copyright 2018 Paul Greenberg (greenpau@outlook.com)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ovs_exporter

import (
	"fmt"
	_ "net/http/pprof"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/greenpau/ovsdb"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/version"
)

const (
	namespace = "ovs"
)

var (
	appName    = "ovs-exporter"
	appVersion = "[untracked]"
	gitBranch  string
	gitCommit  string
	buildUser  string // whoami
	buildDate  string // date -u
)

var (
	up = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "up"),
		"Is OVN stack up (1) or is it down (0).",
		nil, nil,
	)
	info = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "info"),
		"This metric provides basic information about OVN stack. It is always set to 1.",
		[]string{
			"system_id",
			"rundir",
			"hostname",
			"system_type",
			"system_version",
			"ovs_version",
			"db_version",
		}, nil,
	)
	requestErrors = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "failed_req_count"),
		"The number of failed requests to OVN stack.",
		[]string{"system_id"}, nil,
	)
	nextPoll = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "next_poll"),
		"The timestamp of the next potential poll of OVN stack.",
		[]string{"system_id"}, nil,
	)
	pid = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "pid"),
		"The process ID of a running OVN component. If the component is not running, then the ID is 0.",
		[]string{"system_id", "component", "user", "group"}, nil,
	)
	logFileSize = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "log_file_size"),
		"The size of a log file associated with an OVN component.",
		[]string{"system_id", "component", "filename"}, nil,
	)
	logEventStat = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "log_event_count"),
		"The number of recorded log meessage associated with an OVN component by log severity level and source.",
		[]string{"system_id", "component", "severity", "source"}, nil,
	)
	dbFileSize = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "db_file_size"),
		"The size of a database file associated with an OVN component.",
		[]string{"system_id", "component", "filename"}, nil,
	)
	networkPortUp = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "network_port"),
		"The TCP port used for database connection. If the value is 0, then the port is not in use.",
		[]string{"system_id", "component", "usage"}, nil,
	)
	// OVS Coverage and Memory
	covAvg = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "coverage_avg"),
		"The average rate of the number of times particular events occur during a OVSDB daemon's runtime.",
		[]string{"system_id", "component", "event", "interval"}, nil,
	)
	covTotal = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "coverage_total"),
		"The total number of times particular events occur during a OVSDB daemon's runtime.",
		[]string{"system_id", "component", "event"}, nil,
	)
	memUsage = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "memory_usage"),
		"The memory usage.",
		[]string{"system_id", "component", "facility"}, nil,
	)
	// OVS Datapath
	dpInterface = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dp_if"),
		"Represents an existing datapath interface. This metrics is always 1.",
		[]string{"system_id", "datapath", "bridge", "name", "ofport", "index", "port_type"}, nil,
	)
	dpBridgeInterfaceTotal = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dp_br_if_total"),
		"The total number of interfaces attached to a bridge.",
		[]string{"system_id", "datapath", "bridge"}, nil,
	)
	dpFlowsTotal = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dp_flows"),
		"The number of flows in a datapath.",
		[]string{"system_id", "datapath"}, nil,
	)
	// OVS Datapath: Lookups
	dpLookupsHit = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dp_lookups_hit"),
		"The number of incoming packets in a datapath matching existing flows in the datapath.",
		[]string{"system_id", "datapath"}, nil,
	)
	dpLookupsMissed = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dp_lookups_missed"),
		"The number of incoming packets in a datapath not matching any existing flow in the datapath.",
		[]string{"system_id", "datapath"}, nil,
	)
	dpLookupsLost = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dp_lookups_lost"),
		"Returns the number of incoming packets in a datapath destined for userspace process but subsequently dropped before reaching userspace.",
		[]string{"system_id", "datapath"}, nil,
	)
	// OVS Datapath: Masks
	dpMasksHit = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dp_masks_hit"),
		"The total number of masks visited for matching incoming packets.",
		[]string{"system_id", "datapath"}, nil,
	)
	dpMasksTotal = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dp_masks_total"),
		"The number of masks in a datapath.",
		[]string{"system_id", "datapath"}, nil,
	)
	dpMasksHitRatio = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dp_masks_hit_ratio"),
		"The average number of masks visited per packet. It is the ration between hit and total number of packets processed by a datapath.",
		[]string{"system_id", "datapath"}, nil,
	)
	// OVS Interface
	// Reference: http://www.openvswitch.org/support/dist-docs/ovs-vswitchd.conf.db.5.html
	interfaceMain = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "interface"),
		"Represents OVS interface. This is the primary metric for all other interface metrics. This metrics is always 1.",
		[]string{"system_id", "uuid", "name"}, nil,
	)
	interfaceAdminState = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "interface_admin_state"),
		"The administrative state of the physical network link of OVS interface. The values are: down(0), up(1), other(2).",
		[]string{"system_id", "uuid"}, nil,
	)
	interfaceLinkState = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "interface_link_state"),
		"The  observed  state of the physical network link of OVS interface. The values are: down(0), up(1), other(2).",
		[]string{"system_id", "uuid"}, nil,
	)
	interfaceIngressPolicingBurst = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "interface_ingress_policing_burst"),
		"Maximum burst size for data received on OVS interface, in kb. The default burst size if set to 0 is 8000 kbit.",
		[]string{"system_id", "uuid"}, nil,
	)
	interfaceIngressPolicingRate = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "interface_ingress_policing_rate"),
		"Maximum rate for data received on OVS interface, in kbps. If the value is 0, then policing is disabled.",
		[]string{"system_id", "uuid"}, nil,
	)
	interfaceMacInUse = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "interface_mac_in_use"),
		"The MAC address in use by OVS interface.",
		[]string{"system_id", "uuid", "mac_address"}, nil,
	)
	interfaceMtu = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "interface_mtu"),
		"The currently configured MTU for OVS interface.",
		[]string{"system_id", "uuid"}, nil,
	)
	interfaceDuplex = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "interface_duplex"),
		"The duplex mode of the physical network link of OVS interface. The values are: other(0), half(1), full(2).",
		[]string{"system_id", "uuid"}, nil,
	)
	interfaceOfPort = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "interface_of_port"),
		"Represents the OpenFlow port ID associated with OVS interface.",
		[]string{"system_id", "uuid"}, nil,
	)
	interfaceIfIndex = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "interface_if_index"),
		"Represents the interface index associated with OVS interface.",
		[]string{"system_id", "uuid"}, nil,
	)
	interfaceLocalIndex = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "interface_local_index"),
		"Represents the local index associated with OVS interface.",
		[]string{"system_id", "uuid"}, nil,
	)
	// OVS Interface Statistics: Receive errors
	// See http://www.openvswitch.org/support/dist-docs/ovs-vswitchd.conf.db.5.html
	interfaceStatRxCrcError = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "interface_rx_crc_err"),
		"Represents the number of CRC errors for the packets received by OVS interface.",
		[]string{"system_id", "uuid"}, nil,
	)
	interfaceStatRxDropped = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "interface_rx_dropped"),
		"Represents the number of input packets dropped by OVS interface.",
		[]string{"system_id", "uuid"}, nil,
	)
	interfaceStatRxFrameError = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "interface_rx_frame_err"),
		"Represents the number of frame alignment errors on the packets received by OVS interface.",
		[]string{"system_id", "uuid"}, nil,
	)
	interfaceStatRxOverrunError = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "interface_rx_over_err"),
		"Represents the number of packets with RX overrun received by OVS interface.",
		[]string{"system_id", "uuid"}, nil,
	)
	interfaceStatRxErrorsTotal = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "interface_rx_errors"),
		"Represents the total number of packets with errors received by OVS interface.",
		[]string{"system_id", "uuid"}, nil,
	)
	interfaceStatRxMissedErrors = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "interface_rx_missed_errors"),
		"Represents the number of missed packets received by OVS interface.",
		[]string{"system_id", "uuid"}, nil,
	)
	// OVS Interface Statistics: Successful transmit and receive counters
	interfaceStatRxPackets = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "interface_rx_packets"),
		"Represents the number of received packets by OVS interface.",
		[]string{"system_id", "uuid"}, nil,
	)
	interfaceStatRxBytes = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "interface_rx_bytes"),
		"Represents the number of received bytes by OVS interface.",
		[]string{"system_id", "uuid"}, nil,
	)
	interfaceStatTxPackets = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "interface_tx_packets"),
		"Represents the number of transmitted packets by OVS interface.",
		[]string{"system_id", "uuid"}, nil,
	)
	interfaceStatTxBytes = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "interface_tx_bytes"),
		"Represents the number of transmitted bytes by OVS interface.",
		[]string{"system_id", "uuid"}, nil,
	)
	// OVS Interface Statistics: Transmit errors
	interfaceStatTxDropped = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "interface_tx_dropped"),
		"Represents the number of output packets dropped by OVS interface.",
		[]string{"system_id", "uuid"}, nil,
	)
	interfaceStatTxErrorsTotal = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "interface_tx_errors"),
		"Represents the total number of transmit errors by OVS interface.",
		[]string{"system_id", "uuid"}, nil,
	)
	interfaceStatCollisions = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "interface_collisions"),
		"Represents the number of collisions on OVS interface.",
		[]string{"system_id", "uuid"}, nil,
	)
	// OVS Link attributes, e.g. speed, resets, etc.
	interfaceLinkResets = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "interface_link_resets"),
		"The number of times Open vSwitch has observed the link_state of OVS interface change.",
		[]string{"system_id", "uuid"}, nil,
	)
	interfaceLinkSpeed = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "interface_link_speed"),
		"The negotiated speed of the physical network link of OVS interface.",
		[]string{"system_id", "uuid"}, nil,
	)
	// Interface Status, Options, and External IDs Key-Value Pairs
	interfaceStatusKeyValuePair = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "interface_status"),
		"Key-value pair that report port status of OVS interface.",
		[]string{"system_id", "uuid", "key", "value"}, nil,
	)
	interfaceOptionsKeyValuePair = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "interface_options"),
		"Key-value pair that report options of OVS interface.",
		[]string{"system_id", "uuid", "key", "value"}, nil,
	)
	interfaceExternalIdKeyValuePair = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "interface_external_ids"),
		"Key-value pair that report external IDs of OVS interface.",
		[]string{"system_id", "uuid", "key", "value"}, nil,
	)
)

// Exporter collects OVN data from the given server and exports them using
// the prometheus metrics package.
type Exporter struct {
	sync.RWMutex
	Client               *ovsdb.OvsClient
	timeout              int
	pollInterval         int64
	errors               int64
	errorsLocker         sync.RWMutex
	nextCollectionTicker int64
	metrics              []prometheus.Metric
	logger               log.Logger
}

type Options struct {
	Timeout int
	Logger log.Logger
}

// NewLogger returns an instance of logger.
func NewLogger(logLevel string) (log.Logger, error) {
	allowedLogLevel := &promlog.AllowedLevel{}
	if err := allowedLogLevel.Set(logLevel); err != nil {
		return nil, err
	}
	promlogConfig := &promlog.Config{
		Level: allowedLogLevel,
	}
	logger := promlog.New(promlogConfig)
	return logger, nil
}

// NewExporter returns an initialized Exporter.
func NewExporter(opts Options) (*Exporter, error) {
	version.Version = appVersion
	version.Revision = gitCommit
	version.Branch = gitBranch
	version.BuildUser = buildUser
	version.BuildDate = buildDate
	e := Exporter{
		timeout: opts.Timeout,
	}
	client := ovsdb.NewOvsClient()
	client.Timeout = opts.Timeout
	e.Client = client
	e.Client.GetSystemID()
	e.logger = opts.Logger

	level.Debug(e.logger).Log(
		"msg", "NewExporter() calls Connect()",
		"system_id", e.Client.System.ID,
	)

	if err := client.Connect(); err != nil {
		return &e, err
	}

	level.Debug(e.logger).Log(
		"msg", "NewExporter() calls GetSystemInfo()",
		"system_id", e.Client.System.ID,
	)

	if err := e.Client.GetSystemInfo(); err != nil {
		return &e, err
	}

	level.Debug(e.logger).Log(
		"msg", "NewExporter() initialized successfully",
		"system_id", e.Client.System.ID,
	)

	return &e, nil
}

// Describe describes all the metrics ever exported by the OVN exporter. It
// implements prometheus.Collector.
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- up
	ch <- info
	ch <- requestErrors
	ch <- nextPoll
	ch <- pid
	ch <- logFileSize
	ch <- dbFileSize
	ch <- logEventStat
	ch <- networkPortUp
	ch <- covAvg
	ch <- covTotal
	ch <- memUsage
	ch <- dpInterface
	ch <- dpBridgeInterfaceTotal
	ch <- dpLookupsHit
	ch <- dpFlowsTotal
	ch <- dpLookupsMissed
	ch <- dpMasksHit
	ch <- dpMasksTotal
	ch <- dpMasksHitRatio
	ch <- dpLookupsLost
	ch <- interfaceMain
	ch <- interfaceAdminState
	ch <- interfaceLinkState
	ch <- interfaceIngressPolicingBurst
	ch <- interfaceIngressPolicingRate
	ch <- interfaceMacInUse
	ch <- interfaceMtu
	ch <- interfaceDuplex
	ch <- interfaceOfPort
	ch <- interfaceIfIndex
	ch <- interfaceLocalIndex
	ch <- interfaceStatRxCrcError
	ch <- interfaceStatRxDropped
	ch <- interfaceStatRxFrameError
	ch <- interfaceStatRxOverrunError
	ch <- interfaceStatRxErrorsTotal
	ch <- interfaceStatRxMissedErrors
	ch <- interfaceStatRxPackets
	ch <- interfaceStatRxBytes
	ch <- interfaceStatTxPackets
	ch <- interfaceStatTxBytes
	ch <- interfaceStatTxDropped
	ch <- interfaceStatTxErrorsTotal
	ch <- interfaceStatCollisions
	ch <- interfaceLinkResets
	ch <- interfaceLinkSpeed
	ch <- interfaceStatusKeyValuePair
	ch <- interfaceOptionsKeyValuePair
	ch <- interfaceExternalIdKeyValuePair
}

// IncrementErrorCounter increases the counter of failed queries
// to OVN server.
func (e *Exporter) IncrementErrorCounter() {
	e.errorsLocker.Lock()
	defer e.errorsLocker.Unlock()
	atomic.AddInt64(&e.errors, 1)
}

// Collect implements prometheus.Collector.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	e.GatherMetrics()

	level.Debug(e.logger).Log(
		"msg", "Collect() calls RLock()",
		"system_id", e.Client.System.ID,
	)

	e.RLock()
	defer e.RUnlock()
	if len(e.metrics) == 0 {
		level.Debug(e.logger).Log(
			"msg", "Collect() no metrics found",
			"system_id", e.Client.System.ID,
		)

		ch <- prometheus.MustNewConstMetric(
			up,
			prometheus.GaugeValue,
			0,
		)
		ch <- prometheus.MustNewConstMetric(
			info,
			prometheus.GaugeValue,
			1,
			e.Client.System.ID, e.Client.System.RunDir, e.Client.System.Hostname,
			e.Client.System.Type, e.Client.System.Version,
			e.Client.Database.Vswitch.Version, e.Client.Database.Vswitch.Schema.Version,
		)
		ch <- prometheus.MustNewConstMetric(
			requestErrors,
			prometheus.CounterValue,
			float64(e.errors),
			e.Client.System.ID,
		)
		ch <- prometheus.MustNewConstMetric(
			nextPoll,
			prometheus.CounterValue,
			float64(e.nextCollectionTicker),
			e.Client.System.ID,
		)
		return
	}

	level.Debug(e.logger).Log(
		"msg", "Collect() sends metrics to a shared channel",
		"system_id", e.Client.System.ID,
		"metric_count", len(e.metrics),
	)

	for _, m := range e.metrics {
		ch <- m
	}
}

// GatherMetrics collect data from OVN server and stores them
// as Prometheus metrics.
func (e *Exporter) GatherMetrics() {
	level.Debug(e.logger).Log(
		"msg", "GatherMetrics() called",
		"system_id", e.Client.System.ID,
	)

	if time.Now().Unix() < e.nextCollectionTicker {
		return
	}
	e.Lock()
	level.Debug(e.logger).Log(
		"msg", "GatherMetrics() locked",
		"system_id", e.Client.System.ID,
	)
	defer e.Unlock()
	if len(e.metrics) > 0 {
		e.metrics = e.metrics[:0]
		level.Debug(e.logger).Log(
			"msg", "GatherMetrics() cleared metrics",
			"system_id", e.Client.System.ID,
		)
	}
	upValue := 1

	var err error

	err = e.Client.GetSystemInfo()
	if err != nil {
		level.Error(e.logger).Log(
			"msg", "GetSystemInfo() failed",
			"vswitch_name", e.Client.Database.Vswitch.Name,
			"system_id", e.Client.System.ID,
			"error", err.Error(),
		)
		e.IncrementErrorCounter()
		upValue = 0
	} else {
		level.Debug(e.logger).Log(
			"msg", "GetSystemInfo() successful",
			"vswitch_name", e.Client.Database.Vswitch.Name,
			"system_id", e.Client.System.ID,
		)
	}

	components := []string{
		"ovsdb-server",
		"ovs-vswitchd",
	}
	for _, component := range components {
		p, err := e.Client.GetProcessInfo(component)
		level.Debug(e.logger).Log(
			"msg", "GatherMetrics() calls GetProcessInfo()",
			"component", component,
			"system_id", e.Client.System.ID,
		)

		if err != nil {
			level.Error(e.logger).Log(
				"msg", "GetProcessInfo() failed",
				"component", component,
				"system_id", e.Client.System.ID,
				"error", err.Error(),
			)
			e.IncrementErrorCounter()
			upValue = 0
		}
		e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
			pid,
			prometheus.GaugeValue,
			float64(p.ID),
			e.Client.System.ID,
			component,
			p.User,
			p.Group,
		))
		level.Debug(e.logger).Log(
			"msg", "GatherMetrics() completed GetProcessInfo()",
			"component", component,
			"system_id", e.Client.System.ID,
		)
	}

	components = []string{
		"ovsdb-server",
		"ovs-vswitchd",
	}
	for _, component := range components {
		level.Debug(e.logger).Log(
			"msg", "GatherMetrics() calls GetLogFileInfo()",
			"component", component,
			"system_id", e.Client.System.ID,
		)

		file, err := e.Client.GetLogFileInfo(component)
		if err != nil {
			level.Error(e.logger).Log(
				"msg", "GetLogFileInfo() failed",
				"component", component,
				"system_id", e.Client.System.ID,
				"error", err.Error(),
			)
			e.IncrementErrorCounter()
			continue
		}
		level.Debug(e.logger).Log(
			"msg", "GatherMetrics() completed GetLogFileInfo()",
			"component", component,
			"system_id", e.Client.System.ID,
		)

		e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
			logFileSize,
			prometheus.GaugeValue,
			float64(file.Info.Size()),
			e.Client.System.ID,
			file.Component,
			file.Path,
		))

		level.Debug(e.logger).Log(
			"msg", "GatherMetrics() calls GetLogFileEventStats()",
			"component", component,
			"system_id", e.Client.System.ID,
		)

		eventStats, err := e.Client.GetLogFileEventStats(component)
		if err != nil {
			level.Error(e.logger).Log(
				"msg", "GetLogFileEventStats() failed",
				"component", component,
				"system_id", e.Client.System.ID,
				"error", err.Error(),
			)
			e.IncrementErrorCounter()
			continue
		}

		level.Debug(e.logger).Log(
			"msg", "GatherMetrics() completed GetLogFileEventStats()",
			"component", component,
			"system_id", e.Client.System.ID,
		)

		for sev, sources := range eventStats {
			for source, count := range sources {
				e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
					logEventStat,
					prometheus.GaugeValue,
					float64(count),
					e.Client.System.ID,
					component,
					sev,
					source,
				))
			}
		}
	}

	components = []string{
		"ovsdb-server",
		"vswitchd-service",
	}

	for _, component := range components {
		level.Debug(e.logger).Log(
			"msg", "GatherMetrics() calls AppListCommands()",
			"component", component,
			"system_id", e.Client.System.ID,
		)

		if cmds, err := e.Client.AppListCommands(component); err != nil {
			level.Error(e.logger).Log(
				"msg", "AppListCommands() failed",
				"component", component,
				"system_id", e.Client.System.ID,
				"error", err.Error(),
			)
			e.IncrementErrorCounter()
			level.Debug(e.logger).Log(
				"msg", "GatherMetrics() completed AppListCommands()",
				"component", component,
				"system_id", e.Client.System.ID,
			)
		} else {
			level.Debug(e.logger).Log(
				"msg", "GatherMetrics() completed AppListCommands()",
				"component", component,
				"system_id", e.Client.System.ID,
			)
			if cmds["coverage/show"] {
				level.Debug(e.logger).Log(
					"msg", "GatherMetrics() calls GetAppCoverageMetrics()",
					"component", component,
					"system_id", e.Client.System.ID,
				)

				if metrics, err := e.Client.GetAppCoverageMetrics(component); err != nil {
					level.Error(e.logger).Log(
						"msg", "GetAppCoverageMetrics() failed",
						"component", component,
						"system_id", e.Client.System.ID,
						"error", err.Error(),
					)
					e.IncrementErrorCounter()
				} else {
					for event, metric := range metrics {
						for period, value := range metric {
							if period == "total" {
								e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
									covTotal,
									prometheus.CounterValue,
									value,
									e.Client.System.ID,
									component,
									event,
								))
							} else {
								e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
									covAvg,
									prometheus.GaugeValue,
									value,
									e.Client.System.ID,
									component,
									event,
									period,
								))
							}
						}
					}
				}
				level.Debug(e.logger).Log(
					"msg", "GatherMetrics() completed GetAppCoverageMetrics()",
					"component", component,
					"system_id", e.Client.System.ID,
				)
			}
			if cmds["memory/show"] {
				level.Debug(e.logger).Log(
					"msg", "GatherMetrics() calls GetAppMemoryMetrics()",
					"component", component,
					"system_id", e.Client.System.ID,
				)
				if metrics, err := e.Client.GetAppMemoryMetrics(component); err != nil {
					level.Error(e.logger).Log(
						"msg", "GetAppMemoryMetrics() failed",
						"component", component,
						"system_id", e.Client.System.ID,
						"error", err.Error(),
					)
					e.IncrementErrorCounter()
				} else {
					for facility, value := range metrics {
						e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
							memUsage,
							prometheus.GaugeValue,
							value,
							e.Client.System.ID,
							component,
							facility,
						))
					}
				}
				level.Debug(e.logger).Log(
					"msg", "GatherMetrics() completed GetAppMemoryMetrics()",
					"component", component,
					"system_id", e.Client.System.ID,
				)
			}
			if cmds["dpif/show"] && (component == "vswitchd-service") {
				level.Debug(e.logger).Log(
					"msg", "GatherMetrics() calls GetAppDatapath()",
					"component", component,
					"system_id", e.Client.System.ID,
				)

				if dps, brs, intfs, err := e.Client.GetAppDatapath(component); err != nil {
					level.Error(e.logger).Log(
						"msg", "GetAppDatapath() failed",
						"component", component,
						"system_id", e.Client.System.ID,
						"error", err.Error(),
					)
					e.IncrementErrorCounter()
				} else {
					for _, dp := range dps {
						dpIntefaceCount := 0
						for _, br := range brs {
							if dp.Name != br.DatapathName {
								continue
							}
							brIntefaceCount := 0
							for _, intf := range intfs {
								if dp.Name != intf.DatapathName || br.Name != intf.BridgeName {
									continue
								}
								dpIntefaceCount += 1
								brIntefaceCount += 1
								e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
									dpInterface,
									prometheus.GaugeValue,
									1,
									e.Client.System.ID,
									dp.Name,
									br.Name,
									intf.Name,
									fmt.Sprintf("%0.f", intf.OfPort),
									fmt.Sprintf("%0.f", intf.Index),
									intf.Type,
								))
							}
							// Calculate the total number of interfaces per datapath
							e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
								dpBridgeInterfaceTotal,
								prometheus.GaugeValue,
								float64(brIntefaceCount),
								e.Client.System.ID,
								dp.Name,
								br.Name,
							))
						}
						// Add datapath hits and misses
						e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
							dpLookupsHit,
							prometheus.CounterValue,
							dp.Lookups.Hit,
							e.Client.System.ID,
							dp.Name,
						))
						e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
							dpLookupsMissed,
							prometheus.CounterValue,
							dp.Lookups.Missed,
							e.Client.System.ID,
							dp.Name,
						))
						e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
							dpLookupsLost,
							prometheus.CounterValue,
							dp.Lookups.Lost,
							e.Client.System.ID,
							dp.Name,
						))
						// Add datapath flows
						e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
							dpFlowsTotal,
							prometheus.GaugeValue,
							dp.Flows,
							e.Client.System.ID,
							dp.Name,
						))
						// Add datapath masks
						e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
							dpMasksHit,
							prometheus.CounterValue,
							dp.Masks.Hit,
							e.Client.System.ID,
							dp.Name,
						))
						e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
							dpMasksTotal,
							prometheus.CounterValue,
							dp.Masks.Total,
							e.Client.System.ID,
							dp.Name,
						))
						e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
							dpMasksHitRatio,
							prometheus.GaugeValue,
							dp.Masks.HitRatio,
							e.Client.System.ID,
							dp.Name,
						))
					}
				}
				level.Debug(e.logger).Log(
					"msg", "GatherMetrics() completed GetAppDatapath()",
					"component", component,
					"system_id", e.Client.System.ID,
				)
			}
		}
	}

	level.Debug(e.logger).Log(
		"msg", "GatherMetrics() calls GetDbInterfaces()",
		"system_id", e.Client.System.ID,
	)

	if intfs, err := e.Client.GetDbInterfaces(); err != nil {
		level.Error(e.logger).Log(
			"msg", "GetDbInterfaces() failed",
			"system_id", e.Client.System.ID,
			"error", err.Error(),
		)
		e.IncrementErrorCounter()
	} else {
		for _, intf := range intfs {
			e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
				interfaceMain,
				prometheus.GaugeValue,
				1,
				e.Client.System.ID,
				intf.UUID,
				intf.Name,
			))
			var adminState float64
			switch intf.AdminState {
			case "down":
				adminState = 0
			case "up":
				adminState = 1
			default:
				adminState = 2
			}
			e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
				interfaceAdminState,
				prometheus.GaugeValue,
				adminState,
				e.Client.System.ID,
				intf.UUID,
			))
			var linkState float64
			switch intf.LinkState {
			case "down":
				linkState = 0
			case "up":
				linkState = 1
			default:
				linkState = 2
			}
			e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
				interfaceLinkState,
				prometheus.GaugeValue,
				linkState,
				e.Client.System.ID,
				intf.UUID,
			))
			e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
				interfaceIngressPolicingBurst,
				prometheus.GaugeValue,
				intf.IngressPolicingBurst,
				e.Client.System.ID,
				intf.UUID,
			))
			e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
				interfaceIngressPolicingRate,
				prometheus.GaugeValue,
				intf.IngressPolicingRate,
				e.Client.System.ID,
				intf.UUID,
			))
			e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
				interfaceMacInUse,
				prometheus.GaugeValue,
				1,
				e.Client.System.ID,
				intf.UUID,
				intf.MacInUse,
			))
			e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
				interfaceMtu,
				prometheus.GaugeValue,
				intf.Mtu,
				e.Client.System.ID,
				intf.UUID,
			))
			var linkDuplex float64
			switch intf.Duplex {
			case "half":
				linkDuplex = 1
			case "full":
				linkDuplex = 2
			default:
				linkDuplex = 0
			}
			e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
				interfaceDuplex,
				prometheus.GaugeValue,
				linkDuplex,
				e.Client.System.ID,
				intf.UUID,
			))
			e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
				interfaceOfPort,
				prometheus.GaugeValue,
				intf.OfPort,
				e.Client.System.ID,
				intf.UUID,
			))
			e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
				interfaceIfIndex,
				prometheus.GaugeValue,
				intf.IfIndex,
				e.Client.System.ID,
				intf.UUID,
			))
			e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
				interfaceLocalIndex,
				prometheus.GaugeValue,
				intf.Index,
				e.Client.System.ID,
				intf.UUID,
			))
			for key, value := range intf.Statistics {
				switch key {
				case "rx_crc_err":
					e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
						interfaceStatRxCrcError,
						prometheus.CounterValue,
						float64(value),
						e.Client.System.ID,
						intf.UUID,
					))
				case "rx_dropped":
					e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
						interfaceStatRxDropped,
						prometheus.CounterValue,
						float64(value),
						e.Client.System.ID,
						intf.UUID,
					))
				case "rx_frame_err":
					e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
						interfaceStatRxFrameError,
						prometheus.CounterValue,
						float64(value),
						e.Client.System.ID,
						intf.UUID,
					))
				case "rx_over_err":
					e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
						interfaceStatRxOverrunError,
						prometheus.CounterValue,
						float64(value),
						e.Client.System.ID,
						intf.UUID,
					))
				case "rx_errors":
					e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
						interfaceStatRxErrorsTotal,
						prometheus.CounterValue,
						float64(value),
						e.Client.System.ID,
						intf.UUID,
					))
				case "rx_packets":
					e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
						interfaceStatRxPackets,
						prometheus.CounterValue,
						float64(value),
						e.Client.System.ID,
						intf.UUID,
					))
				case "rx_bytes":
					e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
						interfaceStatRxBytes,
						prometheus.CounterValue,
						float64(value),
						e.Client.System.ID,
						intf.UUID,
					))
				case "tx_packets":
					e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
						interfaceStatTxPackets,
						prometheus.CounterValue,
						float64(value),
						e.Client.System.ID,
						intf.UUID,
					))
				case "tx_bytes":
					e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
						interfaceStatTxBytes,
						prometheus.CounterValue,
						float64(value),
						e.Client.System.ID,
						intf.UUID,
					))
				case "tx_dropped":
					e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
						interfaceStatTxDropped,
						prometheus.CounterValue,
						float64(value),
						e.Client.System.ID,
						intf.UUID,
					))
				case "tx_errors":
					e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
						interfaceStatTxErrorsTotal,
						prometheus.CounterValue,
						float64(value),
						e.Client.System.ID,
						intf.UUID,
					))
				case "collisions":
					e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
						interfaceStatCollisions,
						prometheus.CounterValue,
						float64(value),
						e.Client.System.ID,
						intf.UUID,
					))
				case "rx_missed_errors":
					e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
						interfaceStatRxMissedErrors,
						prometheus.CounterValue,
						float64(value),
						e.Client.System.ID,
						intf.UUID,
					))
				default:
					level.Error(e.logger).Log(
						"msg", "detected malformed interface statistics",
						"system_id", e.Client.System.ID,
						"key", key,
						"value", value,
						"error", "OVS interface statistics has unsupported key",
					)
				}
			}
			e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
				interfaceLinkResets,
				prometheus.CounterValue,
				intf.LinkResets,
				e.Client.System.ID,
				intf.UUID,
			))
			e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
				interfaceLinkSpeed,
				prometheus.GaugeValue,
				intf.LinkSpeed,
				e.Client.System.ID,
				intf.UUID,
			))
			for key, value := range intf.Status {
				e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
					interfaceStatusKeyValuePair,
					prometheus.GaugeValue,
					1,
					e.Client.System.ID,
					intf.UUID,
					key,
					value,
				))
			}
			for key, value := range intf.Options {
				e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
					interfaceOptionsKeyValuePair,
					prometheus.GaugeValue,
					1,
					e.Client.System.ID,
					intf.UUID,
					key,
					value,
				))
			}
			for key, value := range intf.ExternalIDs {
				e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
					interfaceExternalIdKeyValuePair,
					prometheus.GaugeValue,
					1,
					e.Client.System.ID,
					intf.UUID,
					key,
					value,
				))
			}
		}
	}

	level.Debug(e.logger).Log(
		"msg", "GatherMetrics() completed GetDbInterfaces()",
		"system_id", e.Client.System.ID,
	)

	components = []string{
		"ovsdb-server",
	}

	for _, component := range components {
		level.Debug(e.logger).Log(
			"msg", "GatherMetrics() calls IsDefaultPortUp()",
			"component", component,
			"system_id", e.Client.System.ID,
		)
		defaultPortUp, err := e.Client.IsDefaultPortUp(component)
		if err != nil {
			level.Error(e.logger).Log(
				"msg", "IsDefaultPortUp() failed",
				"component", component,
				"system_id", e.Client.System.ID,
				"error", err.Error(),
			)
			e.IncrementErrorCounter()
		}
		e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
			networkPortUp,
			prometheus.GaugeValue,
			float64(defaultPortUp),
			e.Client.System.ID,
			component,
			"default",
		))
		level.Debug(e.logger).Log(
			"msg", "GatherMetrics() completed IsDefaultPortUp()",
			"component", component,
			"system_id", e.Client.System.ID,
		)

		level.Debug(e.logger).Log(
			"msg", "GatherMetrics() calls IsSslPortUp()",
			"component", component,
			"system_id", e.Client.System.ID,
		)
		sslPortUp, err := e.Client.IsSslPortUp(component)
		if err != nil {
			level.Error(e.logger).Log(
				"msg", "IsSslPortUp() failed",
				"component", component,
				"system_id", e.Client.System.ID,
				"error", err.Error(),
			)
			e.IncrementErrorCounter()
		}
		e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
			networkPortUp,
			prometheus.GaugeValue,
			float64(sslPortUp),
			e.Client.System.ID,
			component,
			"ssl",
		))
		level.Debug(e.logger).Log(
			"msg", "GatherMetrics() completed IsSslPortUp()",
			"component", component,
			"system_id", e.Client.System.ID,
		)
	}

	e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
		up,
		prometheus.GaugeValue,
		float64(upValue),
	))

	e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
		info,
		prometheus.GaugeValue,
		1,
		e.Client.System.ID, e.Client.System.RunDir, e.Client.System.Hostname,
		e.Client.System.Type, e.Client.System.Version,
		e.Client.Database.Vswitch.Version, e.Client.Database.Vswitch.Schema.Version,
	))

	e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
		requestErrors,
		prometheus.CounterValue,
		float64(e.errors),
		e.Client.System.ID,
	))

	e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
		nextPoll,
		prometheus.CounterValue,
		float64(e.nextCollectionTicker),
		e.Client.System.ID,
	))

	e.nextCollectionTicker = time.Now().Add(time.Duration(e.pollInterval) * time.Second).Unix()

	level.Debug(e.logger).Log(
		"msg", "GatherMetrics() returns",
		"system_id", e.Client.System.ID,
	)

	return
}

func init() {
	prometheus.MustRegister(version.NewCollector(namespace + "_exporter"))
}

// GetVersionInfo returns exporter info.
func GetVersionInfo() string {
	return version.Info()
}

// GetVersionBuildContext returns exporter build context.
func GetVersionBuildContext() string {
	return version.BuildContext()
}

// GetVersion returns exporter version.
func GetVersion() string {
	return version.Version
}

// GetRevision returns exporter revision.
func GetRevision() string {
	return version.Revision
}

// GetExporterName returns exporter name.
func GetExporterName() string {
	return appName
}

// SetPollInterval sets exporter's polling interval.
func (e *Exporter) SetPollInterval(i int64) {
	e.pollInterval = i
}
