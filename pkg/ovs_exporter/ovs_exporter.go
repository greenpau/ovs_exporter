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
	//"github.com/davecgh/go-spew/spew"
	"github.com/greenpau/ovsdb"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	"github.com/prometheus/common/version"
	_ "net/http/pprof"
	"sync"
	"sync/atomic"
	"time"
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
}

type Options struct {
	Timeout int
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
	log.Debugf("%s: NewExporter() calls Connect()", e.Client.System.ID)
	if err := client.Connect(); err != nil {
		return &e, err
	}
	log.Debugf("%s: NewExporter() calls GetSystemInfo()", e.Client.System.ID)
	if err := e.Client.GetSystemInfo(); err != nil {
		return &e, err
	}
	log.Debugf("%s: NewExporter() initialized successfully", e.Client.System.ID)
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
	log.Debugf("%s: Collect() calls RLock()", e.Client.System.ID)
	e.RLock()
	defer e.RUnlock()
	if len(e.metrics) == 0 {
		log.Debugf("%s: Collect() no metrics found", e.Client.System.ID)
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
	log.Debugf("%s: Collect() sends %d metrics to a shared channel", e.Client.System.ID, len(e.metrics))
	for _, m := range e.metrics {
		ch <- m
	}
}

// GatherMetrics collect data from OVN server and stores them
// as Prometheus metrics.
func (e *Exporter) GatherMetrics() {
	log.Debugf("%s: GatherMetrics() called", e.Client.System.ID)
	if time.Now().Unix() < e.nextCollectionTicker {
		return
	}
	e.Lock()
	log.Debugf("%s: GatherMetrics() locked", e.Client.System.ID)
	defer e.Unlock()
	if len(e.metrics) > 0 {
		e.metrics = e.metrics[:0]
		log.Debugf("%s: GatherMetrics() cleared metrics", e.Client.System.ID)
	}
	upValue := 1

	var err error

	err = e.Client.GetSystemInfo()
	if err != nil {
		log.Errorf("%s: %v", e.Client.Database.Vswitch.Name, err)
		e.IncrementErrorCounter()
		upValue = 0
	} else {
		log.Debugf("%s: system-id: %s", e.Client.Database.Vswitch.Name, e.Client.System.ID)
	}

	components := []string{
		"ovsdb-server",
		"ovs-vswitchd",
	}
	for _, component := range components {
		p, err := e.Client.GetProcessInfo(component)
		log.Debugf("%s: GatherMetrics() calls GetProcessInfo(%s)", e.Client.System.ID, component)
		if err != nil {
			log.Errorf("%s: pid-%v", component, err)
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
		log.Debugf("%s: GatherMetrics() completed GetProcessInfo(%s)", e.Client.System.ID, component)
	}

	components = []string{
		"ovsdb-server",
		"ovs-vswitchd",
	}
	for _, component := range components {
		log.Debugf("%s: GatherMetrics() calls GetLogFileInfo(%s)", e.Client.System.ID, component)
		file, err := e.Client.GetLogFileInfo(component)
		if err != nil {
			log.Errorf("%s: log-file-%v", component, err)
			e.IncrementErrorCounter()
			continue
		}
		log.Debugf("%s: GatherMetrics() completed GetLogFileInfo(%s)", e.Client.System.ID, component)
		e.metrics = append(e.metrics, prometheus.MustNewConstMetric(
			logFileSize,
			prometheus.GaugeValue,
			float64(file.Info.Size()),
			e.Client.System.ID,
			file.Component,
			file.Path,
		))
		log.Debugf("%s: GatherMetrics() calls GetLogFileEventStats(%s)", e.Client.System.ID, component)
		eventStats, err := e.Client.GetLogFileEventStats(component)
		if err != nil {
			log.Errorf("%s: log-event-stat: %v", component, err)
			e.IncrementErrorCounter()
			continue
		}
		log.Debugf("%s: GatherMetrics() completed GetLogFileEventStats(%s)", e.Client.System.ID, component)
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
	}

	for _, component := range components {
		log.Debugf("%s: GatherMetrics() calls AppListCommands(%s)", e.Client.System.ID, component)
		if cmds, err := e.Client.AppListCommands(component); err != nil {
			log.Errorf("%s: %v", component, err)
			e.IncrementErrorCounter()
			log.Debugf("%s: GatherMetrics() completed AppListCommands(%s)", e.Client.System.ID, component)
		} else {
			log.Debugf("%s: GatherMetrics() completed AppListCommands(%s)", e.Client.System.ID, component)
			if cmds["coverage/show"] {
				log.Debugf("%s: GatherMetrics() calls GetAppCoverageMetrics(%s)", e.Client.System.ID, component)
				if metrics, err := e.Client.GetAppCoverageMetrics(component); err != nil {
					log.Errorf("%s: %v", component, err)
					e.IncrementErrorCounter()
				} else {
					for event, metric := range metrics {
						//log.Infof("%s: %s, %s", component, name, metric)
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
				log.Debugf("%s: GatherMetrics() completed GetAppCoverageMetrics(%s)", e.Client.System.ID, component)
			}
		}
	}

	components = []string{
		"ovsdb-server",
	}

	for _, component := range components {
		log.Debugf("%s: GatherMetrics() calls IsDefaultPortUp(%s)", e.Client.System.ID, component)
		defaultPortUp, err := e.Client.IsDefaultPortUp(component)
		if err != nil {
			log.Errorf("%s: %v", component, err)
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
		log.Debugf("%s: GatherMetrics() completed IsDefaultPortUp(%s)", e.Client.System.ID, component)
		log.Debugf("%s: GatherMetrics() calls IsSslPortUp(%s)", e.Client.System.ID, component)
		sslPortUp, err := e.Client.IsSslPortUp(component)
		if err != nil {
			log.Errorf("%s: %v", component, err)
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
		log.Debugf("%s: GatherMetrics() completed IsSslPortUp(%s)", e.Client.System.ID, component)
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

	log.Debugf("%s: GatherMetrics() returns", e.Client.System.ID)
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
