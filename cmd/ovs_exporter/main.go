package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/go-kit/log/level"
	ovs "github.com/greenpau/ovs_exporter/pkg/ovs_exporter"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
)

func main() {
	var listenAddress string
	var metricsPath string
	var pollTimeout int
	var pollInterval int
	var isShowVersion bool
	var logLevel string
	var systemRunDir string
	var databaseVswitchName string
	var databaseVswitchSocketRemote string
	var databaseVswitchFileDataPath string
	var databaseVswitchFileLogPath string
	var databaseVswitchFilePidPath string
	var databaseVswitchFileSystemIDPath string
	var serviceVswitchdFileLogPath string
	var serviceVswitchdFilePidPath string
	var serviceOvnControllerFileLogPath string
	var serviceOvnControllerFilePidPath string

	flag.StringVar(&listenAddress, "web.listen-address", ":9475", "Address to listen on for web interface and telemetry.")
	flag.StringVar(&metricsPath, "web.telemetry-path", "/metrics", "Path under which to expose metrics.")
	flag.IntVar(&pollTimeout, "ovs.timeout", 2, "Timeout on JSON-RPC requests to OVS.")
	flag.IntVar(&pollInterval, "ovs.poll-interval", 15, "The minimum interval (in seconds) between collections from OVS server.")
	flag.BoolVar(&isShowVersion, "version", false, "version information")
	flag.StringVar(&logLevel, "log.level", "info", "logging severity level")

	flag.StringVar(&systemRunDir, "system.run.dir", "/var/run/openvswitch", "OVS default run directory.")

	flag.StringVar(&databaseVswitchName, "database.vswitch.name", "Open_vSwitch", "The name of OVS db.")
	flag.StringVar(&databaseVswitchSocketRemote, "database.vswitch.socket.remote", "unix:/var/run/openvswitch/db.sock", "JSON-RPC unix socket to OVS db.")
	flag.StringVar(&databaseVswitchFileDataPath, "database.vswitch.file.data.path", "/etc/openvswitch/conf.db", "OVS db file.")
	flag.StringVar(&databaseVswitchFileLogPath, "database.vswitch.file.log.path", "/var/log/openvswitch/ovsdb-server.log", "OVS db log file.")
	flag.StringVar(&databaseVswitchFilePidPath, "database.vswitch.file.pid.path", "/var/run/openvswitch/ovsdb-server.pid", "OVS db process id file.")
	flag.StringVar(&databaseVswitchFileSystemIDPath, "database.vswitch.file.system.id.path", "/etc/openvswitch/system-id.conf", "OVS system id file.")

	flag.StringVar(&serviceVswitchdFileLogPath, "service.vswitchd.file.log.path", "/var/log/openvswitch/ovs-vswitchd.log", "OVS vswitchd daemon log file.")
	flag.StringVar(&serviceVswitchdFilePidPath, "service.vswitchd.file.pid.path", "/var/run/openvswitch/ovs-vswitchd.pid", "OVS vswitchd daemon process id file.")

	flag.StringVar(&serviceOvnControllerFileLogPath, "service.ovncontroller.file.log.path", "/var/log/openvswitch/ovn-controller.log", "OVN controller daemon log file.")
	flag.StringVar(&serviceOvnControllerFilePidPath, "service.ovncontroller.file.pid.path", "/var/run/openvswitch/ovn-controller.pid", "OVN controller daemon process id file.")

	var usageHelp = func() {
		fmt.Fprintf(os.Stderr, "\n%s - Prometheus Exporter for Open Virtual Switch (OVS)\n\n", ovs.GetExporterName())
		fmt.Fprintf(os.Stderr, "Usage: %s [arguments]\n\n", ovs.GetExporterName())
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nDocumentation: https://github.com/greenpau/ovs_exporter/\n\n")
	}
	flag.Usage = usageHelp
	flag.Parse()

	opts := ovs.Options{
		Timeout: pollTimeout,
	}

	allowedLogLevel := &promlog.AllowedLevel{}
	if err := allowedLogLevel.Set(logLevel); err != nil {
		fmt.Fprintf(os.Stderr, "%s", err.Error());
		os.Exit(1);
	}

	promlogConfig := &promlog.Config{
		Level: allowedLogLevel,
	}

	logger := promlog.New(promlogConfig)

	if isShowVersion {
		fmt.Fprintf(os.Stdout, "%s %s", ovs.GetExporterName(), ovs.GetVersion())
		if ovs.GetRevision() != "" {
			fmt.Fprintf(os.Stdout, ", commit: %s\n", ovs.GetRevision())
		} else {
			fmt.Fprint(os.Stdout, "\n")
		}
		os.Exit(0)
	}

	level.Info(logger).Log(
		"msg", "Starting exporter", 
		"exporter", ovs.GetExporterName(), 
		"version", ovs.GetVersionInfo(),
		"build_context", ovs.GetVersionBuildContext(),
	)
	
	exporter, err := ovs.NewExporter(opts)
	if err != nil {
		level.Error(logger).Log(
			"msg",  "failed to init properly",
			"error", err.Error(),
		)
		os.Exit(1);
	}
	exporter.SetLogger(logger)

	exporter.Client.System.RunDir = systemRunDir

	exporter.Client.Database.Vswitch.Name = databaseVswitchName
	exporter.Client.Database.Vswitch.Socket.Remote = databaseVswitchSocketRemote
	exporter.Client.Database.Vswitch.File.Data.Path = databaseVswitchFileDataPath
	exporter.Client.Database.Vswitch.File.Log.Path = databaseVswitchFileLogPath
	exporter.Client.Database.Vswitch.File.Pid.Path = databaseVswitchFilePidPath
	exporter.Client.Database.Vswitch.File.SystemID.Path = databaseVswitchFileSystemIDPath

	exporter.Client.Service.Vswitchd.File.Log.Path = serviceVswitchdFileLogPath
	exporter.Client.Service.Vswitchd.File.Pid.Path = serviceVswitchdFilePidPath

	exporter.Client.Service.OvnController.File.Log.Path = serviceOvnControllerFileLogPath
	exporter.Client.Service.OvnController.File.Pid.Path = serviceOvnControllerFilePidPath

	level.Info(logger).Log("ovs_system_id",exporter.Client.System.ID)

	exporter.SetPollInterval(int64(pollInterval))
	prometheus.MustRegister(exporter)

	http.Handle(metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
             <head><title>OVS Exporter</title></head>
             <body>
             <h1>OVS Exporter</h1>
             <p><a href='` + metricsPath + `'>Metrics</a></p>
             </body>
             </html>`))
	})

	level.Info(logger).Log("listen_on ", listenAddress)
	if err := http.ListenAndServe(listenAddress, nil); err != nil {
		level.Error(logger).Log(
			"msg",  "listener failed",
			"error", err.Error(),
		)
		os.Exit(1);
	}
}
