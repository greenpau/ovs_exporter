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
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func TestNewExporter(t *testing.T) {
	logger, err := NewLogger("debug")
	if err != nil {
		t.Fatal(err)
	}

	opts := Options{
		Timeout: 2,
		Logger:  logger,
	}

	exporter := NewExporter(opts)
	if err := exporter.Connect(); err != nil {
		t.Fatalf("expected no error, but got %q", err)
	}

	exporter.Client.System.RunDir = "/var/run/openvswitch"
	exporter.Client.Database.Vswitch.Name = "Open_vSwitch"
	exporter.Client.Database.Vswitch.Socket.Remote = "unix:/var/run/openvswitch/db.sock"
	exporter.Client.Database.Vswitch.File.Data.Path = "/etc/openvswitch/conf.db"
	exporter.Client.Database.Vswitch.File.Log.Path = "/var/log/openvswitch/ovsdb-server.log"
	exporter.Client.Database.Vswitch.File.Pid.Path = "/var/run/openvswitch/ovsdb-server.pid"
	exporter.Client.Database.Vswitch.File.SystemID.Path = "/etc/openvswitch/system-id.conf"

	exporter.Client.Service.Vswitchd.File.Log.Path = "/var/log/openvswitch/ovs-vswitchd.log"
	exporter.Client.Service.Vswitchd.File.Pid.Path = "/var/run/openvswitch/ovs-vswitchd.pid"

	exporter.Client.Service.OvnController.File.Log.Path = "/var/log/openvswitch/ovn-controller.log"
	exporter.Client.Service.OvnController.File.Pid.Path = "/var/run/openvswitch/ovn-controller.pid"

	exporter.SetPollInterval(int64(15))
	prometheus.MustRegister(exporter)
	metricsPath := "/metrics"
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

	go func() {
		http.ListenAndServe(":9475", nil)
	}()

	time.Sleep(1 * time.Second)

	tr := &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 10 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	httpClient := &http.Client{
		Transport: tr,
		Timeout:   time.Second * 30,
	}

	var req *http.Request
	req, err = http.NewRequest("GET", "http://127.0.0.1:9475/metrics", nil)
	if err != nil {
		t.Fatalf("%s", err)
	}

	res, err := httpClient.Do(req)
	if err != nil {
		if !strings.HasSuffix(err.Error(), "EOF") {
			t.Fatalf("%s", err)
		}
	}

	if res == nil {
		t.Fatalf("response: <nil>")
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("non-EOF error: %s", err)
	}

	t.Logf("%s", string(body))
}
