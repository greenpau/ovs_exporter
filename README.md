# Open Virtual Switch (OVS) Exporter

Export Open Virtual Switch (OVS) data to Prometheus.

## Introduction

This exporter exports metrics from the following OVS components:
* OVS `vswitchd` service
* `Open_vSwitch` database
* OVN `ovn-controller` service

## Getting Started

Run the following commands to install it:

```bash
wget https://github.com/ovnworks/ovs_exporter/releases/download/v1.0.0/ovs-exporter-1.0.0.linux-amd64.tar.gz
tar xvzf ovs-exporter-1.0.0.linux-amd64.tar.gz
cd ovs-exporter*
./install.sh
cd ..
rm -rf ovs-exporter-1.0.0.linux-amd64*
systemctl status ovs-exporter -l
curl -s localhost:9475/metrics | grep server_id
```

Run the following commands to build and test it:

```bash
cd $GOPATH/src
mkdir -p github.com/ovnworks
cd github.com/ovnworks
git clone https://github.com/ovnworks/ovs_exporter.git
cd ovs_exporter
make
make qtest
```

## Exported Metrics

| Metric | Meaning | Labels |
| ------ | ------- | ------ |
| `ovs_up` |  Is OVS stack up (1) or is it down (0). | `system_id` |

For example:

```bash
$ curl localhost:9475/metrics | grep ovn
# HELP ovs_up Is OVS stack up (1) or is it down (0).
# TYPE ovs_up gauge
ovs_up 1
```

## Flags

```bash
./bin/ovs-exporter --help
```
