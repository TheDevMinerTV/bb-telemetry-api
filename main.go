package main

import (
	"flag"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log"
	"net/http"
)

var (
	runningInstances = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "battlebit",
		Subsystem: "telemetry",
		Name:      "running_instances",
		Help:      "The total number of running instances separated by module and version",
	}, []string{"module", "version"})

	fTelemetryAddr = flag.String("telemetry-addr", "127.0.0.1:65500", "The address to listen for telemetry connections on")
	fMetricsAddr   = flag.String("metrics-addr", "127.0.0.1:65501", "The address to listen for metrics requests on")
)

func main() {
	flag.Parse()

	registry := prometheus.NewRegistry()
	registry.MustRegister(runningInstances)

	telemetry := NewTelemetryServer()
	if err := telemetry.Listen(*fTelemetryAddr); err != nil {
		log.Fatalf("failed to launch telemetry server: %v", err)
	}
	defer telemetry.Close()

	go telemetry.run()

	log.Printf("listening for metrics on %s", *fMetricsAddr)
	http.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	//http.HandleFunc("/add", func(w http.ResponseWriter, r *http.Request) {
	//	module := r.URL.Query().Get("module")
	//	version := r.URL.Query().Get("version")
	//
	//	runningInstances.With(map[string]string{
	//		"module":  module,
	//		"version": version,
	//	}).Inc()
	//})

	if err := http.ListenAndServe(*fMetricsAddr, nil); err != nil {
		log.Fatalf("failed to launch HTTP metrics server: %v", err)
	}
}
