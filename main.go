package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	runningModules = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "battlebit",
		Subsystem: "telemetry",
		Name:      "running_modules",
		Help:      "The total number of running modules separated by module, version and hash",
	}, []string{"name", "version", "hash"})

	fTelemetryAddr = flag.String("telemetry-addr", "127.0.0.1:65500", "The address to listen for telemetry connections on")
	fMetricsAddr   = flag.String("metrics-addr", "127.0.0.1:65501", "The address to listen for metrics requests on")
	fVerbose       = flag.Bool("verbose", false, "Whether to log verbose messages")
)

func main() {
	flag.Parse()

	registry := prometheus.NewRegistry()
	registry.MustRegister(runningModules)

	telemetry := NewTelemetryServer(*fVerbose)
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
