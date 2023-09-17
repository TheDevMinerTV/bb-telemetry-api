package main

import (
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
)

func main() {
	registry := prometheus.NewRegistry()
	registry.MustRegister(runningInstances)

	telemetry := NewTelemetryServer()
	if err := telemetry.Listen("127.0.0.1:65500"); err != nil {
		log.Fatalf("failed to launch telemetry server: %v", err)
	}
	defer telemetry.Close()

	go telemetry.run()

	log.Println("Listening for metrics on 127.0.0.1:65501")
	http.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	http.HandleFunc("/add", func(w http.ResponseWriter, r *http.Request) {
		module := r.URL.Query().Get("module")
		version := r.URL.Query().Get("version")

		runningInstances.With(map[string]string{
			"module":  module,
			"version": version,
		}).Inc()
	})

	if err := http.ListenAndServe("127.0.0.1:65501", nil); err != nil {
		log.Fatalf("failed to launch HTTP metrics server: %v", err)
	}
}
