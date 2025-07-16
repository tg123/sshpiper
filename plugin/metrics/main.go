package main

import (
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"github.com/tg123/sshpiper/libplugin"
	"github.com/urfave/cli/v2"
)

func main() {
	libplugin.CreateAndRunPluginTemplate(&libplugin.PluginTemplate{
		Name:  "metrics",
		Usage: "sshpiperd metrics plugin, expose prometheus metrics after login",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "address",
				Usage:    "Metrics server listen address",
				Required: false,
				EnvVars:  []string{"SSHPIPERD_METRICS_ADDRESS"},
			},
			&cli.IntFlag{
				Name:     "port",
				Usage:    "Metrics server listen port",
				Required: false,
				Value:    9000,
				EnvVars:  []string{"SSHPIPERD_METRICS_PORT"},
			},
			&cli.BoolFlag{
				Name:     "collect-pipe-create-errors",
				Usage:    "Collect metrics on pipe creation errors",
				Required: false,
				Value:    false,
				EnvVars:  []string{"SSHPIPERD_METRICS_COLLECT_PIPE_CREATE_ERRORS"},
			},
			&cli.BoolFlag{
				Name:     "collect-upstream-auth-failures",
				Usage:    "Collect metrics on upstream auth failures",
				Required: false,
				Value:    false,
				EnvVars:  []string{"SSHPIPERD_METRICS_COLLECT_UPSTREAM_AUTH_FAILURES"},
			},
		},
		CreateConfig: func(c *cli.Context) (*libplugin.SshPiperPluginConfig, error) {
			port := c.Int("port")
			address := c.String("address")
			bindAddress := fmt.Sprintf("%v:%v", address, port)
			metrics, config := newPrometheusMetrics(
				c.Bool("collect-pipe-create-errors"), c.Bool("collect-upstream-auth-failures"),
			)
			go func(metrics *prometheusMetrics, bindAddress string) {
				if err := metrics.ListenAndServe(bindAddress); err != nil {
					log.Error("Metrics server error:", err)
				}
			}(metrics, bindAddress)
			log.Info("Metrics server is listening on: ", bindAddress)
			return config, nil
		},
	})
}

func newPrometheusMetrics(collectPipeCreateErrors, collectUpstreamAuthFailures bool) (*prometheusMetrics, *libplugin.SshPiperPluginConfig) {
	registry := prometheus.NewRegistry()
	openConnections := prometheus.NewGaugeVec(
		// sshpiper_pipe_open_connections
		prometheus.GaugeOpts{
			Namespace: "sshpiper",
			Subsystem: "pipe",
			Name:      "open_connections",
			Help:      "Number of open connections that currently exist partitioned by remote_addr and user",
		},
		[]string{"remote_addr", "username"},
	)
	registry.MustRegister(openConnections)

	metrics := &prometheusMetrics{
		registry:        registry,
		openConnections: openConnections,
	}
	config := &libplugin.SshPiperPluginConfig{
		PipeStartCallback: metrics.pipeStartCallback,
		PipeErrorCallback: metrics.pipeErrorCallback,
	}

	// Optional metrics
	if collectPipeCreateErrors {
		metrics.pipeCreateErrors = prometheus.NewCounterVec(
			// sshpiper_pipe_create_errors
			prometheus.CounterOpts{
				Namespace: "sshpiper",
				Subsystem: "pipe",
				Name:      "create_errors",
				Help:      "Number of create pipe errors partitioned by remote_addr",
			},
			[]string{"remote_addr"},
		)
		registry.MustRegister(metrics.pipeCreateErrors)
		config.PipeCreateErrorCallback = metrics.pipeCreateErrorCallback
	}
	if collectUpstreamAuthFailures {
		metrics.upstreamAuthFailures = prometheus.NewCounterVec(
			// sshpiper_upstream_auth_failures
			prometheus.CounterOpts{
				Namespace: "sshpiper",
				Subsystem: "upstream",
				Name:      "auth_failures",
				Help:      "Number of upstream auth failures partitioned by remote_addr, user, and method",
			},
			[]string{"remote_addr", "user", "method"},
		)
		registry.MustRegister(metrics.upstreamAuthFailures)
		config.UpstreamAuthFailureCallback = metrics.upstreamAuthFailureCallback
	}
	return metrics, config
}

type prometheusMetrics struct {
	registry *prometheus.Registry

	openConnections      *prometheus.GaugeVec
	pipeCreateErrors     *prometheus.CounterVec
	upstreamAuthFailures *prometheus.CounterVec
}

func (ms *prometheusMetrics) ListenAndServe(addr string) error {
	http.Handle("/metrics", promhttp.InstrumentMetricHandler(
		ms.registry, promhttp.HandlerFor(ms.registry, promhttp.HandlerOpts{
			ErrorLog: errorLogger{},
		}),
	))
	return http.ListenAndServe(addr, nil)
}

func (ms *prometheusMetrics) pipeStartCallback(conn libplugin.ConnMetadata) {
	gauge, err := ms.openConnections.GetMetricWithLabelValues(conn.RemoteAddr(), conn.User())
	if err != nil {
		log.Error("Failed to fetch gauge for pipe start callback: ", err)
		return
	}
	gauge.Inc()
}

func (ms *prometheusMetrics) pipeErrorCallback(conn libplugin.ConnMetadata, _ error) {
	ms.openConnections.DeleteLabelValues(conn.RemoteAddr(), conn.User())
}

func (ms *prometheusMetrics) pipeCreateErrorCallback(remoteAddr string, _ error) {
	counter, err := ms.pipeCreateErrors.GetMetricWithLabelValues(remoteAddr)
	if err != nil {
		log.Error("Failed to get counter for pipe create error callback: ", err)
		return
	}
	counter.Inc()
}

func (ms *prometheusMetrics) upstreamAuthFailureCallback(conn libplugin.ConnMetadata, method string, _ error, _ []string) {
	counter, err := ms.upstreamAuthFailures.GetMetricWithLabelValues(conn.RemoteAddr(), conn.User(), method)
	if err != nil {
		log.Error("Failed to get counter for upstream auth failure callback: ", err)
		return
	}
	counter.Inc()
}

type errorLogger struct{}

func (l errorLogger) Println(v ...any) {
	log.Error(v...)
}
