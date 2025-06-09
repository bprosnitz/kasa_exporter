package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/sync/errgroup"
)

const (
	bindAddr       = "0.0.0.0:0"
	broadcastAddr  = "255.255.255.255:9999"
	waitDeadline   = 500 * time.Millisecond
	readBufSize    = 4096
	request        = `{"system":{"get_sysinfo":{}},"emeter":{"get_realtime":{}}}`
	pollInterval   = 30 * time.Second
	httpListenAddr = "0.0.0.0:6832"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		for {
			responses, err := broadcast()
			if err != nil {
				return fmt.Errorf("error in broadcast: %v", err)
			}
			for _, resp := range responses {
				recordMetrics(resp)
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(pollInterval):
			}
		}
	})
	server := http.Server{
		Addr:    httpListenAddr,
		Handler: promhttp.Handler(),
	}
	g.Go(func() error {
		fmt.Printf("Listening on %s\n", httpListenAddr)
		return server.ListenAndServe()
	})
	g.Go(func() error {
		<-ctx.Done()
		return server.Shutdown(ctx)
	})
	if err := g.Wait(); err != nil {
		log.Fatalf("error: %v", err)
	}
}

func broadcast() ([]Response, error) {
	listenAddr, err := net.ResolveUDPAddr("udp", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve udp address %s: %w", bindAddr, err)
	}
	writeAddr, err := net.ResolveUDPAddr("udp", broadcastAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve udp address %s: %w", bindAddr, err)
	}

	conn, err := net.ListenUDP("udp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on udp address %v: %w", listenAddr, err)
	}
	defer conn.Close()

	outMsg := encrypt([]byte(request))
	if _, err := conn.WriteTo(outMsg, writeAddr); err != nil {
		return nil, fmt.Errorf("failed to write to %v: %w", writeAddr, err)
	}

	var responses []Response
	for {
		if err := conn.SetReadDeadline(time.Now().Add(waitDeadline)); err != nil {
			return nil, fmt.Errorf("failed to set deadline: %w", err)
		}

		readBuf := make([]byte, readBufSize)
		n, err := conn.Read(readBuf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				break
			}
			return nil, fmt.Errorf("failed to read: %w", err)
		}
		inMsg := decrypt(readBuf[:n])
		fmt.Printf("%v: json response: %s\n", time.Now(), inMsg)

		var resp Response
		if err := json.Unmarshal(inMsg, &resp); err != nil {
			return nil, fmt.Errorf("failed to decode response %s: %w", inMsg, err)
		}
		responses = append(responses, resp)
	}
	return responses, nil
}

func encrypt(data []byte) []byte {
	ciphertext := make([]byte, len(data))

	var key byte = 0xAB
	for i, currentByte := range data {
		encByte := key ^ currentByte
		key = encByte
		ciphertext[i] = encByte
	}

	return ciphertext
}

func decrypt(ciphertext []byte) []byte {
	plaintext := make([]byte, len(ciphertext))

	var key byte = 0xAB
	for i, currentByte := range ciphertext {
		decByte := key ^ currentByte
		key = currentByte
		plaintext[i] = decByte
	}

	return plaintext
}

type Response struct {
	System SystemResponse `json:"system"`
	Emeter EmeterResponse `json:"emeter"`
}

type SystemResponse struct {
	GetSysinfo GetSysinfoResponse `json:"get_sysinfo"`
}

type GetSysinfoResponse struct {
	SoftwareVersion  string              `json:"sw_ver"`
	HardwareVersion  string              `json:"hw_ver"`
	Model            string              `json:"model"`
	DeviceId         string              `json:"deviceId"`
	OemId            string              `json:"oemId"`
	HardwareId       string              `json:"hwId"`
	Rssi             *float64            `json:"rssi"`
	LatitudeInteger  *int                `json:"latitude_i"`
	LongitudeInteger *int                `json:"longitude_i"`
	Alias            string              `json:"alias"`
	Status           string              `json:"status"`
	OBDSource        string              `json:"obd_src"`
	MicType          string              `json:"mic_type"`
	Feature          string              `json:"feature"`
	MAC              string              `json:"mac"`
	Updating         *int                `json:"updating"`
	LEDOff           *int                `json:"led_off"`
	RelayState       *int                `json:"relay_state"`
	OnTime           *int                `json:"on_time"`
	IconHash         string              `json:"icon_hash"`
	DevName          string              `json:"dev_name"`
	NextAction       *NextActionResponse `json:"next_action"`
	ErrCode          int                 `json:"err_code"`
	ErrMsg           *string             `json:"err_msg"`
}

type NextActionResponse struct {
	Type             int    `json:"type"`
	Id               string `json:"id"`
	ScheduledSeconds *int   `json:"schd_sec"`
	Action           *int   `json:"action"`
}

type EmeterResponse struct {
	GetRealtime   *GetRealtimeResponse   `json:"get_realtime"`
	GetVgainIgain *GetVgainIgainResponse `json:"get_vgain_igain"`
	ErrCode       int                    `json:"err_code"`
	ErrMsg        *string                `json:"err_msg"`
}

type GetRealtimeResponse struct {
	Current *float64 `json:"current"`
	Voltage *float64 `json:"voltage"`
	Power   *float64 `json:"power"`
	Total   *float64 `json:"total"`

	VoltageMv *int `json:"voltage_mv"`
	CurrentMa *int `json:"current_ma"`
	PowerMw   *int `json:"power_mw"`
	TotalWh   *int `json:"total_wh"`

	ErrCode int     `json:"err_code"`
	ErrMsg  *string `json:"err_msg"`
}

type GetVgainIgainResponse struct {
	Vgain *int `json:"vgain"`
	Igain *int `json:"igain"`

	ErrCode int     `json:"err_code"`
	ErrMsg  *string `json:"err_msg"`
}

var metrics = struct {
	RelayState *prometheus.GaugeVec
	OnTime     *prometheus.GaugeVec
}{
	RelayState: prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kasa_relay_state",
	}, []string{"device_id", "alias", "model", "mac"}),
	OnTime: prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kasa_on_time",
	}, []string{"device_id", "alias", "model", "mac"}),
}

func init() {
	prometheus.Register(metrics.RelayState)
	prometheus.Register(metrics.OnTime)
}

func recordMetrics(resp Response) {
	labels := prometheus.Labels{
		"device_id": resp.System.GetSysinfo.DeviceId,
		"alias":     resp.System.GetSysinfo.Alias,
		"model":     resp.System.GetSysinfo.Model,
		"mac":       resp.System.GetSysinfo.MAC,
	}
	if resp.System.GetSysinfo.RelayState != nil {
		metrics.RelayState.With(labels).Set(float64(*resp.System.GetSysinfo.RelayState))
	}
	if resp.System.GetSysinfo.OnTime != nil {
		metrics.OnTime.With(labels).Set(float64(*resp.System.GetSysinfo.OnTime))
	}
}
