package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/yosssi/gmq/mqtt/client"
)

type proxy struct {
	transport *http.Transport
	cert      string
	key       string

	mqttClient   *client.Client
	mqttConnOpts *client.ConnectOptions
	mqttRetries  int
	mqttTopic    string

	sync.Mutex
	devices map[string]*LCGW
}

// Run creates and starts the HTTPS server.
func (p *proxy) Run() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", p.mitm)
	mux.HandleFunc("/debug", p.debug)

	srv := &http.Server{
		Addr:    ":8443",
		Handler: mux,

		ReadTimeout:  120 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  120 * time.Second,

		// Disable HTTP/2.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	log.Fatal(srv.ListenAndServeTLS(p.cert, p.key))
}

func (p *proxy) debug(w http.ResponseWriter, req *http.Request) {
	d := struct {
		Devices       map[string]*LCGW
		NumGoRoutines int
	}{
		p.devices,
		runtime.NumGoroutine(),
	}

	b, err := json.Marshal(&d)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Write(b)
}

func (p *proxy) mitm(w http.ResponseWriter, req *http.Request) {
	// This is the site we MITM/proxy, fixup the request ready to forward
	req.URL = &url.URL{Scheme: "https", Host: "origin.presencepro.com:8443", Path: req.URL.Path}

	// Capture request body to parse for stats
	body, body2, err := tee(req.Body)
	if err != nil {
		log.Printf("Request tee error: %v\n", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	req.Body = ioutil.NopCloser(body)

	// We can sniff the copy we made
	go p.sniff("Req", body2, req.Header.Get("Content-Type"), &Request{})

	// Forward the request to the presence server
	resp, err := p.transport.RoundTrip(req)
	if err != nil {
		log.Printf("RoundTrip error: %v\n", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	copyHeader(w.Header(), resp.Header)

	resp1, resp2, err := tee(resp.Body)
	if err != nil {
		log.Printf("Response tee error: %v\n", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	go p.sniff("Resp", resp1, w.Header().Get("Content-Type"), &Response{})

	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp2)
}

// Tee the bytes from an io.Reader into 2 buffers (one to sniff
// and the other to forward)
func tee(r io.ReadCloser) (*bytes.Buffer, *bytes.Buffer, error) {
	buf1, err := ioutil.ReadAll(r)
	r.Close()
	if err != nil {
		return nil, nil, fmt.Errorf("request body read error: %v", err)
	}

	buf2 := make([]byte, len(buf1))
	copy(buf2, buf1)

	return bytes.NewBuffer(buf1), bytes.NewBuffer(buf2), nil
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func (p *proxy) sniff(prefix string, r io.Reader, contentType string, t tracker) {
	body, err := ioutil.ReadAll(r)
	if err != nil {
		log.Printf("%s: could not read message: %v", prefix, err)
		return
	}
	if strings.HasPrefix(contentType, "application/json") {
		err := json.Unmarshal(body, t)
		if err != nil {
			log.Printf("%s: could not decode json as Request or Response: %v. body:\n%s", prefix, err, string(body))
			return
		}

		t.track(p)
		return
	}
	log.Printf("%s: got non-json message. CT: %s Content: %q", prefix, contentType, string(body))
}

// publish will attempt to publish msg to the configured
// MQTT topic. If suffixes are provided, they are appended
// to the topic path with a '/' separator.
func (p *proxy) publish(msg []byte, suffixes ...string) {
	topic := []byte(p.mqttTopic)
	for _, s := range suffixes {
		topic = append(topic, []byte("/"+s)...)
	}
	for i := 0; i < p.mqttRetries; i++ {
		if i > 0 {
			log.Printf("publish retrying, attempt %d\n", i+1)
			p.mqttClient.Disconnect()
			time.Sleep(1 * time.Second)
		}
		err := p.mqttClient.Connect(p.mqttConnOpts)
		if err != nil && err != client.ErrAlreadyConnected {
			continue
		}
		err = p.mqttClient.Publish(&client.PublishOptions{
			TopicName: topic,
			Message:   msg,
			Retain:    true,
		})
		if err == nil {
			break
		}
		log.Println(err)
	}
}

type tracker interface {
	track(*proxy)
}

func (r *Request) track(p *proxy) {
	p.Lock()
	defer p.Unlock()
	gw, ok := p.devices[r.GatewayID]
	if !ok {
		gw = &LCGW{
			GatewayID:  r.GatewayID,
			Devices:    make(map[string]*Device),
			Parameters: make(map[string]string),
			Requests:   make(map[string]int),
			Results:    make(map[string]int),
			Commands:   make(map[string]int),
		}
		p.devices[r.GatewayID] = gw
	}

	gw.Requests[r.Command]++

	if r.Command == "postMeasurements" {
		for _, m := range r.Measurements {
			var d *Device
			var ok bool

			params := gw.Parameters
			if m.DeviceID != r.GatewayID {
				// Got measurements for a child device
				d, ok = gw.Devices[m.DeviceID]
				if !ok {
					d = &Device{
						Parameters: make(map[string]string),
					}
					gw.Devices[m.DeviceID] = d
				}
				params = d.Parameters
			}

			// capture measurement params and update tracked values if they changed
			for _, k := range m.Parameters {
				v, ok := params[k.Name]
				if ok {
					if v == k.Value {
						continue
					}
					log.Printf("changing %s from %s to %s for device %s", k.Name, v, k.Value, m.DeviceID)
				}
				params[k.Name] = k.Value
			}

			b, _ := json.Marshal(params)
			p.publish(b, m.DeviceID)
		}
	}
}

func (r *Response) track(p *proxy) {
	p.Lock()
	defer p.Unlock()
	gw, ok := p.devices[r.Command.DeviceID]
	if !ok {
		gw = &LCGW{
			GatewayID:  r.Command.DeviceID,
			Devices:    make(map[string]*Device),
			Parameters: make(map[string]string),
			Requests:   make(map[string]int),
			Results:    make(map[string]int),
			Commands:   make(map[string]int),
		}
		p.devices[r.Command.DeviceID] = gw
	}

	if r.Command.Name != "" {
		gw.Requests[r.Command.Name]++
	}
	gw.Results[r.ResultCode]++
	gw.LastResult = time.Now()
}

// A Response is the json payload sent back to the LCGW
// from the server.
type Response struct {
	Command struct {
		ID         int    `json:"commandId"`
		DeviceID   string `json:"deviceId"`
		Name       string `json:"name"`
		Parameters []struct {
			Name  string `json:"parameterName"`
			Value string `json:"parameterValue"`
		} `json:"parameters"`
	} `json:"command"`
	ResultCode string `json:"resultCode"`
}

// A Request is the json payload sent by the LCGW.
type Request struct {
	Command      string `json:"command"`
	GatewayID    string `json:"gatewayId"`
	Measurements []struct {
		DeviceID   string `json:"deviceId"`
		Parameters []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"parameters"`
		Timestamp int `json:"timestamp"`
	} `json:"measurements"`
}

// LCGW represents the properties of the HomeHQ
// "Low Cost Gateway".
type LCGW struct {
	GatewayID  string
	Parameters map[string]string
	Devices    map[string]*Device

	Commands   map[string]int
	Requests   map[string]int
	Results    map[string]int
	LastResult time.Time
}

// Device tracks the properties and measurements for an
// individual device managed by the LCGW.
type Device struct {
	Parameters map[string]string
	/*
		// Known Parameters from initial inspection:
		DeviceID       string `json:"deviceId"`
		Manufacturer   string `json:"manufacturer"`
		Model          string `json:"model"`
		DoorStatus     string `json:"doorStatus"`
		MotionStatus   string `json:"motionStatus"`
		Tamper         string `json:"ias.tamper"`
		Trouble        string `json:"ias.trouble"`
		BatteryLow     string `json:"batteryLow"`
		ACMains        string `json:"ias.acMains"`
		BatteryDefect  string `json:"ias.batteryDefect"`
		BatteryLevel   string `json:"batteryLevel"`
		BatteryVoltage string `json:"batteryVoltage"`
		LQI            string `json:"lqi"`
		RSSI           string `json:"rssi"`
	*/
}
