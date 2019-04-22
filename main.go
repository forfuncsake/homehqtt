/*
	HomeHQtt is an MQTT adapter for the Origin HomeHQ gateway.
	It acts as an HTTPS proxy and forwards any posted device measurements to an MQTT broker.

	The purpose of the tool is to allow interception of the measurements to that they can be used in 3rd party home monitoring/automation applications. For example, the data in the topics can be used to create `binary_sensor` configurations in Home Assistant so that automations can be triggered by a change in status of the door sensor.
*/
package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/yosssi/gmq/mqtt/client"
)

func main() {
	cert := flag.String("cert", "cert.pem", "path to TLS cert for mitm proxy")
	key := flag.String("key", "key.pem", "path to TLS private key for mitm proxy")
	broker := flag.String("broker", "tcp://127.0.0.1:1883", "URL of the MQTT broker")
	topic := flag.String("topic", "", "MQTT topic to post measurements")

	flag.Parse()

	if *topic == "" {
		log.Fatal("topic must be specified")
	}

	u, err := url.Parse(*broker)
	if err != nil {
		log.Fatal(err)
	}

	mqttClient := client.New(&client.Options{
		ErrorHandler: func(err error) { log.Println("mqttclient:", err) },
	})
	// Terminate the Client.
	defer mqttClient.Terminate()

	server := &proxy{
		transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		cert:       *cert,
		key:        *key,
		devices:    make(map[string]*LCGW),
		mqttClient: mqttClient,
		mqttConnOpts: &client.ConnectOptions{
			Network:         u.Scheme,
			Address:         u.Host,
			ClientID:        []byte("homehqtt"),
			KeepAlive:       30,
			CONNACKTimeout:  5 * time.Second,
			PINGRESPTimeout: 5 * time.Second,
		},
		mqttRetries: 5,
		mqttTopic:   *topic,
	}

	// Attempt initial MQTT connection
	if err := mqttClient.Connect(server.mqttConnOpts); err != nil {
		log.Fatal(err)
	}

	server.Run()
}
