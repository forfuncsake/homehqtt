# homehqtt
HomeHQtt is an MQTT adapter for the Origin HomeHQ gateway.
It acts as an HTTPS proxy and forwards any posted device measurements to an MQTT broker.

The purpose of the tool is to allow interception of the measurements to that they can be used in 3rd party home monitoring/automation applications. For example, the data in the topics can be used to create `binary_sensor` configurations in Home Assistant so that automations can be triggered by a change in status of the door sensor.

# Documentation
Limited godoc can be found here: https://godoc.org/github.com/forfuncsake/homehqtt

# Contributions
Feedback, Issues and PRs are all welcome!



[![Go Report Card](https://goreportcard.com/badge/github.com/forfuncsake/homehqtt)](https://goreportcard.com/report/github.com/forfuncsake/homehqtt)
