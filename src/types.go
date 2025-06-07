package main

import "encoding/json"

// Response formats
type AgentApiResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type PeerApiResponse struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"` // Defer parsing of `data`
}

// Agent API Session types
type BgpSession struct {
	UUID          string   `json:"uuid"`
	ASN           int      `json:"asn"`
	Status        int      `json:"status"`
	IPv4          string   `json:"ipv4"`
	IPv6          string   `json:"ipv6"`
	IPv6LinkLocal string   `json:"ipv6LinkLocal"`
	Type          string   `json:"type"`
	Extensions    []string `json:"extensions"`
	Interface     string   `json:"interface"`
	Endpoint      string   `json:"endpoint"`
	Credential    string   `json:"credential"`
	Data          string   `json:"data"`
	MTU           int      `json:"mtu"`
	Policy        int      `json:"policy"`
}

type BgpSessionsResponse struct {
	BgpSessions []BgpSession `json:"bgpSessions"`
}

// Session Modify request type
type SessionModifyRequest struct {
	Status  int    `json:"status"`
	Session string `json:"session"`
}

type SessionReportRequest struct {
	Sessions []SessionMetric `json:"sessions"`
}

type SessionMetric struct {
	UUID      string          `json:"uuid"`
	ASN       int             `json:"asn"`
	Timestamp int64           `json:"timestamp"`
	BGP       BGPMetric       `json:"bgp"`
	Interface InterfaceMetric `json:"interface"`
	RTT       RTT             `json:"rtt"`
}

type BGPMetric struct {
	State  string          `json:"state"`
	Info   string          `json:"info"`
	Routes BGPRoutesMetric `json:"routes"`
}

type BGPRoutesMetric struct {
	IPv4 RouteMetricStruct `json:"ipv4"`
	IPv6 RouteMetricStruct `json:"ipv6"`
}

type RouteMetricStruct struct {
	Imported RouteMetrics `json:"imported"`
	Exported RouteMetrics `json:"exported"`
}

type RouteMetrics struct {
	Current int        `json:"current"`
	Metric  [][2]int64 `json:"metric"` // each metric is a pair [timestamp, value]
}

type InterfaceMetric struct {
	IPv4          string                 `json:"ipv4"`
	IPv6          string                 `json:"ipv6"`
	IPv6LinkLocal string                 `json:"ipv6LinkLocal"`
	MAC           string                 `json:"mac"`
	MTU           int                    `json:"mtu"`
	Status        string                 `json:"status"`
	Traffic       InterfaceTrafficMetric `json:"traffic"`
}

type InterfaceTrafficMetric struct {
	RX TrafficMetrics `json:"rx"`
	TX TrafficMetrics `json:"tx"`
}

type TrafficMetrics struct {
	Total   int64      `json:"total"`
	Current int64      `json:"current"`
	Metric  [][2]int64 `json:"metric"` // each metric is a pair [timestamp, value]
}

type RTT struct {
	Current int      `json:"current"`
	Metric  [][2]int `json:"metric"` // each metric is a pair [timestamp, value]
}
