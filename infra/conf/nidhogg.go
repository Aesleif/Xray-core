package conf

import (
	"github.com/xtls/xray-core/proxy/nidhogg"
	"google.golang.org/protobuf/proto"
)

// NidhoggClientConfig is the JSON config for nidhogg outbound.
type NidhoggClientConfig struct {
	Address            string `json:"address"`
	Port               uint32 `json:"port"`
	PSK                string `json:"psk"`
	TunnelPath         string `json:"tunnel_path"`
	Fingerprint        string `json:"fingerprint"`
	ShapingMode        string `json:"shaping_mode"`
	Insecure           bool   `json:"insecure"`
	ConnectionPoolSize int32  `json:"connection_pool_size"`
}

// Build implements Buildable.
func (c *NidhoggClientConfig) Build() (proto.Message, error) {
	return &nidhogg.ClientConfig{
		ServerAddress:      c.Address,
		ServerPort:         c.Port,
		Psk:                c.PSK,
		TunnelPath:         c.TunnelPath,
		Fingerprint:        c.Fingerprint,
		ShapingMode:        c.ShapingMode,
		Insecure:           c.Insecure,
		ConnectionPoolSize: c.ConnectionPoolSize,
	}, nil
}

// NidhoggServerConfig is the JSON config for nidhogg inbound.
type NidhoggServerConfig struct {
	PSK                 string   `json:"psk"`
	ProxyTo             string   `json:"proxy_to"`
	TunnelPath          string   `json:"tunnel_path"`
	ProfileTargets      []string `json:"profile_targets"`
	ProfileInterval     string   `json:"profile_interval"`
	ProfileMinSnapshots int      `json:"profile_min_snapshots"`
	TelemetryThreshold  int32    `json:"telemetry_threshold"`
}

// Build implements Buildable.
func (c *NidhoggServerConfig) Build() (proto.Message, error) {
	return &nidhogg.ServerConfig{
		Psk:                 c.PSK,
		ProxyTo:             c.ProxyTo,
		TunnelPath:          c.TunnelPath,
		ProfileTargets:      c.ProfileTargets,
		ProfileInterval:     c.ProfileInterval,
		ProfileMinSnapshots: int32(c.ProfileMinSnapshots),
		TelemetryThreshold:  c.TelemetryThreshold,
	}, nil
}
