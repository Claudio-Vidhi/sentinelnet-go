package endpoints

import (
	"testing"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		ip       string
		category string
		role     string
	}{
		{"192.168.1.50", "private", ""},
		{"8.8.8.8", "public", ""},
		{"224.0.0.5", "multicast", "ospf_allspfrouters"},
		{"127.0.0.1", "loopback", ""},
		{"255.255.255.255", "broadcast", "broadcast_limited"},
		{"100.64.0.1", "cgnat", ""},
		{"192.0.2.1", "documentation", ""},
	}

	for _, tt := range tests {
		info := Classify(tt.ip)
		if info == nil {
			t.Fatalf("Classify(%s) returned nil", tt.ip)
		}
		if info.Category != tt.category {
			t.Errorf("Classify(%s).Category = %s; want %s", tt.ip, info.Category, tt.category)
		}
		if info.Role != tt.role {
			t.Errorf("Classify(%s).Role = %s; want %s", tt.ip, info.Role, tt.role)
		}
	}
}

func TestTrafficDirection(t *testing.T) {
	if dir := TrafficDirection("192.168.1.10", "10.0.0.5"); dir != "east_west" {
		t.Errorf("got %s; want east_west", dir)
	}
	if dir := TrafficDirection("192.168.1.10", "8.8.8.8"); dir != "north_south" {
		t.Errorf("got %s; want north_south", dir)
	}
	if dir := TrafficDirection("192.168.1.10", "224.0.0.5"); dir != "control_plane" {
		t.Errorf("got %s; want control_plane", dir)
	}
}

func TestClassifyMAC(t *testing.T) {
	info := ClassifyMAC("00:50:56:00:01:02")
	if info == nil || info.VendorKind != "VMware" {
		t.Errorf("expected VMware OUI, got %+v", info)
	}
	if !IsStableIdentity("00:50:56:00:01:02") {
		t.Errorf("expected stable identity for VMware MAC")
	}
}
