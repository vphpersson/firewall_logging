package firewall_logging

import (
	"net"
	"testing"
	"time"

	"github.com/altshiftab/utils_go/pkg/schema"
	"github.com/florianl/go-nflog/v2"
)

// seedInterfaceNetworks primes the shared cache under its own lock. Writing to
// the map directly races the other parallel tests that read it.
func seedInterfaceNetworks(index int, networks []*net.IPNet) {
	interfaceNetworksCache.mutex.Lock()
	defer interfaceNetworksCache.mutex.Unlock()

	interfaceNetworksCache.entries[index] = cacheEntry[[]*net.IPNet]{
		value:   networks,
		expires: interfaceNetworksCache.now().Add(time.Hour),
	}
}

func TestEnrichWithNflogAttributeSequence(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		sequence         *uint32
		expectedSequence int
	}{
		{
			name:             "no sequence leaves the event unset",
			sequence:         nil,
			expectedSequence: 0,
		},
		{
			name:             "sequence is recorded",
			sequence:         new(uint32(4711)),
			expectedSequence: 4711,
		},
		{
			// Zero is a real sequence number, but it is also the zero value, so
			// it is indistinguishable once recorded. Worth pinning so nobody
			// later "fixes" it into a pointer without deciding that on purpose.
			name:             "zero sequence records zero",
			sequence:         new(uint32(0)),
			expectedSequence: 0,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			base := &schema.Base{}
			EnrichWithNflogAttribute(&nflog.Attribute{Seq: testCase.sequence}, base)

			if testCase.sequence == nil {
				if base.Event != nil {
					t.Errorf("expected no event, got %+v", base.Event)
				}
				return
			}

			if base.Event == nil {
				t.Fatal("expected event to be set")
			}

			if base.Event.Sequence != testCase.expectedSequence {
				t.Errorf("expected sequence %d, got %d", testCase.expectedSequence, base.Event.Sequence)
			}
		})
	}
}

// Hook and conntrack state are both strings derived from a single attribute and
// land on the same object, so one table covers them; separate tests were
// identical but for the field read.
func TestEnrichWithNflogAttributeNftablesStrings(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		attribute nflog.Attribute
		read      func(*schema.Nftables) string
		expected  string
		expectNil bool
	}{
		{
			name:      "no hook records nothing",
			attribute: nflog.Attribute{},
			expectNil: true,
		},
		{
			name:      "hook prerouting",
			attribute: nflog.Attribute{Hook: new(uint8(0))},
			read:      func(n *schema.Nftables) string { return n.Hook },
			expected:  "prerouting",
		},
		{
			name:      "hook input",
			attribute: nflog.Attribute{Hook: new(uint8(1))},
			read:      func(n *schema.Nftables) string { return n.Hook },
			expected:  "input",
		},
		{
			name:      "hook forward",
			attribute: nflog.Attribute{Hook: new(uint8(2))},
			read:      func(n *schema.Nftables) string { return n.Hook },
			expected:  "forward",
		},
		{
			name:      "hook output",
			attribute: nflog.Attribute{Hook: new(uint8(3))},
			read:      func(n *schema.Nftables) string { return n.Hook },
			expected:  "output",
		},
		{
			name:      "hook postrouting",
			attribute: nflog.Attribute{Hook: new(uint8(4))},
			read:      func(n *schema.Nftables) string { return n.Hook },
			expected:  "postrouting",
		},
		{
			name:      "unknown hook id records nothing",
			attribute: nflog.Attribute{Hook: new(uint8(9))},
			expectNil: true,
		},
		{
			name:      "conntrack established",
			attribute: nflog.Attribute{CtInfo: new(uint32(0))},
			read:      func(n *schema.Nftables) string { return n.ConntrackState },
			expected:  "established",
		},
		{
			name:      "conntrack related",
			attribute: nflog.Attribute{CtInfo: new(uint32(1))},
			read:      func(n *schema.Nftables) string { return n.ConntrackState },
			expected:  "related",
		},
		{
			name:      "conntrack new",
			attribute: nflog.Attribute{CtInfo: new(uint32(2))},
			read:      func(n *schema.Nftables) string { return n.ConntrackState },
			expected:  "new",
		},
		{
			// The reply values are the forward ones plus IP_CT_IS_REPLY, which
			// is why established_reply and IP_CT_IS_REPLY share the value 3.
			name:      "conntrack established reply",
			attribute: nflog.Attribute{CtInfo: new(uint32(3))},
			read:      func(n *schema.Nftables) string { return n.ConntrackState },
			expected:  "established_reply",
		},
		{
			name:      "conntrack related reply",
			attribute: nflog.Attribute{CtInfo: new(uint32(4))},
			read:      func(n *schema.Nftables) string { return n.ConntrackState },
			expected:  "related_reply",
		},
		{
			name:      "unknown conntrack value records nothing",
			attribute: nflog.Attribute{CtInfo: new(uint32(99))},
			expectNil: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			base := &schema.Base{}
			EnrichWithNflogAttribute(&testCase.attribute, base)

			if testCase.expectNil {
				if base.Nftables != nil {
					t.Errorf("expected no nftables object, got %+v", base.Nftables)
				}
				return
			}

			if base.Nftables == nil {
				t.Fatal("expected nftables object to be set")
			}

			if got := testCase.read(base.Nftables); got != testCase.expected {
				t.Errorf("expected %q, got %q", testCase.expected, got)
			}
		})
	}
}

func TestEnrichWithNflogAttributeMark(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		mark         *uint32
		expectedMark *uint32
	}{
		{
			name: "no mark leaves the nftables object unset",
			mark: nil,
		},
		{
			name:         "mark is recorded",
			mark:         new(uint32(32)),
			expectedMark: new(uint32(32)),
		},
		{
			// A mark of zero means "unmarked", which is worth distinguishing
			// from "no mark attribute at all" -- hence the pointer.
			name:         "zero mark is recorded as zero, not omitted",
			mark:         new(uint32(0)),
			expectedMark: new(uint32(0)),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			base := &schema.Base{}
			EnrichWithNflogAttribute(&nflog.Attribute{Mark: testCase.mark}, base)

			if testCase.expectedMark == nil {
				if base.Nftables != nil {
					t.Errorf("expected no nftables object, got %+v", base.Nftables)
				}
				return
			}

			if base.Nftables == nil || base.Nftables.Mark == nil {
				t.Fatal("expected a mark to be set")
			}

			if *base.Nftables.Mark != *testCase.expectedMark {
				t.Errorf("expected mark %d, got %d", *testCase.expectedMark, *base.Nftables.Mark)
			}
		})
	}
}

func TestSourceIsOnLink(t *testing.T) {
	t.Parallel()

	// Drive the cache directly rather than depending on the host's interfaces,
	// which differ between glory, capa and saviour.
	const index = 424242
	seedInterfaceNetworks(index, []*net.IPNet{
		{IP: net.ParseIP("192.168.1.1"), Mask: net.CIDRMask(24, 32)},
		{IP: net.ParseIP("10.5.1.1"), Mask: net.CIDRMask(24, 32)},
	})

	testCases := []struct {
		name      string
		ipAddress string
		expected  bool
	}{
		{name: "address on the first network", ipAddress: "192.168.1.50", expected: true},
		{name: "address on the second network", ipAddress: "10.5.1.2", expected: true},
		{name: "address on neither", ipAddress: "8.8.8.8", expected: false},
		{name: "adjacent subnet is not on-link", ipAddress: "192.168.2.50", expected: false},
		{name: "unparseable address", ipAddress: "", expected: false},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			if got := sourceIsOnLink(index, net.ParseIP(testCase.ipAddress)); got != testCase.expected {
				t.Errorf("expected %v, got %v", testCase.expected, got)
			}
		})
	}
}

func TestEnrichWithNflogAttributeSourceMac(t *testing.T) {
	t.Parallel()

	// Separate indexes so this test does not race the one above.
	const index = 424243
	const indexV6 = 424244
	seedInterfaceNetworks(index, []*net.IPNet{
		{IP: net.ParseIP("192.168.1.1"), Mask: net.CIDRMask(24, 32)},
	})
	seedInterfaceNetworks(indexV6, []*net.IPNet{
		{IP: net.ParseIP("fd00:1::1"), Mask: net.CIDRMask(64, 128)},
	})

	hardwareAddress := []byte{0x14, 0x75, 0x5b, 0xd4, 0xb3, 0xcc}

	testCases := []struct {
		name        string
		sourceIp    string
		hardware    *[]byte
		inDev       *uint32
		hook        *uint8
		expectedMac string
	}{
		{
			// The sender is on the arrival segment, so the frame's source
			// address really is the packet's source.
			name:        "on-link source records the mac",
			sourceIp:    "192.168.1.6",
			hardware:    &hardwareAddress,
			inDev:       new(uint32(index)),
			expectedMac: "14:75:5b:d4:b3:cc",
		},
		{
			// Routed traffic: the frame came from the upstream router, whose
			// address says nothing about where the packet originated.
			name:        "off-link source records no mac",
			sourceIp:    "8.8.8.8",
			hardware:    &hardwareAddress,
			inDev:       new(uint32(index)),
			expectedMac: "",
		},
		{
			name:        "no hardware address",
			sourceIp:    "192.168.1.6",
			hardware:    nil,
			inDev:       new(uint32(index)),
			expectedMac: "",
		},
		{
			name:        "no ingress interface",
			sourceIp:    "192.168.1.6",
			hardware:    &hardwareAddress,
			inDev:       nil,
			expectedMac: "",
		},
		{
			// Postrouting runs after srcnat, so the source may be a rewritten
			// address that happens to fall inside the ingress prefix; pairing
			// the frame's MAC with it would assert something false.
			name:        "postrouting never records source.mac",
			sourceIp:    "192.168.1.6",
			hardware:    &hardwareAddress,
			inDev:       new(uint32(index)),
			hook:        new(uint8(4)),
			expectedMac: "",
		},
		{
			name:        "on-link IPv6 source records the mac",
			sourceIp:    "fd00:1::5",
			hardware:    &hardwareAddress,
			inDev:       new(uint32(indexV6)),
			expectedMac: "14:75:5b:d4:b3:cc",
		},
		{
			name:        "off-link IPv6 source records no mac",
			sourceIp:    "2606:4700::1111",
			hardware:    &hardwareAddress,
			inDev:       new(uint32(indexV6)),
			expectedMac: "",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			base := &schema.Base{Source: &schema.Target{Ip: testCase.sourceIp}}
			EnrichWithNflogAttribute(
				&nflog.Attribute{
					HwAddr: testCase.hardware,
					InDev:  testCase.inDev,
					Hook:   testCase.hook,
				},
				base,
			)

			if base.Source.Mac != testCase.expectedMac {
				t.Errorf("expected mac %q, got %q", testCase.expectedMac, base.Source.Mac)
			}

			// The raw frame address is kept regardless of the on-link verdict.
			if testCase.hardware != nil {
				if base.Nftables == nil || base.Nftables.HwAddr != "14:75:5b:d4:b3:cc" {
					t.Errorf("expected the frame address to be recorded, got %+v", base.Nftables)
				}
			}
		})
	}
}
