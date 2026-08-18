package firewall_logging

import (
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/altshiftab/utils_go/pkg/schema"
	"github.com/florianl/go-nflog/v2"
)

// unresolvableInterfaceIndex is far above any interface index a host will have,
// so the name lookup fails predictably and only the id is recorded.
const unresolvableInterfaceIndex = 0x7fffffff

func makeIpv4TcpPayload() []byte {
	return []byte{
		// IPv4 header: version 4, IHL 5, protocol 6 (TCP), 192.0.2.1 -> 198.51.100.2
		0x45, 0x00, 0x00, 0x28,
		0x00, 0x00, 0x40, 0x00,
		0x40, 0x06, 0x00, 0x00,
		192, 0, 2, 1,
		198, 51, 100, 2,
		// TCP header: source port 54321, destination port 443
		0xd4, 0x31, 0x01, 0xbb,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x50, 0x02, 0x20, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
}

func TestEnrichWithNflogAttributeGuards(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name      string
		attribute *nflog.Attribute
		base      *schema.Base
	}{
		{
			name:      "nil attribute and nil base",
			attribute: nil,
			base:      nil,
		},
		{
			name:      "nil attribute",
			attribute: nil,
			base:      &schema.Base{},
		},
		{
			name:      "nil base",
			attribute: &nflog.Attribute{},
			base:      nil,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			EnrichWithNflogAttribute(testCase.attribute, testCase.base)

			if testCase.base != nil && !reflect.DeepEqual(testCase.base, &schema.Base{}) {
				t.Errorf("expected base to be left untouched, got %+v", testCase.base)
			}
		})
	}
}

func TestEnrichWithNflogAttributeTimestamp(t *testing.T) {
	t.Parallel()

	timestamp := time.Date(2026, 8, 18, 12, 30, 45, 123456789, time.UTC)

	testCases := []struct {
		name      string
		timestamp *time.Time
		expected  string
	}{
		{
			name:      "no timestamp leaves the field empty",
			timestamp: nil,
			expected:  "",
		},
		{
			name:      "timestamp is formatted as rfc3339 nano in utc",
			timestamp: &timestamp,
			expected:  "2026-08-18T12:30:45.123456789Z",
		},
		{
			name: "non-utc timestamp is converted",
			timestamp: func() *time.Time {
				converted := timestamp.In(time.FixedZone("CEST", 2*60*60))
				return &converted
			}(),
			expected: "2026-08-18T12:30:45.123456789Z",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			base := &schema.Base{}
			EnrichWithNflogAttribute(&nflog.Attribute{Timestamp: testCase.timestamp}, base)

			if base.Timestamp != testCase.expected {
				t.Errorf("expected timestamp %q, got %q", testCase.expected, base.Timestamp)
			}
		})
	}
}

func TestEnrichWithNflogAttributePayload(t *testing.T) {
	t.Parallel()

	ipv4TcpPayload := makeIpv4TcpPayload()
	emptyPayload := []byte{}
	// An IPv6 header whose first nibble is 6, selecting the IPv6 decoder.
	ipv6Payload := append([]byte{0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3b, 0x40}, make([]byte, 32)...)

	testCases := []struct {
		name              string
		payload           *[]byte
		expectedSourceIp  string
		expectedDestIp    string
		expectedTransport string
		expectedType      string
	}{
		{
			name:    "nil payload",
			payload: nil,
		},
		{
			name:    "empty payload",
			payload: &emptyPayload,
		},
		{
			name:              "ipv4 tcp payload is decoded",
			payload:           &ipv4TcpPayload,
			expectedSourceIp:  "192.0.2.1",
			expectedDestIp:    "198.51.100.2",
			expectedTransport: "tcp",
			expectedType:      "ipv4",
		},
		{
			name:         "leading nibble six selects the ipv6 decoder",
			payload:      &ipv6Payload,
			expectedType: "ipv6",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			base := &schema.Base{}
			EnrichWithNflogAttribute(&nflog.Attribute{Payload: testCase.payload}, base)

			if testCase.expectedType == "" {
				if base.Network != nil {
					t.Errorf("expected no network enrichment, got %+v", base.Network)
				}
				return
			}

			if base.Network == nil {
				t.Fatal("expected network to be set")
			}

			if base.Network.Type != testCase.expectedType {
				t.Errorf("expected network type %q, got %q", testCase.expectedType, base.Network.Type)
			}

			if base.Network.Transport != testCase.expectedTransport {
				t.Errorf("expected transport %q, got %q", testCase.expectedTransport, base.Network.Transport)
			}

			if testCase.expectedSourceIp != "" {
				if base.Source == nil {
					t.Fatal("expected source to be set")
				}
				if base.Source.Ip != testCase.expectedSourceIp {
					t.Errorf("expected source ip %q, got %q", testCase.expectedSourceIp, base.Source.Ip)
				}
			}

			if testCase.expectedDestIp != "" {
				if base.Destination == nil {
					t.Fatal("expected destination to be set")
				}
				if base.Destination.Ip != testCase.expectedDestIp {
					t.Errorf("expected destination ip %q, got %q", testCase.expectedDestIp, base.Destination.Ip)
				}
			}
		})
	}
}

func TestEnrichWithNflogAttributeHook(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name         string
		hook         *uint8
		expectedHook string
		expectNil    bool
	}{
		{
			name:      "no hook leaves observer unset",
			hook:      nil,
			expectNil: true,
		},
		{
			name:         "prerouting",
			hook:         new(uint8(0)),
			expectedHook: "prerouting",
		},
		{
			name:         "input",
			hook:         new(uint8(1)),
			expectedHook: "input",
		},
		{
			name:         "forward",
			hook:         new(uint8(2)),
			expectedHook: "forward",
		},
		{
			name:         "output",
			hook:         new(uint8(3)),
			expectedHook: "output",
		},
		{
			name:         "postrouting",
			hook:         new(uint8(4)),
			expectedHook: "postrouting",
		},
		{
			name:         "unknown hook id leaves the name empty",
			hook:         new(uint8(9)),
			expectedHook: "",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			base := &schema.Base{}
			EnrichWithNflogAttribute(&nflog.Attribute{Hook: testCase.hook}, base)

			if testCase.expectNil {
				if base.Observer != nil {
					t.Errorf("expected no observer, got %+v", base.Observer)
				}
				return
			}

			if base.Observer == nil {
				t.Fatal("expected observer to be set")
			}

			if base.Observer.Hook != testCase.expectedHook {
				t.Errorf("expected hook %q, got %q", testCase.expectedHook, base.Observer.Hook)
			}
		})
	}
}

func TestEnrichWithNflogAttributeInterfaces(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name            string
		inDev           *uint32
		outDev          *uint32
		expectedIngress string
		expectedEgress  string
	}{
		{
			name:   "neither device",
			inDev:  nil,
			outDev: nil,
		},
		{
			name:            "ingress device id is recorded",
			inDev:           new(uint32(unresolvableInterfaceIndex)),
			expectedIngress: "2147483647",
		},
		{
			name:           "egress device id is recorded",
			outDev:         new(uint32(unresolvableInterfaceIndex)),
			expectedEgress: "2147483647",
		},
		{
			name:            "both devices",
			inDev:           new(uint32(unresolvableInterfaceIndex)),
			outDev:          new(uint32(unresolvableInterfaceIndex)),
			expectedIngress: "2147483647",
			expectedEgress:  "2147483647",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			base := &schema.Base{}
			EnrichWithNflogAttribute(
				&nflog.Attribute{InDev: testCase.inDev, OutDev: testCase.outDev},
				base,
			)

			if testCase.expectedIngress == "" && testCase.expectedEgress == "" {
				if base.Observer != nil {
					t.Errorf("expected no observer, got %+v", base.Observer)
				}
				return
			}

			if base.Observer == nil {
				t.Fatal("expected observer to be set")
			}

			assertInterfaceId(t, "ingress", ingressInterfaceId(base), testCase.expectedIngress)
			assertInterfaceId(t, "egress", egressInterfaceId(base), testCase.expectedEgress)
		})
	}
}

func TestEnrichWithNflogAttributePrefix(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name            string
		prefix          string
		hook            *uint8
		expectedRuleset string
		expectedName    string
		expectedAction  string
		expectedType    []string
		expectedOutcome string
		expectNoRule    bool
		expectNoEvent   bool
	}{
		{
			name:            "three part prefix carries its own ruleset",
			prefix:          "myruleset-myrule-A",
			expectedRuleset: "myruleset",
			expectedName:    "myrule",
			expectedAction:  ActionAccept,
			expectedType:    []string{"connection", "allowed"},
			expectedOutcome: "success",
		},
		{
			name:            "two part prefix takes the ruleset from the hook",
			prefix:          "myrule-D",
			hook:            new(uint8(2)),
			expectedRuleset: "forward",
			expectedName:    "myrule",
			expectedAction:  ActionDrop,
			expectedType:    []string{"connection", "denied"},
			expectedOutcome: "failure",
		},
		{
			name:            "reject action",
			prefix:          "myruleset-myrule-R",
			expectedRuleset: "myruleset",
			expectedName:    "myrule",
			expectedAction:  ActionReject,
			expectedType:    []string{"connection", "denied"},
			expectedOutcome: "failure",
		},
		{
			name:            "unknown action has no event type of its own",
			prefix:          "myruleset-myrule-U",
			expectedRuleset: "myruleset",
			expectedName:    "myrule",
			expectedAction:  ActionUnknown,
			expectedType:    []string{"connection"},
			expectedOutcome: "unknown",
		},
		{
			name:            "unrecognised action code leaves the event unset",
			prefix:          "myruleset-myrule-X",
			expectedRuleset: "myruleset",
			expectedName:    "myrule",
			expectNoEvent:   true,
		},
		{
			name:          "single part prefix is not parsed",
			prefix:        "myrule",
			expectNoRule:  true,
			expectNoEvent: true,
		},
		{
			// The rule name keeps the hyphens between the ruleset and the action code.
			name:            "four part prefix keeps a hyphenated rule name",
			prefix:          "myruleset-my-rule-A",
			expectedRuleset: "myruleset",
			expectedName:    "my-rule",
			expectedAction:  ActionAccept,
			expectedType:    []string{"connection", "allowed"},
			expectedOutcome: "success",
		},
		{
			name:            "many part prefix keeps every inner hyphen",
			prefix:          "myruleset-my-long-rule-name-D",
			expectedRuleset: "myruleset",
			expectedName:    "my-long-rule-name",
			expectedAction:  ActionDrop,
			expectedType:    []string{"connection", "denied"},
			expectedOutcome: "failure",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			base := &schema.Base{}
			EnrichWithNflogAttribute(
				&nflog.Attribute{Prefix: &testCase.prefix, Hook: testCase.hook},
				base,
			)

			if testCase.expectNoRule {
				if base.Rule != nil {
					t.Errorf("expected no rule, got %+v", base.Rule)
				}
			} else {
				if base.Rule == nil {
					t.Fatal("expected rule to be set")
				}
				if base.Rule.Ruleset != testCase.expectedRuleset {
					t.Errorf("expected ruleset %q, got %q", testCase.expectedRuleset, base.Rule.Ruleset)
				}
				if base.Rule.Name != testCase.expectedName {
					t.Errorf("expected rule name %q, got %q", testCase.expectedName, base.Rule.Name)
				}
			}

			if testCase.expectNoEvent {
				if base.Event != nil {
					t.Errorf("expected no event, got %+v", base.Event)
				}
				return
			}

			if base.Event == nil {
				t.Fatal("expected event to be set")
			}

			if base.Event.Kind != "event" {
				t.Errorf("expected kind 'event', got %q", base.Event.Kind)
			}

			if !slices.Equal(base.Event.Category, []string{"network"}) {
				t.Errorf("expected category [network], got %v", base.Event.Category)
			}

			if base.Event.Action != testCase.expectedAction {
				t.Errorf("expected action %q, got %q", testCase.expectedAction, base.Event.Action)
			}

			if !slices.Equal(base.Event.Type, testCase.expectedType) {
				t.Errorf("expected type %v, got %v", testCase.expectedType, base.Event.Type)
			}

			if base.Event.Outcome != testCase.expectedOutcome {
				t.Errorf("expected outcome %q, got %q", testCase.expectedOutcome, base.Event.Outcome)
			}
		})
	}
}

func TestEnrichWithNflogAttributeTwoPartPrefixRulesetByHook(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name            string
		hook            *uint8
		expectedRuleset string
	}{
		{name: "no hook leaves the ruleset empty", hook: nil, expectedRuleset: ""},
		{name: "prerouting", hook: new(uint8(0)), expectedRuleset: "prerouting"},
		{name: "input without an ingress interface", hook: new(uint8(1)), expectedRuleset: "input"},
		{name: "forward", hook: new(uint8(2)), expectedRuleset: "forward"},
		{name: "output without an egress interface", hook: new(uint8(3)), expectedRuleset: "output"},
		{name: "postrouting", hook: new(uint8(4)), expectedRuleset: "postrouting"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			prefix := "myrule-A"
			base := &schema.Base{}
			EnrichWithNflogAttribute(
				&nflog.Attribute{Prefix: &prefix, Hook: testCase.hook},
				base,
			)

			if base.Rule == nil {
				t.Fatal("expected rule to be set")
			}

			if base.Rule.Ruleset != testCase.expectedRuleset {
				t.Errorf("expected ruleset %q, got %q", testCase.expectedRuleset, base.Rule.Ruleset)
			}

			if base.Rule.Name != "myrule" {
				t.Errorf("expected rule name 'myrule', got %q", base.Rule.Name)
			}
		})
	}
}

func TestEnrichWithNflogAttributeCredentials(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name            string
		uid             *uint32
		gid             *uint32
		expectedUserId  string
		expectedGroupId string
	}{
		{
			name: "neither",
		},
		{
			name:           "root user id",
			uid:            new(uint32(0)),
			expectedUserId: "0",
		},
		{
			name:            "root group id",
			gid:             new(uint32(0)),
			expectedGroupId: "0",
		},
		{
			name:           "unresolvable user id still records the id",
			uid:            new(uint32(4294967294)),
			expectedUserId: "4294967294",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			base := &schema.Base{}
			EnrichWithNflogAttribute(&nflog.Attribute{UID: testCase.uid, GID: testCase.gid}, base)

			if testCase.expectedUserId == "" {
				if base.User != nil {
					t.Errorf("expected no user, got %+v", base.User)
				}
			} else {
				if base.User == nil {
					t.Fatal("expected user to be set")
				}
				if base.User.Id != testCase.expectedUserId {
					t.Errorf("expected user id %q, got %q", testCase.expectedUserId, base.User.Id)
				}
			}

			if testCase.expectedGroupId == "" {
				if base.Group != nil {
					t.Errorf("expected no group, got %+v", base.Group)
				}
				return
			}

			if base.Group == nil {
				t.Fatal("expected group to be set")
			}

			if base.Group.Id != testCase.expectedGroupId {
				t.Errorf("expected group id %q, got %q", testCase.expectedGroupId, base.Group.Id)
			}
		})
	}
}

func ingressInterfaceId(base *schema.Base) string {
	if base.Observer == nil || base.Observer.Ingress == nil || base.Observer.Ingress.Interface == nil {
		return ""
	}

	return base.Observer.Ingress.Interface.Id
}

func egressInterfaceId(base *schema.Base) string {
	if base.Observer == nil || base.Observer.Egress == nil || base.Observer.Egress.Interface == nil {
		return ""
	}

	return base.Observer.Egress.Interface.Id
}

func assertInterfaceId(t *testing.T, label string, actual string, expected string) {
	t.Helper()

	if actual != expected {
		t.Errorf("expected %s interface id %q, got %q", label, expected, actual)
	}
}
