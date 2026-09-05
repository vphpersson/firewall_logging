package firewall_logging

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/altshiftab/utils_go/pkg/schema"
	"github.com/florianl/go-nflog/v2"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/vphpersson/packet_logging/pkg/packet_logging"
)

const (
	ActionAccept  = "accept"
	ActionDrop    = "drop"
	ActionReject  = "reject"
	ActionUnknown = "unknown"
)

// From enum ip_conntrack_info in linux/netfilter/nf_conntrack_common.h. The
// reply values are the forward ones plus IP_CT_IS_REPLY (3), which is why
// established_reply and IP_CT_IS_REPLY share the value 3.
var conntrackInfoToState = map[uint32]string{
	0: "established",
	1: "related",
	2: "new",
	3: "established_reply",
	4: "related_reply",
}

const netfilterHookPostrouting = "postrouting"

var netfilterHookIdToName = map[uint8]string{
	0: "prerouting",
	1: "input",
	2: "forward",
	3: "output",
	4: "postrouting",
}

// nftables returns the custom nftables object on base, creating it on first
// use. Several unrelated attributes populate it, and each would otherwise
// repeat the same nil check.
func nftables(base *schema.Base) *schema.Nftables {
	if base.Nftables == nil {
		base.Nftables = &schema.Nftables{}
	}

	return base.Nftables
}

func EnrichWithNflogAttribute(nflogAttribute *nflog.Attribute, base *schema.Base) {
	if nflogAttribute == nil || base == nil {
		return
	}

	if timestamp := nflogAttribute.Timestamp; timestamp != nil {
		base.Timestamp = timestamp.UTC().Format(time.RFC3339Nano)
	}

	if payload := nflogAttribute.Payload; payload != nil && len(*payload) != 0 {
		layerType := layers.LayerTypeIPv4
		if (*payload)[0]>>4 == 6 {
			layerType = layers.LayerTypeIPv6
		}

		packet := gopacket.NewPacket(*payload, layerType, gopacket.Default)
		for _, layer := range packet.Layers() {
			packet_logging.EnrichFromLayer(base, layer)
		}
	}

	ecsObserver := base.Observer
	if ecsObserver == nil {
		ecsObserver = &schema.Observer{}
	}

	hook := nflogAttribute.Hook
	var hookName string
	if hook != nil {
		if name, ok := netfilterHookIdToName[*hook]; ok {
			hookName = name
			nftables(base).Hook = hookName
		}
	}

	ecsObserverIngress := ecsObserver.Ingress
	ecsObserverEgress := ecsObserver.Egress

	var ingressInterfaceName string
	if inDev := nflogAttribute.InDev; inDev != nil {
		if ecsObserverIngress == nil {
			ecsObserverIngress = &schema.ObserverIngressEgress{}
			ecsObserver.Ingress = ecsObserverIngress
		}

		inDevInt := int(*inDev)
		ingressInterfaceName = interfaceNameCache.get(inDevInt)

		ecsObserverIngress.Interface = &schema.Interface{Id: strconv.Itoa(inDevInt), Name: ingressInterfaceName}
	}

	var egressInterfaceName string
	if outDev := nflogAttribute.OutDev; outDev != nil {
		if ecsObserverEgress == nil {
			ecsObserverEgress = &schema.ObserverIngressEgress{}
			ecsObserver.Egress = ecsObserverEgress
		}

		outDevInt := int(*outDev)
		egressInterfaceName = interfaceNameCache.get(outDevInt)

		ecsObserverEgress.Interface = &schema.Interface{Id: strconv.Itoa(outDevInt), Name: egressInterfaceName}
	}

	if ecsObserverIngress != nil || ecsObserverEgress != nil {
		base.Observer = ecsObserver
	}

	// The frame's own source address, recorded as-is. It is the previous hop,
	// which is what NFULA_HWADDR means, and it is kept unconditionally because
	// the cases the on-link test below rejects are often the ones where it
	// matters most: a station spoofing another subnet, a DHCP client sending
	// from 0.0.0.0, a link-local or self-assigned host.
	if hardwareAddress := nflogAttribute.HwAddr; hardwareAddress != nil && len(*hardwareAddress) != 0 {
		frameAddress := net.HardwareAddr(*hardwareAddress).String()
		nftables(base).HwAddr = frameAddress

		// source.mac additionally claims the frame's sender IS the packet's
		// source, which holds only when that source is on the segment the
		// packet arrived on. Routed traffic carries the upstream router's
		// address, identical for every packet regardless of origin.
		//
		// Postrouting is excluded: it runs after srcnat, so base.Source.Ip may
		// be a NAT-rewritten address that happens to fall inside the ingress
		// prefix -- hairpin NAT would otherwise pair the client's MAC with the
		// firewall's own address.
		if inDev := nflogAttribute.InDev; inDev != nil && hookName != netfilterHookPostrouting {
			if ecsSource := base.Source; ecsSource != nil && ecsSource.Ip != "" {
				if sourceIsOnLink(int(*inDev), net.ParseIP(ecsSource.Ip)) {
					ecsSource.Mac = frameAddress
				}
			}
		}
	}

	// nflog's per-group sequence number. Gaps mean messages from this group were
	// lost between the kernel and here, which is otherwise silent. SeqGlobal
	// counts every group on the host, so a gap there need not be ours.
	if sequence := nflogAttribute.Seq; sequence != nil {
		ecsEvent := base.Event
		if ecsEvent == nil {
			ecsEvent = &schema.Event{}
			base.Event = ecsEvent
		}

		ecsEvent.Sequence = int(*sequence)
	}

	// What conntrack made of the packet as the rule logged it. The rule naming
	// convention asserts this ("...-new-A"); recording it makes the assertion
	// checkable instead.
	if conntrackInfo := nflogAttribute.CtInfo; conntrackInfo != nil {
		if state, ok := conntrackInfoToState[*conntrackInfo]; ok {
			nftables(base).ConntrackState = state
		}
	}

	// The nftables packet mark, which can decide routing without appearing
	// anywhere else in the log.
	if mark := nflogAttribute.Mark; mark != nil {
		markValue := *mark
		nftables(base).Mark = &markValue
	}

	prefix := nflogAttribute.Prefix
	if prefix != nil {
		prefixString := *prefix

		var actionCode string
		var ruleName string
		var ruleRuleset string

		prefixStringSplit := strings.Split(prefixString, "-")

		switch {
		case len(prefixStringSplit) < 2:
			// A prefix without an action code carries nothing to record.
		case len(prefixStringSplit) == 2:
			switch hookName {
			case "input":
				if ingressInterfaceName != "" {
					ruleRuleset = fmt.Sprintf("%s_%s", hookName, ingressInterfaceName)
				} else {
					ruleRuleset = hookName
				}
			case "output":
				if egressInterfaceName != "" {
					ruleRuleset = fmt.Sprintf("%s_%s", hookName, egressInterfaceName)
				} else {
					ruleRuleset = hookName
				}
			case "prerouting", "forward", "postrouting":
				ruleRuleset = hookName
			}

			ruleName = prefixStringSplit[0]
			actionCode = prefixStringSplit[1]
		default:
			// The ruleset is the first field and the action code the last, so
			// everything between them belongs to the rule name, which may
			// therefore contain hyphens of its own.
			lastIndex := len(prefixStringSplit) - 1
			ruleRuleset = prefixStringSplit[0]
			ruleName = strings.Join(prefixStringSplit[1:lastIndex], "-")
			actionCode = prefixStringSplit[lastIndex]
		}

		if ruleName != "" || ruleRuleset != "" {
			ecsRule := base.Rule
			if ecsRule == nil {
				ecsRule = &schema.Rule{}
				base.Rule = ecsRule
			}

			ecsRule.Ruleset = ruleRuleset
			ecsRule.Name = ruleName
		}

		eventAction, eventType, eventOutcome := "", "", ""
		switch actionCode {
		case "A":
			eventAction = ActionAccept
			eventType = "allowed"
			eventOutcome = "success"
		case "D":
			eventAction = ActionDrop
			eventType = "denied"
			eventOutcome = "failure"
		case "R":
			eventAction = ActionReject
			eventType = "denied"
			eventOutcome = "failure"
		case "U":
			eventAction = ActionUnknown
			eventType = ""
			eventOutcome = "unknown"
		}

		if eventAction != "" || eventType != "" {
			ecsEvent := base.Event
			if ecsEvent == nil {
				ecsEvent = &schema.Event{}
				base.Event = ecsEvent
			}

			eventTypeSlice := []string{"connection"}
			if eventType != "" {
				eventTypeSlice = append(eventTypeSlice, eventType)
			}

			ecsEvent.Kind = "event"
			ecsEvent.Category = []string{"network"}
			ecsEvent.Action = eventAction
			ecsEvent.Type = eventTypeSlice
			ecsEvent.Outcome = eventOutcome
		}
	}

	userId := nflogAttribute.UID
	if userId != nil {
		ecsUser := base.User
		if ecsUser == nil {
			ecsUser = &schema.User{}
			base.User = ecsUser
		}

		userIdString := strconv.Itoa(int(*userId))
		ecsUser.Id = userIdString
		if userName := userNameCache.get(userIdString); userName != "" {
			ecsUser.Name = userName
		}
	}

	groupId := nflogAttribute.GID
	if groupId != nil {
		ecsGroup := base.Group
		if ecsGroup == nil {
			ecsGroup = &schema.Group{}
			base.Group = ecsGroup
		}

		groupIdString := strconv.Itoa(int(*groupId))
		ecsGroup.Id = groupIdString
		if groupName := groupNameCache.get(groupIdString); groupName != "" {
			ecsGroup.Name = groupName
		}
	}
}
