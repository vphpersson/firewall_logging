package firewall_logging

import (
	"fmt"
	"net"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/Motmedel/utils_go/pkg/schema"
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

var netfilterHookIdToName = map[uint8]string{
	0: "prerouting",
	1: "input",
	2: "forward",
	3: "output",
	4: "postrouting",
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
			packet_logging.EnrichFromLayer(base, layer, packet)
		}
	}

	ecsObserver := base.Observer
	if ecsObserver == nil {
		ecsObserver = &schema.Observer{}
	}

	hook := nflogAttribute.Hook
	var hookName string
	if hook != nil {
		var ok bool
		if hookName, ok = netfilterHookIdToName[*hook]; ok {
			ecsObserver.Hook = hookName
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

		networkInterface, _ := net.InterfaceByIndex(inDevInt)
		if networkInterface != nil {
			ingressInterfaceName = networkInterface.Name
		}

		ecsObserverIngress.Interface = &schema.Interface{Id: strconv.Itoa(inDevInt), Name: ingressInterfaceName}
	}

	var egressInterfaceName string
	if outDev := nflogAttribute.OutDev; outDev != nil {
		if ecsObserverEgress == nil {
			ecsObserverEgress = &schema.ObserverIngressEgress{}
			ecsObserver.Egress = ecsObserverEgress
		}

		outDevInt := int(*outDev)

		networkInterface, _ := net.InterfaceByIndex(outDevInt)
		if networkInterface != nil {
			egressInterfaceName = networkInterface.Name
		}

		ecsObserverEgress.Interface = &schema.Interface{Id: strconv.Itoa(outDevInt), Name: egressInterfaceName}
	}

	if hook != nil || ecsObserverIngress != nil || ecsObserverEgress != nil {
		base.Observer = ecsObserver
	}

	prefix := nflogAttribute.Prefix
	if prefix != nil {
		prefixString := *prefix

		var actionCode string
		var ruleName string
		var ruleRuleset string

		prefixStringSplit := strings.Split(prefixString, "-")

		switch len(prefixStringSplit) {
		case 2:
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
		case 3:
			ruleRuleset = prefixStringSplit[0]
			ruleName = prefixStringSplit[1]
			actionCode = prefixStringSplit[2]
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

		eventAction, eventType := "", ""
		switch actionCode {
		case "A":
			eventAction = ActionAccept
			eventType = "allowed"
		case "D":
			eventAction = ActionDrop
			eventType = "denied"
		case "R":
			eventAction = ActionReject
			eventType = "denied"
		case "U":
			eventAction = ActionUnknown
			eventType = ""
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

			ecsEvent.Action = eventAction
			ecsEvent.Type = eventTypeSlice
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

		lookupUser, _ := user.LookupId(userIdString)
		if lookupUser != nil {
			ecsUser.Name = lookupUser.Username
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

		lookupGroup, _ := user.LookupGroupId(groupIdString)
		if lookupGroup != nil {
			ecsGroup.Name = lookupGroup.Name
		}
	}
}
