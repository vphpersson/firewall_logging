package main

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	argumentParserErrors "github.com/altshiftab/utils_go/pkg/cli/argument_parser/errors"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	"github.com/florianl/go-nflog/v2"
)

func TestParseGroup(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		arguments     []string
		expected      uint16
		expectedError error
	}{
		{
			name:      "long name",
			arguments: []string{"--group", "4"},
			expected:  4,
		},
		{
			name:      "long name with an attached value",
			arguments: []string{"--group=4"},
			expected:  4,
		},
		{
			name:      "short name",
			arguments: []string{"-g", "4"},
			expected:  4,
		},
		{
			name:      "short name with an attached value",
			arguments: []string{"-g4"},
			expected:  4,
		},
		{
			name:      "unambiguous long prefix",
			arguments: []string{"--gr", "4"},
			expected:  4,
		},
		{
			name:      "highest valid group",
			arguments: []string{"--group", "65535"},
			expected:  65535,
		},
		{
			name:          "missing required option",
			arguments:     nil,
			expectedError: argumentParserErrors.ErrMissingRequiredOption,
		},
		{
			name:          "zero is out of range",
			arguments:     []string{"--group", "0"},
			expectedError: altshiftErrors.ErrValidationError,
		},
		{
			name:          "negative is out of range",
			arguments:     []string{"--group", "-1"},
			expectedError: altshiftErrors.ErrValidationError,
		},
		{
			name:          "above the 16-bit range",
			arguments:     []string{"--group", "65536"},
			expectedError: altshiftErrors.ErrValidationError,
		},
		{
			name:          "help is reported as its own error",
			arguments:     []string{"--help"},
			expectedError: argumentParserErrors.ErrHelp,
		},
		{
			name:          "unknown option",
			arguments:     []string{"--nope", "1"},
			expectedError: argumentParserErrors.ErrNameNotFound,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			group, err := parseGroup(testCase.arguments, io.Discard)

			if testCase.expectedError != nil {
				if !errors.Is(err, testCase.expectedError) {
					t.Fatalf("expected error %v, got %v", testCase.expectedError, err)
				}
				return
			}

			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			if group != testCase.expected {
				t.Errorf("expected group %d, got %d", testCase.expected, group)
			}
		})
	}
}

func TestParseGroupWritesHelpToOutput(t *testing.T) {
	t.Parallel()

	var builder strings.Builder

	if _, err := parseGroup([]string{"--help"}, &builder); !errors.Is(err, argumentParserErrors.ErrHelp) {
		t.Fatalf("expected a help error, got %v", err)
	}

	help := builder.String()
	for _, expected := range []string{programName, "--group", "The NFLOG group to listen on."} {
		if !strings.Contains(help, expected) {
			t.Errorf("expected the help message to contain %q, got:\n%s", expected, help)
		}
	}
}

func TestMakeDocument(t *testing.T) {
	t.Parallel()

	fallbackTimestamp := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	attributeTimestamp := time.Date(2026, 8, 18, 6, 30, 0, 0, time.UTC)

	acceptPrefix := "myruleset-myrule-A"
	dropPrefix := "myruleset-myrule-D"
	unparsedPrefix := "myrule"

	testCases := []struct {
		name              string
		attribute         *nflog.Attribute
		expectedTimestamp string
		expectedMessage   string
		expectedAction    string
	}{
		{
			name:              "nil attribute still yields a dated document",
			attribute:         nil,
			expectedTimestamp: "2026-08-18T12:00:00Z",
			expectedMessage:   "(unknown)",
		},
		{
			name:              "empty attribute falls back to the supplied timestamp",
			attribute:         &nflog.Attribute{},
			expectedTimestamp: "2026-08-18T12:00:00Z",
			expectedMessage:   "(unknown)",
		},
		{
			name:              "attribute timestamp wins over the fallback",
			attribute:         &nflog.Attribute{Timestamp: &attributeTimestamp},
			expectedTimestamp: "2026-08-18T06:30:00Z",
			expectedMessage:   "(unknown)",
		},
		{
			name:              "rule and action are appended to the message",
			attribute:         &nflog.Attribute{Prefix: &acceptPrefix},
			expectedTimestamp: "2026-08-18T12:00:00Z",
			expectedMessage:   "(unknown) myruleset-myrule accept",
			expectedAction:    "accept",
		},
		{
			name:              "drop action",
			attribute:         &nflog.Attribute{Prefix: &dropPrefix},
			expectedTimestamp: "2026-08-18T12:00:00Z",
			expectedMessage:   "(unknown) myruleset-myrule drop",
			expectedAction:    "drop",
		},
		{
			name:              "unparsed prefix leaves the message without a rule suffix",
			attribute:         &nflog.Attribute{Prefix: &unparsedPrefix},
			expectedTimestamp: "2026-08-18T12:00:00Z",
			expectedMessage:   "(unknown)",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			document := makeDocument(testCase.attribute, fallbackTimestamp)

			if document.Timestamp != testCase.expectedTimestamp {
				t.Errorf("expected timestamp %q, got %q", testCase.expectedTimestamp, document.Timestamp)
			}

			if document.Message != testCase.expectedMessage {
				t.Errorf("expected message %q, got %q", testCase.expectedMessage, document.Message)
			}

			if document.Event == nil {
				t.Fatal("expected event to be set")
			}

			if document.Event.Dataset != dataset {
				t.Errorf("expected dataset %q, got %q", dataset, document.Event.Dataset)
			}

			if document.Event.Reason != reason {
				t.Errorf("expected reason %q, got %q", reason, document.Event.Reason)
			}

			if document.Event.Action != testCase.expectedAction {
				t.Errorf("expected action %q, got %q", testCase.expectedAction, document.Event.Action)
			}
		})
	}
}

func TestMakeDocumentEnrichesFromPayload(t *testing.T) {
	t.Parallel()

	payload := []byte{
		// IPv4 header: protocol 6 (TCP), 192.0.2.1 -> 198.51.100.2
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

	prefix := "myruleset-myrule-A"

	document := makeDocument(
		&nflog.Attribute{Payload: &payload, Prefix: &prefix},
		time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC),
	)

	expectedMessage := "192.0.2.1:54321 -> 198.51.100.2:443 tcp myruleset-myrule accept"
	if document.Message != expectedMessage {
		t.Errorf("expected message %q, got %q", expectedMessage, document.Message)
	}

	if document.Source == nil || document.Source.Ip != "192.0.2.1" || document.Source.Port != 54321 {
		t.Errorf("expected source 192.0.2.1:54321, got %+v", document.Source)
	}

	if document.Destination == nil || document.Destination.Ip != "198.51.100.2" || document.Destination.Port != 443 {
		t.Errorf("expected destination 198.51.100.2:443, got %+v", document.Destination)
	}
}

func TestNewLoggerWritesJson(t *testing.T) {
	t.Parallel()

	var builder strings.Builder

	logger := newLogger(&builder)
	logger.Info("test message")

	line := builder.String()
	for _, expected := range []string{`"message":"test message"`, `"dataset":"firewall_logging"`} {
		if !strings.Contains(line, expected) {
			t.Errorf("expected the log line to contain %s, got:\n%s", expected, line)
		}
	}
}
