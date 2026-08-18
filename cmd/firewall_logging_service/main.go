package main

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"os/signal"
	"syscall"
	"time"

	argumentParser "github.com/altshiftab/utils_go/pkg/cli/argument_parser"
	argumentParserErrors "github.com/altshiftab/utils_go/pkg/cli/argument_parser/errors"
	"github.com/altshiftab/utils_go/pkg/cli/argument_parser/option"
	altshiftErrors "github.com/altshiftab/utils_go/pkg/errors"
	altshiftLog "github.com/altshiftab/utils_go/pkg/log"
	altshiftErrorLogger "github.com/altshiftab/utils_go/pkg/log/error_logger"
	"github.com/altshiftab/utils_go/pkg/schema"
	schemaLog "github.com/altshiftab/utils_go/pkg/schema/log"
	"github.com/florianl/go-nflog/v2"
	"github.com/mdlayher/netlink"
	"github.com/vphpersson/firewall_logging/pkg/firewall_logging"
)

const (
	dataset     = "firewall_logging"
	programName = "firewall_logging_service"
	description = "Read packets from an NFLOG group and write them to standard output as ECS documents."
	reason      = "A packet matched a firewall logging rule."
)

const exitError = 1

// newLogger makes the logger the service writes its own diagnostics with, in the
// same ECS shape as the documents it emits.
func newLogger(writer io.Writer) *altshiftErrorLogger.Logger {
	return &altshiftErrorLogger.Logger{
		Logger: slog.New(
			&altshiftLog.ContextHandler{
				Next: slog.NewJSONHandler(
					writer,
					&slog.HandlerOptions{
						AddSource:   false,
						Level:       slog.LevelInfo,
						ReplaceAttr: schemaLog.ReplaceAttr,
					},
				),
				Extractors: []altshiftLog.ContextExtractor{
					&altshiftLog.ErrorContextExtractor{},
				},
			},
		).With(slog.Group("event", slog.String("dataset", dataset))),
	}
}

// parseGroup reads the NFLOG group to listen on from the command line, writing
// any help message to output. An argumentParserErrors.ErrHelp error means help
// was requested and answered.
func parseGroup(arguments []string, output io.Writer) (uint16, error) {
	var group int

	parser := &argumentParser.Parser{
		ProgramName: programName,
		Description: description,
		Output:      output,
		Options: []option.Option{
			option.NewIntOption('g', "group", "The NFLOG group to listen on.", true, &group),
		},
	}

	if err := parser.Validate(); err != nil {
		return 0, altshiftErrors.New(fmt.Errorf("parser validate: %w", err))
	}

	if err := parser.ParseArgs(arguments); err != nil {
		return 0, altshiftErrors.New(fmt.Errorf("parse args: %w", err), arguments)
	}

	if group <= 0 || group > math.MaxUint16 {
		return 0, altshiftErrors.NewWithTrace(
			fmt.Errorf("%w: group outside the range 1-%d: %d", altshiftErrors.ErrValidationError, math.MaxUint16, group),
			group,
		)
	}

	return uint16(group), nil
}

// makeDocument turns an NFLOG attribute into the ECS document written to standard
// output. timestamp is used only when the attribute carries none of its own.
func makeDocument(attribute *nflog.Attribute, timestamp time.Time) *schema.Base {
	document := &schema.Base{Event: &schema.Event{Dataset: dataset, Reason: reason}}

	firewall_logging.EnrichWithNflogAttribute(attribute, document)

	if document.Timestamp == "" {
		document.Timestamp = timestamp.UTC().Format(time.RFC3339Nano)
	}

	document.Message = document.MakeConnectionMessage()
	if ecsRule := document.Rule; ecsRule != nil {
		document.Message += fmt.Sprintf(" %s-%s", ecsRule.Ruleset, ecsRule.Name)
		if ecsEvent := document.Event; ecsEvent != nil && ecsEvent.Action != "" {
			document.Message += " " + ecsEvent.Action
		}
	}

	return document
}

func main() {
	logger := newLogger(os.Stdout)
	slog.SetDefault(logger.Logger)

	var arguments []string
	if osArgs := os.Args; len(osArgs) > 1 {
		arguments = osArgs[1:]
	}

	group, err := parseGroup(arguments, os.Stdout)
	if err != nil {
		// Help is an answer to an explicit request, not a failure.
		if errors.Is(err, argumentParserErrors.ErrHelp) {
			return
		}

		fmt.Fprintf(os.Stderr, "%s: %v\n", programName, err)
		os.Exit(exitError)
	}

	netfilterLogHandler, err := nflog.Open(&nflog.Config{Group: group, Copymode: nflog.CopyPacket})
	if err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when opening a connection to the Netfilter log system",
			altshiftErrors.NewWithTrace(fmt.Errorf("nflog open: %w", err), group),
		)
	}
	defer func() {
		if err := netfilterLogHandler.Close(); err != nil {
			logger.Warning(
				"An error occurred when closing the netfilter log handler.",
				altshiftErrors.NewWithTrace(fmt.Errorf("nflog close: %w", err), netfilterLogHandler),
			)
		}
	}()

	// Avoid receiving ENOBUFS errors.
	if err := netfilterLogHandler.SetOption(netlink.NoENOBUFS, true); err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when setting the NoENOBUFS Netlink option.",
			altshiftErrors.NewWithTrace(fmt.Errorf("netlink set option: %w", err)),
		)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err = netfilterLogHandler.RegisterWithErrorFunc(
		ctx,
		func(attrs nflog.Attribute) int {
			document := makeDocument(&attrs, time.Now())

			documentData, err := json.Marshal(document)
			if err != nil {
				logger.Error(
					"An error occurred when marshalling a document. Skipping.",
					altshiftErrors.NewWithTrace(fmt.Errorf("json marshal: %w", err), document),
				)
				return 0
			}

			if _, err := os.Stdout.Write(append(documentData, '\n')); err != nil {
				logger.Error(
					"An error occurred when writing a document to stdout.",
					altshiftErrors.NewWithTrace(fmt.Errorf("os stdout write: %w", err)),
				)
			}

			return 0
		},
		func(err error) int {
			logger.Error("An error occurred when receiving from the Netfilter log handler.", err)
			return 0
		},
	)
	if err != nil {
		logger.FatalWithExitingMessage(
			"An error occurred when registering Netfilter hook functions.",
			altshiftErrors.NewWithTrace(
				fmt.Errorf("nflog register with err func: %w", err),
				netfilterLogHandler,
			),
		)
	}

	<-ctx.Done()
}
