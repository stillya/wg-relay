package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jessevdk/go-flags"
	"github.com/pkg/errors"
	"github.com/stillya/wg-relay/pkg/api"
)

type GlobalOpts struct {
	SocketPath string `short:"s" long:"socket" description:"Unix socket path for daemon" default:"/var/run/wg-relay/control.sock"`
}

type EnableCmd struct {
	ConfigPath string `short:"c" long:"config" description:"Path to configuration file (uses agent's default if not specified)" default:""`
}

type DisableCmd struct{}

type ReloadCmd struct {
	ConfigPath string `short:"c" long:"config" description:"Path to configuration file (uses agent's default if not specified)" default:""`
}

type StatusCmd struct{}

type StatsCmd struct {
	Watch    bool          `short:"w" long:"watch" description:"Watch mode - continuously display stats"`
	Interval time.Duration `short:"i" long:"interval" description:"Update interval in watch mode" default:"5s"`
}

type VersionCmd struct{}

type Opts struct {
	GlobalOpts
	Enable  EnableCmd  `command:"enable" description:"Enable dataplane with config"`
	Disable DisableCmd `command:"disable" description:"Disable dataplane"`
	Reload  ReloadCmd  `command:"reload" description:"Reload dataplane with new config"`
	Status  StatusCmd  `command:"status" description:"Show dataplane status"`
	Stats   StatsCmd   `command:"stats" description:"Show traffic statistics"`
	Version VersionCmd `command:"version" description:"Show version information"`
}

const version = "0.1.0"

func main() {
	var opts Opts
	parser := flags.NewParser(&opts, flags.Default)

	_, err := parser.Parse()
	if err != nil {
		var flagsErr *flags.Error
		if errors.As(err, &flagsErr) {
			if errors.Is(flagsErr.Type, flags.ErrHelp) {
				os.Exit(0)
			}
			if errors.Is(flagsErr.Type, flags.ErrCommandRequired) {
				parser.WriteHelp(os.Stderr)
			}
		}
		os.Exit(1)
	}

	ctx := context.Background()
	client := api.NewClient(opts.SocketPath)
	printer := NewPrinter()

	switch parser.Active.Name {
	case "enable":
		if err := handleEnable(ctx, client, printer, &opts.Enable); err != nil {
			printer.Error("Error: %v\n", err)
			os.Exit(1)
		}

	case "disable":
		if err := handleDisable(ctx, client, printer); err != nil {
			printer.Error("Error: %v\n", err)
			os.Exit(1)
		}

	case "reload":
		if err := handleReload(ctx, client, printer, &opts.Reload); err != nil {
			printer.Error("Error: %v\n", err)
			os.Exit(1)
		}

	case "status":
		if err := handleStatus(ctx, client, printer); err != nil {
			printer.Error("Error: %v\n", err)
			os.Exit(1)
		}

	case "stats":
		if err := handleStats(ctx, client, printer, &opts.Stats); err != nil {
			printer.Error("Error: %v\n", err)
			os.Exit(1)
		}

	case "version":
		printer.Printf("wg-relay version %s\n", version)
	}
}

func handleEnable(ctx context.Context, client *api.Client, printer *Printer, cmd *EnableCmd) error {
	if cmd.ConfigPath != "" {
		if _, err := os.Stat(cmd.ConfigPath); os.IsNotExist(err) {
			return fmt.Errorf("config file not found: %s", cmd.ConfigPath)
		}
	}

	if err := client.Enable(ctx, cmd.ConfigPath); err != nil {
		return err
	}

	if cmd.ConfigPath != "" {
		printer.Printf("Dataplane enabled successfully with config: %s\n", cmd.ConfigPath)
	} else {
		printer.Print("Dataplane enabled successfully with default config")
	}
	return nil
}

func handleDisable(ctx context.Context, client *api.Client, printer *Printer) error {
	if err := client.Disable(ctx); err != nil {
		return err
	}

	printer.Print("Dataplane disabled successfully")
	return nil
}

func handleReload(ctx context.Context, client *api.Client, printer *Printer, cmd *ReloadCmd) error {
	if cmd.ConfigPath != "" {
		if _, err := os.Stat(cmd.ConfigPath); os.IsNotExist(err) {
			return fmt.Errorf("config file not found: %s", cmd.ConfigPath)
		}
	}

	if err := client.Reload(ctx, cmd.ConfigPath); err != nil {
		return err
	}

	if cmd.ConfigPath != "" {
		printer.Printf("Dataplane reloaded successfully with config: %s\n", cmd.ConfigPath)
	} else {
		printer.Print("Dataplane reloaded successfully with default config")
	}
	return nil
}

func handleStatus(ctx context.Context, client *api.Client, printer *Printer) error {
	status, err := client.Status(ctx)
	if err != nil {
		return err
	}

	printer.PrintStatus(status)
	return nil
}

func handleStats(ctx context.Context, client *api.Client, printer *Printer, cmd *StatsCmd) error {
	if cmd.Watch {
		return watchStats(ctx, client, printer, cmd.Interval)
	}

	return displayStats(ctx, client, printer)
}

func displayStats(ctx context.Context, client *api.Client, printer *Printer) error {
	stats, err := client.Stats(ctx)
	if err != nil {
		return err
	}

	printer.PrintStats(stats)
	return nil
}

func watchStats(ctx context.Context, client *api.Client, printer *Printer, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		printer.Print("\033c")

		if err := displayStats(ctx, client, printer); err != nil {
			return err
		}

		printer.Printf("Updating every %s. Press Ctrl+C to exit.\n", interval)

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
