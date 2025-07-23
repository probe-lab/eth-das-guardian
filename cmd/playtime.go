package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/probe-lab/eth-das-guardian/dora"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

// ClientStatus represents the execution status of a client
type ClientStatus int

const (
	StatusPending ClientStatus = iota
	StatusRunning
	StatusSuccess
	StatusFailed
)

// ClientResult holds the result of processing a client
type ClientResult struct {
	DoraInfo dora.ConsensusClientNodeInfo
	Status   ClientStatus
	Error    error
}

var (
	gridMutex sync.RWMutex
	stopGrid  chan struct{}
)

var playTimeConfig = struct {
	Parallelism  int32
	DoraEndpoint string
	LogDir       string
}{
	Parallelism:  4,
	DoraEndpoint: "https://dora.fusaka-devnet-2.ethpandaops.io/api/",
	LogDir:       ".logs",
}

var cmdPlaytime = &cli.Command{
	Name:  "playtime",
	Usage: "Run monitor or scan commands on all consensus clients from Dora",
	Description: `Fetches all consensus clients from Dora API and runs the specified command
(monitor or scan) on each client in parallel.`,
	Arguments: []cli.Argument{&cli.StringArg{
		Name: "command",
	}},
	Flags: []cli.Flag{
		&cli.Int32Flag{
			Name:        "parallelism",
			Usage:       "Number of parallel executions",
			Value:       playTimeConfig.Parallelism,
			Destination: &playTimeConfig.Parallelism,
		},
		&cli.StringFlag{
			Name:        "dora-endpoint",
			Usage:       "HTTPs endpoint of the dora API",
			Value:       playTimeConfig.DoraEndpoint,
			Destination: &playTimeConfig.DoraEndpoint,
		},
		&cli.StringFlag{
			Name:        "log-dir",
			Usage:       "Directory to write log files",
			Value:       playTimeConfig.LogDir,
			Destination: &playTimeConfig.LogDir,
		},
	},
	Action: runPlaytime,
}

func runPlaytime(ctx context.Context, cmd *cli.Command) error {
	// logrus to keep the logs in the same folder
	if err := ensureLogPath(playTimeConfig.LogDir); err != nil {
		return fmt.Errorf("unable to create log-folder at %s - %w", playTimeConfig.LogDir, err)
	}

	mainLogsFile := playTimeConfig.LogDir + "/main.logs"
	f, err := os.OpenFile(mainLogsFile, os.O_CREATE|os.O_WRONLY, 0755)
	if err != nil {
		return err
	}
	defer f.Close()

	// init logrus to keep logs in the previously create folder
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetOutput(f)
	logrus.SetLevel(ParseLogLevel(rootConfig.LogLevel))

	doraApiCli, err := dora.NewClient(dora.ClientConfig{
		Endpoint:     playTimeConfig.DoraEndpoint,
		QueryTimeout: 10 * time.Second,
		Logger:       logrus.New(),
	})

	consensusClients, err := doraApiCli.GetConsensusClients(ctx)
	if err != nil {
		return err
	}

	if consensusClients.Count == 0 {
		logrus.Error("No clients found from Dora API")
		return nil
	}

	// Initialize client results
	results := make(map[string]*ClientResult)
	for _, client := range consensusClients.Clients {
		results[client.PeerID] = &ClientResult{
			DoraInfo: client,
			Status:   StatusPending,
		}
		logrus.WithFields(logrus.Fields{
			"client-name": client.ClientName,
			"version":     client.Version,
		}).Info("new consensus node")
	}

	// Start live grid updates
	stopGrid = make(chan struct{})
	go startLiveGridUpdates(results)

	// Display initial grid
	displayGrid(results)

	// process clients in parallel
	// TODO:

	// Stop live updates and display final grid
	close(stopGrid)
	displayGrid(results)

	if err != nil {
		return err
	}

	// Print summary
	printSummary(results)

	return nil
}

func ensureLogPath(path string) error {
	_, err := os.Stat(path)
	if err != nil {
		// only create the folder if it doesn't exists
		return os.Mkdir(path, 0755)
	} else {
		return err
	}
}

func startLiveGridUpdates(results map[string]*ClientResult) {
	ticker := time.NewTicker(500 * time.Millisecond) // Update every 500ms
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			displayGrid(results)
		case <-stopGrid:
			return
		}
	}
}

func executeScan(ctx context.Context, beaconURL, logFile string) error {
	// Create log file
	file, err := os.Create(logFile)
	if err != nil {
		return fmt.Errorf("failed to create log file: %w", err)
	}
	defer file.Close()

	// Create a logger that writes to the file
	logger := logrus.New()
	logger.SetOutput(file)

	// Create a context with timeout to prevent hanging
	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	// Call the scarusn function with the beacon URL
	// We need to temporarily override the global config for this execution
	originalEndpoint := rootConfig.BeaconAPIendpoint
	rootConfig.BeaconAPIendpoint = beaconURL
	defer func() {
		rootConfig.BeaconAPIendpoint = originalEndpoint
	}()

	// Create a fake CLI context to pass to the scan command
	return runScan(timeoutCtx, logger, file)
}

func runScan(ctx context.Context, logger *logrus.Logger, output io.Writer) error {
	// This should call your existing scan logic
	// You'll need to extract the actual logic from cmdScan.Action
	// and make it callable with custom parameters

	fmt.Fprintf(output, "Scan started for %s at %s\n", rootConfig.BeaconAPIendpoint, time.Now())

	// TODO: Replace this with actual scan logic
	// Example: return scan.Run(ctx, rootConfig, logger)

	// Simulate some work
	time.Sleep(1 * time.Second)

	fmt.Fprintf(output, "Scan completed for %s at %s\n", rootConfig.BeaconAPIendpoint, time.Now())
	return nil
}

func displayGrid(results map[string]*ClientResult) {
	gridMutex.RLock()
	defer gridMutex.RUnlock()

	// Clear screen and move cursor to top
	fmt.Print("\033[2J\033[H")

	fmt.Println("Consensus Clients Status:")
	fmt.Println("========================")

	const colWidth = 20
	const cols = 4

	clients := make([]*ClientResult, 0, len(results))
	for _, result := range results {
		clients = append(clients, result)
	}

	for i := 0; i < len(clients); i += cols {
		for j := 0; j < cols && i+j < len(clients); j++ {
			client := clients[i+j]
			status := getStatusDisplay(client.Status)
			clientName := client.DoraInfo.ClientName
			if len(clientName) > 15 {
				clientName = clientName[:15] + "..."
			}
			fmt.Printf("%-*s", colWidth, fmt.Sprintf("%s %s", status, clientName))
		}
		fmt.Println()
	}

	fmt.Println()
	fmt.Println("Legend: 🟡 Running, 🟢 Success, 🔴 Failed, ⚪ Pending")

	// Show current counts
	var pending, running, success, failed int
	for _, result := range results {
		switch result.Status {
		case StatusPending:
			pending++
		case StatusRunning:
			running++
		case StatusSuccess:
			success++
		case StatusFailed:
			failed++
		}
	}

	fmt.Printf("Status: %d pending, %d running, %d success, %d failed\n",
		pending, running, success, failed)
	fmt.Println()
}

func getStatusDisplay(status ClientStatus) string {
	switch status {
	case StatusPending:
		return "⚪"
	case StatusRunning:
		return "\033[33m🟡\033[0m" // Yellow
	case StatusSuccess:
		return "\033[32m🟢\033[0m" // Green
	case StatusFailed:
		return "\033[31m🔴\033[0m" // Red
	default:
		return "⚪"
	}
}

func printSummary(results map[string]*ClientResult) {
	var pending, running, success, failed int

	for _, result := range results {
		switch result.Status {
		case StatusPending:
			pending++
		case StatusRunning:
			running++
		case StatusSuccess:
			success++
		case StatusFailed:
			failed++
		}
	}

	fmt.Printf("\nFinal Summary: %d total, %d success, %d failed, %d pending, %d running\n",
		len(results), success, failed, pending, running)

	// Print failed clients with errors
	if failed > 0 {
		fmt.Println("\nFailed clients:")
		for _, result := range results {
			if result.Status == StatusFailed {
				fmt.Printf("  %s: %v\n", result.DoraInfo.ClientName, result.Error)
			}
		}
	}

	// Print successful clients
	if success > 0 {
		fmt.Println("\nSuccessful clients:")
		for _, result := range results {
			if result.Status == StatusSuccess {
				fmt.Printf("  %s: completed successfully\n", result.DoraInfo.ClientName)
			}
		}
	}
}

func configureGlobalLogger(logDir string) error {
	// logrus to keep the logs in the same folder
	if err := ensureLogPath(logDir); err != nil {
		return fmt.Errorf("unable to create log-folder at %s - %w", logDir, err)
	}

	mainLogsFile := logDir + "/main.logs"
	f, err := os.OpenFile(mainLogsFile, os.O_CREATE|os.O_WRONLY, 0755)
	if err != nil {
		return err
	}

	// init logrus to keep logs in the previously create folder
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetOutput(f)
	logrus.SetLevel(ParseLogLevel(rootConfig.LogLevel))
	return nil
}
