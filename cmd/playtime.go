package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v3"
)

// DoraClient represents a consensus client from Dora API
type DoraClient struct {
	Name   string `json:"client_name"`
	Status string `json:"status"`
}

// DoraResponse represents the API response structure
type DoraResponse struct {
	Clients []DoraClient `json:"clients"`
}

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
	Client DoraClient
	Status ClientStatus
	Error  error
}

var (
	gridMutex sync.RWMutex
	stopGrid  chan struct{}
)

var cmdPlaytime = &cli.Command{
	Name:  "playtime",
	Usage: "Run monitor or scan commands on all consensus clients from Dora",
	Description: `Fetches all consensus clients from Dora API and runs the specified command 
(monitor or scan) on each client in parallel.`,
	Arguments: []cli.Argument{&cli.StringArg{
		Name: "command",
	}},
	Flags: []cli.Flag{
		&cli.IntFlag{
			Name:  "parallelism",
			Usage: "Number of parallel executions",
			Value: 4,
		},
		&cli.StringFlag{
			Name:  "network-name",
			Usage: " of parallel executions",
			Value: 4,
		},
		&cli.StringFlag{
			Name:  "log-dir",
			Usage: "Directory to write log files",
			Value: "./logs",
		},
		&cli.StringFlag{
			Name:     "auth-user",
			Usage:    "Authentication username",
			Required: true,
		},
		&cli.StringFlag{
			Name:     "auth-pass",
			Usage:    "Authentication password",
			Required: true,
		},
	},
	Action: runPlaytime,
}

func runPlaytime(ctx context.Context, cmd *cli.Command) error {
	args := cmd.Args().Slice()
	if len(args) != 1 {
		return fmt.Errorf("expected exactly one argument (monitor or scan), got %d", len(args))
	}

	command := args[0]
	if command != "monitor" && command != "scan" {
		return fmt.Errorf("invalid command: %s. Must be 'monitor' or 'scan'", command)
	}

	var (
		parallelism = cmd.Int("parallelism")
		logDir      = cmd.String("log-dir")
		authUser    = cmd.String("auth-user")
		authPass    = cmd.String("auth-pass") // Create log directory if it doesn't exist
	)

	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Fetch clients from Dora API
	clients, err := fetchDoraClients()
	if err != nil {
		return fmt.Errorf("failed to fetch clients from Dora: %w", err)
	}

	if len(clients) == 0 {
		fmt.Println("No clients found from Dora API")
		return nil
	}

	// Initialize client results
	results := make(map[string]*ClientResult)
	for _, client := range clients {
		results[client.ID] = &ClientResult{
			Client: client,
			Status: StatusPending,
		}
	}

	// Start live grid updates
	stopGrid = make(chan struct{})
	go startLiveGridUpdates(results)

	// Display initial grid
	displayGrid(results)

	// Process clients in parallel
	err = processClients(ctx, command, clients, results, parallelism, logDir, authUser, authPass)

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

func fetchDoraClients(devnet string) ([]DoraClient, error) {
	resp, err := http.Get("https://dora." + devnet + ".ethpandaops.io/api/v1/clients")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch from Dora API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dora API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var doraResp DoraResponse
	if err := json.Unmarshal(body, &doraResp); err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w", err)
	}

	return doraResp.Clients, nil
}

func processClients(ctx context.Context, command string, clients []DoraClient, results map[string]*ClientResult, parallelism int, logDir, authUser, authPass string) error {
	// Create a semaphore to limit parallelism
	semaphore := make(chan struct{}, parallelism)
	var wg sync.WaitGroup

	for _, client := range clients {
		wg.Add(1)
		go func(c DoraClient) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Update status to running
			gridMutex.Lock()
			results[c.Name].Status = StatusRunning
			gridMutex.Unlock()

			// Process the client
			err := processClient(ctx, command, c, logDir, authUser, authPass)

			// Update final status
			gridMutex.Lock()
			if err != nil {
				results[c.Name].Status = StatusFailed
				results[c.Name].Error = err
			} else {
				results[c.Name].Status = StatusSuccess
			}
			gridMutex.Unlock()
		}(client)
	}

	wg.Wait()
	return nil
}

func processClient(ctx context.Context, devnet string, command string, client DoraClient, logDir, authUser, authPass string) error {
	// Construct beacon node URL
	baseURL := fmt.Sprintf("https://bn.%s.%s.ethpandaops.io", client.Name, devnet)
	u, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("failed to parse base URL: %w", err)
	}

	// Add authentication
	u.User = url.UserPassword(authUser, authPass)

	beaconURL := u.String()

	// Create log file
	logFile := filepath.Join(logDir, fmt.Sprintf("%s.log", client.ID))

	// Execute the command based on type
	switch command {
	case "monitor":
		return executeMonitor(ctx, beaconURL, logFile)
	case "scan":
		return executeScan(ctx, beaconURL, logFile)
	default:
		return fmt.Errorf("unknown command: %s", command)
	}
}

func executeMonitor(ctx context.Context, beaconURL, logFile string) error {
	// Create log file
	file, err := os.Create(logFile)
	if err != nil {
		return fmt.Errorf("failed to create log file: %w", err)
	}
	defer file.Close()

	// Create a logger that writes to the file
	logger := log.New()
	logger.SetOutput(file)

	// Create a context with timeout to prevent hanging
	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	// Call the monitor function with the beacon URL
	// We need to temporarily override the global config for this execution
	originalEndpoint := rootConfig.BeaconAPIendpoint
	rootConfig.BeaconAPIendpoint = beaconURL
	defer func() {
		rootConfig.BeaconAPIendpoint = originalEndpoint
	}()

	// Create a fake CLI context to pass to the monitor command
	return runMonitor(timeoutCtx, logger, file)
}

func executeScan(ctx context.Context, beaconURL, logFile string) error {
	// Create log file
	file, err := os.Create(logFile)
	if err != nil {
		return fmt.Errorf("failed to create log file: %w", err)
	}
	defer file.Close()

	// Create a logger that writes to the file
	logger := log.New()
	logger.SetOutput(file)

	// Create a context with timeout to prevent hanging
	timeoutCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	// Call the scan function with the beacon URL
	// We need to temporarily override the global config for this execution
	originalEndpoint := rootConfig.BeaconAPIendpoint
	rootConfig.BeaconAPIendpoint = beaconURL
	defer func() {
		rootConfig.BeaconAPIendpoint = originalEndpoint
	}()

	// Create a fake CLI context to pass to the scan command
	return runScan(timeoutCtx, logger, file)
}

// These functions need to be implemented based on your existing monitor and scan commands
func runMonitor(ctx context.Context, logger *log.Logger, output io.Writer) error {
	// This should call your existing monitor logic
	// You'll need to extract the actual logic from cmdMonitor.Action
	// and make it callable with custom parameters

	fmt.Fprintf(output, "Monitor started for %s at %s\n", rootConfig.BeaconAPIendpoint, time.Now())

	// TODO: Replace this with actual monitor logic
	// Example: return monitor.Run(ctx, rootConfig, logger)

	// Simulate some work
	time.Sleep(2 * time.Second)

	fmt.Fprintf(output, "Monitor completed for %s at %s\n", rootConfig.BeaconAPIendpoint, time.Now())
	return nil
}

func runScan(ctx context.Context, logger *log.Logger, output io.Writer) error {
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
			clientName := client.Client.ID
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
				fmt.Printf("  %s: %v\n", result.Client.ID, result.Error)
			}
		}
	}

	// Print successful clients
	if success > 0 {
		fmt.Println("\nSuccessful clients:")
		for _, result := range results {
			if result.Status == StatusSuccess {
				fmt.Printf("  %s: completed successfully\n", result.Client.ID)
			}
		}
	}
}
