package dasguardian

import (
	"fmt"
	"time"
)

// ClientStatus represents the execution status of a client
type ClientStatus int

const (
	StatusPending ClientStatus = iota
	StatusRunning
	StatusSuccess
	StatusFailed
)

func displayGrid(results []ClientResult) {
	// Clear screen and move cursor to top
	fmt.Print("\033[2J\033[H")

	fmt.Println("Consensus Clients Status:", time.Now().Format(time.RFC850))
	fmt.Println("===========================================================")

	const colWidth = 50
	const cols = 4

	for i := 0; i < len(results); i += cols {
		for j := 0; j < cols && i+j < len(results); j++ {
			client := results[i+j]
			status := getStatusDisplay(client.Status)
			clientName := client.ClientName
			if len(clientName) > 25 {
				clientName = clientName[:25] + "..."
			}
			fmt.Printf(" %-*s", colWidth, fmt.Sprintf("%s %s", status, clientName))
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
