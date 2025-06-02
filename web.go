package main

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sync"
	"time"

	pb "github.com/OffchainLabs/prysm/v6/proto/prysm/v1alpha1"
	"github.com/libp2p/go-libp2p/core/peer"
	log "github.com/sirupsen/logrus"
)

type WebConfig struct {
	APIEndpoint string   `json:"api_endpoint"`
	NodeKeys    []string `json:"node_keys"`
	Samples     uint64   `json:"samples,omitempty"`
}

type NodeScanResult struct {
	NodeKey       string                 `json:"node_key"`
	PeerID        string                 `json:"peer_id"`
	ENRCustody    uint64                 `json:"enr_custody"`
	CustodyGroups []uint64               `json:"custody_groups"`
	Libp2pInfo    map[string]interface{} `json:"libp2p_info"`
	BeaconStatus  map[string]interface{} `json:"beacon_status"`
	BeaconMeta    map[string]interface{} `json:"beacon_meta"`
	CustodyTable  [][]string             `json:"custody_table"`
	TableHeaders  []string               `json:"table_headers"`
	Error         string                 `json:"error,omitempty"`
	Duration      time.Duration          `json:"duration"`
}

type WebScanResponse struct {
	Results  []NodeScanResult `json:"results"`
	Duration time.Duration    `json:"duration"`
}

func startWebServer(port int) {
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/scan", handleScan)
	http.HandleFunc("/api/scan", handleAPIScan)

	log.Infof("Starting web server on port %d", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), nil))
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	tmpl := `<!DOCTYPE html>
<html>
<head>
    <title>Eth DAS Guardian Web UI</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; }
        input[type="text"], textarea { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        textarea { height: 120px; resize: vertical; }
        button { background-color: #007cba; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background-color: #005a8a; }
        button:disabled { background-color: #ccc; cursor: not-allowed; }
        .result { margin-top: 20px; }
        .node-result { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 4px; }
        .node-result.success { border-color: #28a745; }
        .node-result.error { border-color: #dc3545; }
        .info-section { margin: 10px 0; }
        .info-title { font-weight: bold; color: #007cba; margin-bottom: 5px; }
        .info-content { background-color: #f8f9fa; padding: 10px; border-radius: 4px; font-family: monospace; white-space: pre-wrap; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .loading { text-align: center; padding: 20px; }
        .status { margin: 10px 0; padding: 10px; border-radius: 4px; }
        .status.success { background-color: #d4edda; color: #155724; }
        .status.error { background-color: #f8d7da; color: #721c24; }
        .duration { font-size: 0.9em; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Eth DAS Guardian Web UI</h1>
        <p>Configure one API endpoint and multiple node keys to scan Ethereum DAS custody information.</p>

        <form id="scanForm">
            <div class="form-group">
                <label for="apiEndpoint">Beacon API Endpoint:</label>
                <input type="text" id="apiEndpoint" name="apiEndpoint" value="https://beacon.fusaka-devnet-0.ethpandaops.io/" placeholder="https://beacon.fusaka-devnet-0.ethpandaops.io/">
            </div>

            <div class="form-group">
                <label for="nodeKeys">Node Keys (ENRs, one per line):</label>
                <textarea id="nodeKeys" name="nodeKeys" placeholder="enr:-Oi4QJ..."></textarea>
            </div>

            <div class="form-group">
                <label for="numSlots">Number of Slots to Sample:</label>
                <input type="number" id="numSlots" name="numSlots" value="8" min="1" max="20" placeholder="8">
                <small style="color: #666;">Number of random slots to sample for DAS verification (1-20)</small>
            </div>

            <button type="submit" id="scanButton">Scan Nodes</button>
        </form>

        <div id="results" class="result"></div>
    </div>

    <script>
        document.getElementById('scanForm').addEventListener('submit', async function(e) {
            e.preventDefault();

            const scanButton = document.getElementById('scanButton');
            const results = document.getElementById('results');

            scanButton.disabled = true;
            scanButton.textContent = 'Scanning...';
            results.innerHTML = '<div class="loading">Scanning nodes...</div>';

            const apiEndpoint = document.getElementById('apiEndpoint').value.trim();
            const nodeKeysText = document.getElementById('nodeKeys').value.trim();
            const nodeKeys = nodeKeysText.split('\n').map(k => k.trim()).filter(k => k.length > 0);
            const numSlots = parseInt(document.getElementById('numSlots').value) || 8;

            if (!apiEndpoint || nodeKeys.length === 0) {
                results.innerHTML = '<div class="status error">Please provide both API endpoint and at least one node key.</div>';
                scanButton.disabled = false;
                scanButton.textContent = 'Scan Nodes';
                return;
            }

            if (numSlots < 1 || numSlots > 20) {
                results.innerHTML = '<div class="status error">Number of slots must be between 1 and 20.</div>';
                scanButton.disabled = false;
                scanButton.textContent = 'Scan Nodes';
                return;
            }

            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        api_endpoint: apiEndpoint,
                        node_keys: nodeKeys,
                        samples: numSlots
                    })
                });

                const data = await response.json();
                displayResults(data);
            } catch (error) {
                results.innerHTML = '<div class="status error">Error: ' + error.message + '</div>';
            }

            scanButton.disabled = false;
            scanButton.textContent = 'Scan Nodes';
        });

        function displayResults(data) {
            const results = document.getElementById('results');
            let html = '<h2>Scan Results</h2>';
            html += '<div class="duration">Total scan duration: ' + formatDuration(data.duration) + '</div>';

            data.results.forEach(result => {
                const isError = result.error && result.error.length > 0;
                html += '<div class="node-result ' + (isError ? 'error' : 'success') + '">';
                html += '<h3>Node: ' + truncateENR(result.node_key) + '</h3>';
                html += '<div class="duration">Duration: ' + formatDuration(result.duration) + '</div>';

                if (isError) {
                    html += '<div class="status error">Error: ' + result.error + '</div>';
                } else {
                    html += '<div class="info-section">';
                    html += '<div class="info-title">Peer Information</div>';
                    html += '<div class="info-content">Peer ID: ' + result.peer_id;
                    html += '\nENR Custody: ' + result.enr_custody;
                    html += '\nCustody Groups: [' + result.custody_groups.join(', ') + ']</div>';
                    html += '</div>';

                    if (result.libp2p_info) {
                        html += '<div class="info-section">';
                        html += '<div class="info-title">Libp2p Information</div>';
                        html += '<div class="info-content">' + formatJSON(result.libp2p_info) + '</div>';
                        html += '</div>';
                    }

                    if (result.beacon_status) {
                        html += '<div class="info-section">';
                        html += '<div class="info-title">Beacon Status</div>';
                        html += '<div class="info-content">' + formatJSON(result.beacon_status) + '</div>';
                        html += '</div>';
                    }

                    if (result.beacon_meta) {
                        html += '<div class="info-section">';
                        html += '<div class="info-title">Beacon Metadata</div>';
                        html += '<div class="info-content">' + formatJSON(result.beacon_meta) + '</div>';
                        html += '</div>';
                    }

                    if (result.custody_table && result.table_headers) {
                        html += '<div class="info-section">';
                        html += '<div class="info-title">Custody Summary</div>';
                        html += createTable(result.table_headers, result.custody_table);
                        html += '</div>';
                    }
                }

                html += '</div>';
            });

            results.innerHTML = html;
        }

        function formatJSON(obj) {
            return JSON.stringify(obj, null, 2);
        }

        function createTable(headers, rows) {
            let html = '<table>';
            html += '<thead><tr>';
            headers.forEach(header => {
                html += '<th>' + header + '</th>';
            });
            html += '</tr></thead><tbody>';

            rows.forEach(row => {
                html += '<tr>';
                row.forEach(cell => {
                    html += '<td>' + cell + '</td>';
                });
                html += '</tr>';
            });

            html += '</tbody></table>';
            return html;
        }

        function truncateENR(enr) {
            if (enr.length > 50) {
                return enr.substring(0, 47) + '...';
            }
            return enr;
        }

        function formatDuration(nanoseconds) {
            const ms = nanoseconds / 1000000;
            if (ms < 1000) {
                return ms.toFixed(1) + 'ms';
            }
            return (ms / 1000).toFixed(1) + 's';
        }
    </script>
</body>
</html>`

	t, err := template.New("index").Parse(tmpl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html")
	t.Execute(w, nil)
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	// Redirect to index
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleAPIScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var config WebConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	if config.APIEndpoint == "" || len(config.NodeKeys) == 0 {
		http.Error(w, "API endpoint and node keys are required", http.StatusBadRequest)
		return
	}

	startTime := time.Now()

	// Scan all nodes in parallel
	var wg sync.WaitGroup
	results := make([]NodeScanResult, len(config.NodeKeys))

	for i, nodeKey := range config.NodeKeys {
		wg.Add(1)
		go func(index int, key string) {
			defer wg.Done()
			samples := config.Samples
			if samples == 0 {
				samples = Samples // Use default if not specified
			}
			results[index] = scanSingleNode(config.APIEndpoint, key, samples)
		}(i, nodeKey)
	}

	wg.Wait()

	response := WebScanResponse{
		Results:  results,
		Duration: time.Since(startTime),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func scanSingleNode(apiEndpoint, nodeKey string, samples uint64) NodeScanResult {
	startTime := time.Now()
	result := NodeScanResult{
		NodeKey:  nodeKey,
		Duration: 0,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Parse the node
	ethNode, err := parseNode(nodeKey)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to parse ENR: %v", err)
		result.Duration = time.Since(startTime)
		return result
	}

	// Create DAS Guardian instance
	ethConfig := &DasGuardianConfig{
		Libp2pHost:        "127.0.0.1",
		Libp2pPort:        int(9013 + (time.Now().UnixNano() % 1000)), // Randomize port to avoid conflicts
		ConnectionRetries: 3,
		ConnectionTimeout: 30 * time.Second,
		BeaconAPIendpoint: apiEndpoint,
	}

	guardian, err := NewDASGuardian(ctx, ethConfig)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to create DAS Guardian: %v", err)
		result.Duration = time.Since(startTime)
		return result
	}
	defer guardian.host.Close()

	// Extract custody information from ENR
	enrCustody, err := GetCustodyFromEnr(ethNode)
	if err != nil {
		log.Warnf("Failed to get custody from ENR for %s: %v", truncateStr(nodeKey, 24), err)
		enrCustody = 0
	}

	enrCustodyGroups, err := CustodyColumnsSlice(ethNode.ID(), enrCustody, DataColumnSidecarSubnetCount, DataColumnSidecarSubnetCount)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to compute custody groups: %v", err)
		result.Duration = time.Since(startTime)
		return result
	}

	result.ENRCustody = enrCustody
	result.CustodyGroups = enrCustodyGroups

	// Get peer address info
	enodeAddr, err := parseMaddrFromEnode(ethNode)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to parse multiaddr: %v", err)
		result.Duration = time.Since(startTime)
		return result
	}

	result.PeerID = enodeAddr.ID.String()

	// Connect to the node
	if err := guardian.ConnectNode(ctx, enodeAddr); err != nil {
		result.Error = fmt.Sprintf("Failed to connect to node: %v", err)
		result.Duration = time.Since(startTime)
		return result
	}

	// Extract libp2p information
	result.Libp2pInfo = guardian.libp2pPeerInfo(enodeAddr.ID)

	// Get beacon status
	remoteStatus := guardian.requestBeaconStatus(ctx, enodeAddr.ID)
	if remoteStatus != nil {
		result.BeaconStatus = guardian.visualizeBeaconStatus(remoteStatus)
	}

	// Get beacon metadata
	remoteMetadata := guardian.requestBeaconMetadata(ctx, enodeAddr.ID)
	if remoteMetadata != nil {
		result.BeaconMeta = guardian.visualizeBeaconMetadata(remoteMetadata)

		// Check custody mismatch
		if enrCustody != remoteMetadata.CustodyGroupCount {
			if result.BeaconMeta == nil {
				result.BeaconMeta = make(map[string]interface{})
			}
			result.BeaconMeta["custody_mismatch"] = fmt.Sprintf("ENR: %d, Metadata: %d", enrCustody, remoteMetadata.CustodyGroupCount)
		}

		// Perform DAS sampling
		if remoteStatus != nil {
			metadataCustodyIdxs, err := CustodyColumnsSlice(ethNode.ID(), remoteMetadata.CustodyGroupCount, DataColumnSidecarSubnetCount, DataColumnSidecarSubnetCount)
			if err == nil {
				table, headers := performDASCheck(ctx, guardian, remoteStatus, metadataCustodyIdxs, enodeAddr.ID, samples)
				result.CustodyTable = table
				result.TableHeaders = headers
			}
		}
	}

	result.Duration = time.Since(startTime)
	return result
}

func performDASCheck(ctx context.Context, guardian *DasGuardian, status *pb.Status, custodyIdxs []uint64, peerID peer.ID, samples uint64) ([][]string, []string) {
	// Select random slots for sampling
	randomSlots := guardian.selectRandomSlotsForRange(
		uint64(status.HeadSlot),
		samples,
		CustodySlots,
	)

	log.Infof("Selected random slots: %v (head slot: %d)", randomSlots, status.HeadSlot)

	// Filter out any zero slots that might have been generated due to logic issues
	validSlots := make([]uint64, 0, len(randomSlots))
	for _, slot := range randomSlots {
		if slot > 0 {
			validSlots = append(validSlots, slot)
		}
	}

	if len(validSlots) == 0 {
		log.Warnf("No valid slots generated, using recent slots as fallback")
		// Fallback: use some recent slots relative to head
		headSlot := uint64(status.HeadSlot)
		for i := uint64(1); i <= samples && i <= headSlot; i++ {
			if headSlot >= i {
				validSlots = append(validSlots, headSlot-i)
			}
		}
	}

	log.Infof("Using valid slots: %v", validSlots)

	// Get blocks for the selected slots
	bBlocks, err := guardian.fetchSlotBlocks(ctx, validSlots)
	if err != nil {
		log.Warnf("Failed to fetch slot blocks: %v", err)
		return nil, nil
	}

	// Get data columns from the peer
	dataCols, err := guardian.getDataColumnForSlotAndSubnet(ctx, peerID, validSlots, custodyIdxs)
	if err != nil {
		log.Warnf("Failed to get data columns: %v", err)
		return nil, nil
	}

	// Build table similar to evaluateColumnResponses but return data instead of printing
	headers := make([]string, 1+len(custodyIdxs))
	headers[0] = "Slot"
	for i, idx := range custodyIdxs {
		headers[i+1] = fmt.Sprintf("Col [%d]", idx)
	}

	rows := [][]string{}
	for s, slot := range validSlots {
		row := make([]string, 1+len(custodyIdxs))
		row[0] = fmt.Sprintf("%d", slot)

		if len(dataCols) <= s || len(dataCols[s]) == 0 {
			for i := range custodyIdxs {
				row[i+1] = "x"
			}
		} else {
			for c, dataCol := range dataCols[s] {
				if c < len(custodyIdxs) && len(bBlocks) > s {
					blobKzgCommitments := bBlocks[s].Data.Message.Body.BlobKZGCommitments
					blobCount := len(blobKzgCommitments)

					validCommit := 0
					for _, colCom := range dataCol.KzgCommitments {
						for _, kzgCom := range blobKzgCommitments {
							if compareBytes(colCom, kzgCom[:]) {
								validCommit++
							}
						}
					}

					row[c+1] = fmt.Sprintf(
						"blobs (%d/%d) / kzg-cmts (%d/%d/%d)",
						len(dataCol.Column), blobCount,
						validCommit, len(dataCol.KzgCommitments), blobCount,
					)
				} else if c < len(custodyIdxs) {
					row[c+1] = "x"
				}
			}
		}
		rows = append(rows, row)
	}

	return rows, headers
}
