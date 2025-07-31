package dasguardian

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/pkg/errors"
	"github.com/probe-lab/eth-das-guardian/dora"
	"github.com/sirupsen/logrus"
)

// ClientResult holds the result of processing a client
type ClientResult struct {
	ClientName string
	Status     ClientStatus
	Error      error
}

type DevnetScannerConfig struct {
	// log config
	LogLevel  logrus.Level
	LogFormat logrus.Formatter
	LogDir    string

	// variables
	Parallelism             int32
	DoraApiEndpoint         string
	BeaconApiEndpoint       string
	ScanFreq                time.Duration
	DryScan                 bool
	FilterClientsContaining string
}

type DevnetScanner struct {
	// config
	cfg      DevnetScannerConfig
	mainLog  *logrus.Logger
	mainLogF *os.File

	// Dora API
	DoraApi *dora.Client

	// client data
	ClClients map[string]*clientMonitor
}

func NewDevnetScanner(cfg DevnetScannerConfig) (*DevnetScanner, error) {
	return &DevnetScanner{
		cfg:       cfg,
		ClClients: make(map[string]*clientMonitor),
	}, nil
}

func (s *DevnetScanner) Start(ctx context.Context) error {
	if err := s.init(ctx); err != nil {
		return err
	}
	defer s.close()

	networkScan := func(scanCtx context.Context) error {
		results, err := s.scanClients(scanCtx)
		if err != nil {
			return err
		}
		displayGrid(results)
		return nil
	}

	err := networkScan(ctx)
	if err != nil || s.cfg.DryScan {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(s.cfg.ScanFreq):
			err := networkScan(ctx)
			if err != nil {
				return err
			}
		}
	}
}

func (s *DevnetScanner) close() error {
	// close the file descriptors
	// TODO: iter through each of the indv loggers per client
	err := s.mainLogF.Close()
	if err != nil {
		logrus.Error(errors.Wrap(err, "closing main logger"))
	}
	for _, clMonitor := range s.ClClients {
		if err := clMonitor.loggerF.Close(); err != nil {
			logrus.Error(errors.Wrap(err, "closing main logger for "+clMonitor.nodeInfo.ClientName))
		}
	}
	return nil
}

func (s *DevnetScanner) init(ctx context.Context) error {
	// configure main logger
	err := s.configureLoggers(s.cfg.LogDir)
	if err != nil {
		return errors.Wrap(err, "configuring the loggers")
	}
	s.mainLog, s.mainLogF, err = s.newLogger("main.logs")
	if err != nil {
		return errors.Wrap(err, "creating main logger")
	}

	s.mainLog.WithFields(logrus.Fields{
		"log-level":   s.cfg.LogLevel.String(),
		"log-dir":     s.cfg.LogDir,
		"parellelism": s.cfg.Parallelism,
		"dora-api":    s.cfg.DoraApiEndpoint,
		"beacon-api":  s.cfg.BeaconApiEndpoint,
		"scan-freq":   s.cfg.ScanFreq,
		"dry-scan":    s.cfg.DryScan,
	}).Info("starting devnet scanner...")

	// create new API client for Dora
	s.DoraApi, err = dora.NewClient(dora.ClientConfig{
		Endpoint:     s.cfg.DoraApiEndpoint,
		QueryTimeout: 10 * time.Second, // TODO: hardcoded
		Logger:       s.mainLog,
	})
	if err != nil {
		return err
	}

	// get the whole list of clients from the Dora API
	consensusClients, err := s.DoraApi.GetConsensusClients(ctx)
	if err != nil {
		return err
	}
	if consensusClients.Count == 0 {
		logrus.Error("No clients found from Dora API")
		return nil
	}

	if s.cfg.FilterClientsContaining != "" {
		consensusClients = filterClClients(consensusClients, s.cfg.FilterClientsContaining)
	}

	// Initialize client results
	for _, client := range consensusClients.Clients {
		clLogger, logF, err := s.newLogger(fmt.Sprintf("%s.logs", client.ClientName))
		if err != nil {
			return err
		}

		guardianCfg := &DasGuardianConfig{
			Logger:                  clLogger,
			Libp2pHost:              "127.0.0.1",
			Libp2pPort:              9020,
			ConnectionRetries:       3,
			ConnectionTimeout:       10 * time.Second,
			BeaconAPIendpoint:       s.cfg.BeaconApiEndpoint,
			BeaconAPIcustomClClient: "",
			WaitForFulu:             false,
			InitTimeout:             20 * time.Second,
		}
		clClientMonitor, err := newClientMonitor(ctx, guardianCfg, logF, client)
		if err != nil {
			return err
		}
		s.ClClients[client.ClientName] = clClientMonitor
		s.mainLog.WithFields(logrus.Fields{
			"client-name": client.ClientName,
			"version":     client.Version,
		}).Debug("new consensus node")
	}
	s.mainLog.WithFields(logrus.Fields{
		"clients": len(s.ClClients),
	}).Info("reply from Dora to indentify participants")
	return nil
}

func ensureLogPath(path string) error {
	_, err := os.Stat(path)
	if err != nil {
		// only create the folder if it doesn't exists
		return os.Mkdir(path, 0o755)
	} else {
		return err
	}
}

func (s *DevnetScanner) scanClients(ctx context.Context) ([]ClientResult, error) {
	var m sync.Mutex
	numClients := len(s.ClClients)
	clientResults := make([]ClientResult, 0, numClients)
	clientC := make(chan string, s.cfg.Parallelism)
	var wg sync.WaitGroup

	// spawn the consumers
	for i := int32(0); i < s.cfg.Parallelism; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case clName, ok := <-clientC:
					if !ok {
						return
					}
					clientMonitor, ok := s.ClClients[clName]
					if !ok {
						s.mainLog.Panicf("couldn't finde a client-monitor ready item for %s", clName)
					}
					res := clientMonitor.scanClient(ctx, 5) // TODO: hardcoded
					m.Lock()
					clientResults = append(clientResults, res)
					m.Unlock()
				}
			}
		}()
	}

	i := 0
orchester:
	for clName, clientM := range s.ClClients {
		select {
		case clientC <- clName:
			i++
			s.mainLog.WithFields(logrus.Fields{
				"client-name": clName,
				"version":     clientM.nodeInfo.Version,
				"indes":       fmt.Sprintf("node: %d/%d", i, numClients),
			}).Info("scanning node...")
			// pass
		case <-ctx.Done():
			break orchester
		}
	}
	close(clientC)
	wg.Wait()
	return clientResults, nil
}

func (s *DevnetScanner) configureLoggers(logDir string) error {
	return ensureLogPath(logDir)
}

func (s *DevnetScanner) newLogger(fPath string) (*logrus.Logger, *os.File, error) {
	log := logrus.New()
	f, err := os.OpenFile(s.cfg.LogDir+"/"+fPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o755)
	if err != nil {
		return nil, nil, err
	}
	log.SetFormatter(&logrus.JSONFormatter{})
	log.SetOutput(f)
	log.SetLevel(s.cfg.LogLevel)
	return log, f, nil
}

type clientMonitor struct {
	// main
	guardianCfg *DasGuardianConfig
	logger      *logrus.Logger
	loggerF     *os.File

	// client info
	nodeInfo dora.ConsensusClientNodeInfo
	ethNode  *enode.Node

	// results
	lastResult ClientResult
}

func newClientMonitor(ctx context.Context, guardianCfg *DasGuardianConfig, logF *os.File, nodeInfo dora.ConsensusClientNodeInfo) (*clientMonitor, error) {
	ethNode, err := ParseNode(nodeInfo.ENR)
	if err != nil {
		return nil, err
	}
	return &clientMonitor{
		// main
		guardianCfg: guardianCfg,
		logger:      guardianCfg.Logger,
		loggerF:     logF,
		// info
		nodeInfo: nodeInfo,
		ethNode:  ethNode,
		// results
		lastResult: ClientResult{},
	}, nil
}

func (m *clientMonitor) scanClient(ctx context.Context, slots int32) ClientResult {
	result := ClientResult{
		ClientName: m.nodeInfo.ClientName,
		Status:     StatusRunning,
		Error:      nil,
	}
	// create a new DASGuardian instance on each scan
	guardian, err := NewDASGuardian(ctx, m.guardianCfg)
	if err != nil {
		result.Status = StatusFailed
		result.Error = err
		return result
	}
	defer guardian.Close()
	scanResult, err := guardian.Scan(ctx, m.ethNode, WithRandomAvailableSlots(slots))
	if err != nil {
		result.Status = StatusFailed
		result.Error = err
		return result
	}
	scanResult.EvalResult.LogVisualization(m.logger)

	if scanResult.EvalResult.Error != nil {
		result.Status = StatusFailed
		result.Error = err
		return result
	}

	// make sure that the resutls are correct
	// check the number of columns
	for i, validSlot := range scanResult.EvalResult.ValidSlot {
		if !validSlot {
			result.Status = StatusFailed
			result.Error = fmt.Errorf("slot %d was invalid", scanResult.EvalResult.Slots[i])
			return result
		}
	}
	result.Status = StatusSuccess
	result.Error = nil
	return result
}

func filterClClients(clients *dora.ConsensusClientsResponse, subString string) *dora.ConsensusClientsResponse {
	filteredClients := new(dora.ConsensusClientsResponse)
	for _, client := range clients.Clients {
		if strings.Contains(strings.ToLower(client.ClientName), subString) {
			filteredClients.Clients = append(filteredClients.Clients, client)
			filteredClients.Count++
		}
	}
	return filteredClients
}
