package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Colors for terminal output
const (
	ColorRed    = "\033[0;31m"
	ColorGreen  = "\033[0;32m"
	ColorYellow = "\033[1;33m"
	ColorBlue   = "\033[0;34m"
	ColorPurple = "\033[0;35m"
	ColorCyan   = "\033[0;36m"
	ColorWhite  = "\033[1;37m"
	ColorGray   = "\033[0;90m"
	ColorReset  = "\033[0m"
)

// ScanConfig holds configuration for scans
type ScanConfig struct {
	Target       string
	OutputDir    string
	MaxWorkers   int
	FastMode     bool
	SkipUDP      bool
	TunnelGW     string
	Verbose      bool
}

// TunnelMonitor checks tunnel health
type TunnelMonitor struct {
	gateway     string
	healthy     bool
	latency     float64
	packetLoss  float64
	mu          sync.RWMutex
}

// NetworkMonitor tracks network activity per target
type NetworkMonitor struct {
	stats      map[string]*ConnectionStats
	vpnIface   string
	lastCheck  time.Time
	mu         sync.RWMutex
}

// ConnectionStats tracks connections per IP
type ConnectionStats struct {
	ActiveConnections int
	LastActivity      time.Time
	StuckSince        *time.Time
}

// Scanner performs the actual scanning
type Scanner struct {
	config  *ScanConfig
	tunnel  *TunnelMonitor
	monitor *NetworkMonitor
	wg      sync.WaitGroup
	results sync.Map
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex // For synchronized output
	workers map[int]*WorkerStatus // Track worker status
	stats   *ScanStats
}

// WorkerStatus tracks each worker's progress
type WorkerStatus struct {
	IP          string
	Phase       int
	PhaseDesc   string
	Progress    int
	StartTime   time.Time
	LastUpdate  time.Time
}

// ScanStats tracks overall progress
type ScanStats struct {
	TotalHosts   int
	CompletedHosts int
	mu           sync.Mutex
}

// Result stores scan results for a target
type Result struct {
	IP       string
	TCPPorts []string
	UDPPorts []string
	Services map[string]string
	Vulns    []string
}

func main() {
	config := parseFlags()
	
	// Setup signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	
	// Create scanner before signal handler
	scanner := NewScanner(config, ctx)
	
	go func() {
		<-sigChan
		fmt.Printf("\n%s[!] Scan interrupted, cleaning up...%s\n", ColorYellow, ColorReset)
		cancel() // This will cancel all contexts
		
		// Give a moment for graceful shutdown
		time.Sleep(500 * time.Millisecond)
		os.Exit(0)
	}()
	
	// Validate and expand targets
	targets, err := expandTargets(config.Target)
	if err != nil {
		log.Fatalf("%s[!] Invalid target: %v%s", ColorRed, err, ColorReset)
	}
	
	// Print banner
	printBanner(len(targets))
	
	// Start tunnel monitoring if not in fast mode
	if !config.FastMode && config.TunnelGW != "" {
		go scanner.tunnel.monitor(ctx)
	}
	
	// Start network monitoring
	go scanner.monitor.run(ctx)
	
	// Start status updates
	go scanner.statusUpdates(ctx)
	
	// Execute scans
	startTime := time.Now()
	scanner.scanTargets(targets)
	
	// Print summary
	duration := time.Since(startTime)
	printSummary(scanner, targets, duration)
}

func parseFlags() *ScanConfig {
	config := &ScanConfig{}
	
	flag.StringVar(&config.Target, "t", "", "Target IP, CIDR (10.10.10.0/24), or range (10.10.10.1-20)")
	flag.StringVar(&config.OutputDir, "o", ".", "Output directory for results")
	flag.IntVar(&config.MaxWorkers, "w", 3, "Maximum concurrent scans")
	flag.BoolVar(&config.FastMode, "fast", false, "Fast mode (top 1000 ports only)")
	flag.BoolVar(&config.SkipUDP, "no-udp", false, "Skip UDP scanning")
	flag.StringVar(&config.TunnelGW, "gw", "", "Tunnel gateway IP for health monitoring")
	flag.BoolVar(&config.Verbose, "v", false, "Verbose output")
	
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `%sNHUNTP Scanner - Blazing Fast OSCP Scanner%s
Usage: %s -t <target> [options]

Options:
`, ColorPurple, ColorReset, os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
Examples:
  %s -t 10.10.10.5                    # Single IP
  %s -t 10.10.10.0/24 -w 5            # Subnet with 5 workers
  %s -t 10.10.10.1-20 -o results/     # IP range with custom output
  %s -t 10.10.10.0/24 -fast -no-udp   # Fast mode, skip UDP
`, os.Args[0], os.Args[0], os.Args[0], os.Args[0])
	}
	
	flag.Parse()
	
	if config.Target == "" {
		flag.Usage()
		os.Exit(1)
	}
	
	// Auto-detect tunnel gateway if not specified
	if config.TunnelGW == "" && !config.FastMode {
		config.TunnelGW = detectGateway()
	}
	
	return config
}

func NewScanner(config *ScanConfig, ctx context.Context) *Scanner {
	s := &Scanner{
		config: config,
		tunnel: &TunnelMonitor{
			gateway: config.TunnelGW,
			healthy: true,
		},
		monitor: &NetworkMonitor{
			stats: make(map[string]*ConnectionStats),
			vpnIface: detectVPNInterface(),
		},
		ctx: ctx,
		workers: make(map[int]*WorkerStatus),
		stats: &ScanStats{},
	}
	s.ctx, s.cancel = context.WithCancel(ctx)
	
	// Initialize worker status
	for i := 1; i <= config.MaxWorkers; i++ {
		s.workers[i] = &WorkerStatus{}
	}
	
	return s
}

// Network monitoring functions
func (nm *NetworkMonitor) run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			nm.updateStats()
		}
	}
}

func (nm *NetworkMonitor) updateStats() {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	
	nm.lastCheck = time.Now()
	
	// Update connection stats for each monitored IP
	for ip, stats := range nm.stats {
		connections := getActiveConnections(ip)
		stats.ActiveConnections = connections
		
		// Also check if nmap is still running
		nmapRunning := isNmapRunning(ip)
		
		if connections > 0 || nmapRunning {
			stats.LastActivity = time.Now()
			stats.StuckSince = nil
		} else if stats.StuckSince == nil {
			now := time.Now()
			stats.StuckSince = &now
		}
	}
}

func (nm *NetworkMonitor) startTracking(ip string) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	
	nm.stats[ip] = &ConnectionStats{
		LastActivity: time.Now(),
	}
}

func (nm *NetworkMonitor) stopTracking(ip string) {
	nm.mu.Lock()
	defer nm.mu.Unlock()
	
	delete(nm.stats, ip)
}

func (nm *NetworkMonitor) getStats(ip string) (int, *time.Duration) {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	
	if stats, ok := nm.stats[ip]; ok {
		var stuckDuration *time.Duration
		if stats.StuckSince != nil {
			duration := time.Since(*stats.StuckSince)
			stuckDuration = &duration
		}
		return stats.ActiveConnections, stuckDuration
	}
	return 0, nil
}

// Status update function
func (s *Scanner) statusUpdates(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	// Track alerts to avoid spam
	alertedHosts := make(map[string]time.Time)
	
	// Wait a bit before first update
	time.Sleep(10 * time.Second)
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.printStatusUpdate(alertedHosts)
		}
	}
}

func (s *Scanner) printStatusUpdate(alertedHosts map[string]time.Time) {
	// Build status string
	s.stats.mu.Lock()
	completed := s.stats.CompletedHosts
	total := s.stats.TotalHosts
	s.stats.mu.Unlock()
	
	if total == 0 {
		return // No scan started yet
	}
	
	// Count active workers and stuck workers
	activeWorkers := 0
	stuckWorkers := []string{}
	
	for id, worker := range s.workers {
		s.mu.Lock()
		ip := worker.IP
		s.mu.Unlock()
		
		if ip != "" {
			activeWorkers++
			connections, stuckDuration := s.monitor.getStats(ip)
			
			// Check if stuck
			if stuckDuration != nil && *stuckDuration > 45*time.Second && connections == 0 {
				// Only alert once per host per 5 minutes
				if lastAlert, exists := alertedHosts[ip]; !exists || time.Since(lastAlert) > 5*time.Minute {
					stuckWorkers = append(stuckWorkers, fmt.Sprintf("W%d(%s)", id, shortenIP(ip)))
					alertedHosts[ip] = time.Now()
				}
			}
		}
	}
	
	// Build concise status line
	status := fmt.Sprintf("%d/%d hosts | %d workers active", completed, total, activeWorkers)
	
	// Add VPN status
	if s.config.TunnelGW != "" {
		latency, loss := s.tunnel.getStats()
		if loss > 10 || latency > 200 {
			status += fmt.Sprintf(" | VPN:WARNING %.0fms", latency)
		} else {
			status += fmt.Sprintf(" | VPN:OK %.0fms", latency)
		}
	}
	
	fmt.Printf("\n%s[STATUS] %s%s\n", ColorCyan, status, ColorReset)
	
	// Only show stuck workers if any
	if len(stuckWorkers) > 0 {
		fmt.Printf("%s[STUCK] %s - no network activity detected%s\n", 
			ColorYellow, strings.Join(stuckWorkers, ", "), ColorReset)
	}
}

func (s *Scanner) scanTargets(targets []string) {
	// Create output directory if needed
	if err := os.MkdirAll(s.config.OutputDir, 0755); err != nil {
		log.Fatalf("%s[!] Failed to create output directory: %v%s", ColorRed, err, ColorReset)
	}
	
	// Phase 0: Host Discovery (if more than 5 targets)
	liveTargets := targets
	if len(targets) > 5 {
		fmt.Printf("%s[*] Starting host discovery for %d targets...%s\n", ColorCyan, len(targets), ColorReset)
		liveTargets = s.discoverLiveHosts(targets)
		if len(liveTargets) == 0 {
			fmt.Printf("%s[!] No live hosts found in target range%s\n", ColorRed, ColorReset)
			return
		}
		fmt.Printf("%s[+] Found %d live hosts out of %d targets%s\n", ColorGreen, len(liveTargets), len(targets), ColorReset)
		fmt.Printf("%s[+] Live hosts: %s%s\n", ColorGreen, strings.Join(liveTargets, ", "), ColorReset)
		fmt.Printf("\n%s═══ Starting concurrent scans ═══%s\n\n", ColorCyan, ColorReset)
	}
	
	// Initialize stats
	s.stats.TotalHosts = len(liveTargets)
	
	// Worker pool
	targetChan := make(chan string, len(liveTargets))
	
	// Start workers
	for i := 0; i < s.config.MaxWorkers; i++ {
		s.wg.Add(1)
		go s.worker(targetChan, i+1)
	}
	
	// Feed live targets only
	for _, target := range liveTargets {
		select {
		case targetChan <- target:
		case <-s.ctx.Done():
			close(targetChan)
			s.wg.Wait()
			return
		}
	}
	close(targetChan)
	
	// Wait for completion
	s.wg.Wait()
}

func (s *Scanner) worker(targets <-chan string, workerID int) {
	defer s.wg.Done()
	
	for target := range targets {
		select {
		case <-s.ctx.Done():
			return
		default:
			// Check tunnel health before scanning
			if !s.config.FastMode && s.tunnel.isHealthy() {
				time.Sleep(2 * time.Second) // Back off if tunnel is struggling
			}
			
			s.scanHost(target, workerID)
		}
	}
}

func (s *Scanner) scanHost(ip string, workerID int) {
	// Start tracking this IP
	s.monitor.startTracking(ip)
	defer s.monitor.stopTracking(ip)
	
	// Update worker status
	s.updateWorkerStatus(workerID, ip, "starting", 0)
	
	outputDir := filepath.Join(s.config.OutputDir, fmt.Sprintf("nmap-%s", ip))
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		s.logWorker(workerID, ColorRed, "Failed to create directory for %s: %v", ip, err)
		return
	}
	
	result := &Result{
		IP:       ip,
		Services: make(map[string]string),
	}
	
	s.logWorker(workerID, ColorCyan, "Starting scan for %s", ip)
	
	// Calculate total phases for progress
	totalPhases := 4 // Base phases
	if !s.config.FastMode {
		totalPhases = 5
	}
	if !s.config.SkipUDP {
		totalPhases++
	}
	
	currentPhase := 0
	
	// Phase 1: Fast TCP scan with basic scripts
	currentPhase++
	progress := (currentPhase * 100) / totalPhases
	s.updateWorkerStatus(workerID, ip, "tcp-fast", progress)
	s.logWorker(workerID, ColorYellow, "[%d%%] Phase 1: Fast TCP scan on %s", progress, ip)
	tcpPorts := s.fastTCPScan(ip, outputDir, workerID)
	if len(tcpPorts) > 0 {
		result.TCPPorts = tcpPorts
		s.logWorker(workerID, ColorGreen, "Found ports on %s: %s", ip, strings.Join(tcpPorts, ","))
		
		// Phase 2: Full port scan (if not in fast mode)
		if !s.config.FastMode {
			currentPhase++
			progress = (currentPhase * 100) / totalPhases
			s.updateWorkerStatus(workerID, ip, "tcp-full", progress)
			s.logWorker(workerID, ColorYellow, "[%d%%] Phase 2: Full port scan on %s", progress, ip)
			allPorts := s.fullPortScan(ip, outputDir, workerID)
			if len(allPorts) > len(tcpPorts) {
				result.TCPPorts = allPorts
				s.logWorker(workerID, ColorGreen, "Additional ports found on %s: %s", ip, 
					strings.Join(getDifference(allPorts, tcpPorts), ","))
			} else {
				s.logWorker(workerID, ColorYellow, "No additional ports found on %s during full scan", ip)
			}
		}
		
		// Phase 3: Service enumeration
		currentPhase++
		progress = (currentPhase * 100) / totalPhases
		s.updateWorkerStatus(workerID, ip, "service", progress)
		s.logWorker(workerID, ColorYellow, "[%d%%] Phase 3: Service detection on %s", progress, ip)
		s.serviceScan(ip, result.TCPPorts, outputDir, result, workerID)
		
		// Phase 4: Vulnerability scan
		currentPhase++
		progress = (currentPhase * 100) / totalPhases
		s.updateWorkerStatus(workerID, ip, "vuln", progress)
		s.logWorker(workerID, ColorYellow, "[%d%%] Phase 4: Vulnerability scan on %s", progress, ip)
		vulns := s.vulnScan(ip, result.TCPPorts, outputDir, workerID)
		if len(vulns) > 0 {
			result.Vulns = vulns
			s.logImportant("VULNERABILITIES found on %s!", ip)
		} else {
			s.logWorker(workerID, ColorYellow, "No vulnerabilities detected on %s", ip)
		}
		
		// Phase 5: SMB enumeration if applicable
		if s.hasSMBPorts(result.TCPPorts) {
			currentPhase++
			progress = (currentPhase * 100) / totalPhases
			s.updateWorkerStatus(workerID, ip, "smb", progress)
			s.logWorker(workerID, ColorYellow, "[%d%%] Phase 5: SMB enumeration on %s", progress, ip)
			s.smbScan(ip, outputDir, workerID)
		}
	} else {
		s.logWorker(workerID, ColorYellow, "No TCP ports found on %s", ip)
	}
	
	// Phase 6: UDP scan (if not skipped)
	if !s.config.SkipUDP {
		currentPhase++
		progress = (currentPhase * 100) / totalPhases
		s.updateWorkerStatus(workerID, ip, "udp", progress)
		s.logWorker(workerID, ColorYellow, "[%d%%] Phase 6: UDP scan on %s", progress, ip)
		udpPorts := s.udpScan(ip, outputDir, workerID)
		if len(udpPorts) > 0 {
			result.UDPPorts = udpPorts
			s.logWorker(workerID, ColorGreen, "UDP ports found on %s: %s", ip, strings.Join(udpPorts, ","))
		} else {
			s.logWorker(workerID, ColorYellow, "No UDP ports found on %s", ip)
		}
	}
	
	// Save results
	s.results.Store(ip, result)
	s.createSummary(ip, outputDir, result)
	
	// Update stats
	s.stats.mu.Lock()
	s.stats.CompletedHosts++
	completed := s.stats.CompletedHosts
	total := s.stats.TotalHosts
	s.stats.mu.Unlock()
	
	// Clear worker status
	s.updateWorkerStatus(workerID, "", "", 0)
	
	overallProgress := (completed * 100) / total
	s.logWorker(workerID, ColorGreen, "[100%%] Completed scan for %s (%d/%d hosts done - %d%% overall)", 
		ip, completed, total, overallProgress)
}

// Update worker status
func (s *Scanner) updateWorkerStatus(workerID int, ip, phase string, progress int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if worker, ok := s.workers[workerID]; ok {
		worker.IP = ip
		worker.PhaseDesc = phase
		worker.Progress = progress
		worker.LastUpdate = time.Now()
		if ip != "" && worker.StartTime.IsZero() {
			worker.StartTime = time.Now()
		}
	}
}

// Host discovery function
func (s *Scanner) discoverLiveHosts(targets []string) []string {
	liveHosts := []string{}
	
	// Get local IP to exclude
	localIP := getLocalIP()
	
	// Build the nmap command
	var cmd *exec.Cmd
	
	// Check if we need to pass the original CIDR notation
	if s.config.Target != "" && strings.Contains(s.config.Target, "/") {
		// Use the original CIDR notation directly
		cmd = exec.CommandContext(s.ctx, "nmap", "-sn", "-T4", "-n", 
			s.config.Target, "--exclude", localIP)
	} else {
		// For ranges or multiple IPs, pass them as arguments
		args := []string{"-sn", "-T4", "-n", "--exclude", localIP}
		args = append(args, targets...)
		cmd = exec.CommandContext(s.ctx, "nmap", args...)
	}
	
	output, err := cmd.Output()
	if err != nil {
		fmt.Printf("%s[!] Host discovery failed: %v%s\n", ColorRed, err, ColorReset)
		// Try without exclude
		if s.config.Target != "" && strings.Contains(s.config.Target, "/") {
			cmd = exec.CommandContext(s.ctx, "nmap", "-sn", "-T4", s.config.Target)
		} else {
			cmd = exec.CommandContext(s.ctx, "nmap", append([]string{"-sn", "-T4"}, targets...)...)
		}
		output, err = cmd.Output()
		if err != nil {
			return targets // Return all targets if discovery fails
		}
	}
	
	// Debug output
	if s.config.Verbose {
		fmt.Printf("%s[DEBUG] Discovery command: %s%s\n", ColorGray, strings.Join(cmd.Args, " "), ColorReset)
	}
	
	// Parse output for live hosts - improved regex
	ipRegex := regexp.MustCompile(`(?:Nmap scan report for\s+(?:[^\s]+\s+\()?(\d+\.\d+\.\d+\.\d+)\)?)|(?:Host\s+(\d+\.\d+\.\d+\.\d+)\s+is up)`)
	matches := ipRegex.FindAllStringSubmatch(string(output), -1)
	
	for _, match := range matches {
		// Check both capture groups
		ip := match[1]
		if ip == "" {
			ip = match[2]
		}
		if ip != "" && net.ParseIP(ip) != nil {
			liveHosts = append(liveHosts, ip)
		}
	}
	
	// Remove duplicates
	seen := make(map[string]bool)
	unique := []string{}
	for _, ip := range liveHosts {
		if !seen[ip] {
			seen[ip] = true
			unique = append(unique, ip)
		}
	}
	
	return unique
}

// Simplified output function
func (s *Scanner) logWorker(workerID int, color, format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)
	fmt.Printf("%s[W%d]%s %s%s%s\n", ColorGray, workerID, ColorReset, color, message, ColorReset)
}

func (s *Scanner) logImportant(format string, args ...interface{}) {
	fmt.Printf("\n%s[!] %s%s\n", ColorRed, fmt.Sprintf(format, args...), ColorReset)
}

// Scanning functions with better error handling
func (s *Scanner) fastTCPScan(ip, outputDir string, workerID int) []string {
	cmd := exec.CommandContext(s.ctx, "nmap", "-T4", "-F", "-sC", "-Pn", "--open",
		"-oN", filepath.Join(outputDir, "1-fast-scan.txt"),
		"-oG", filepath.Join(outputDir, ".fast-scan.gnmap"),
		ip)
	
	if err := s.runCommandForWorker(cmd, "Scanning top 1000 TCP ports", 60, workerID); err != nil {
		s.logWorker(workerID, ColorRed, "Fast TCP scan failed for %s: %v", ip, err)
		return nil
	}
	
	// Verify output file exists and is complete
	if !s.verifyScanCompletion(filepath.Join(outputDir, "1-fast-scan.txt")) {
		s.logWorker(workerID, ColorYellow, "Fast TCP scan incomplete for %s", ip)
	}
	
	return s.parsePorts(filepath.Join(outputDir, ".fast-scan.gnmap"))
}

func (s *Scanner) fullPortScan(ip, outputDir string, workerID int) []string {
	cmd := exec.CommandContext(s.ctx, "nmap", "-p-", "--min-rate=2000", "--max-retries=2",
		"-T4", "-Pn", "--open",
		"-oN", filepath.Join(outputDir, "2-full-ports.txt"),
		"-oG", filepath.Join(outputDir, ".full-port.gnmap"),
		ip)
	
	if err := s.runCommandForWorker(cmd, "Scanning all TCP ports", 300, workerID); err != nil {
		s.logWorker(workerID, ColorRed, "Full port scan failed for %s: %v", ip, err)
		return nil
	}
	
	// Verify output file exists and is complete
	if !s.verifyScanCompletion(filepath.Join(outputDir, "2-full-ports.txt")) {
		s.logWorker(workerID, ColorYellow, "Full port scan incomplete for %s", ip)
	}
	
	return s.parsePorts(filepath.Join(outputDir, ".full-port.gnmap"))
}

func (s *Scanner) serviceScan(ip string, ports []string, outputDir string, result *Result, workerID int) {
	if len(ports) == 0 {
		return
	}
	
	portList := strings.Join(ports, ",")
	// Increase timeout based on number of ports - more generous for services
	timeout := 120 + (len(ports) * 20)
	if timeout > 600 {
		timeout = 600
	}
	
	// Add --reason to understand why ports show as open
	cmd := exec.CommandContext(s.ctx, "nmap", "-sC", "-sV", "--version-intensity", "7",
		"-T4", "--reason", fmt.Sprintf("-p%s", portList),
		"-oN", filepath.Join(outputDir, "3-services.txt"),
		"-oX", filepath.Join(outputDir, "3-services.xml"),
		ip)
	
	if err := s.runCommandForWorker(cmd, "Detecting services and versions", timeout, workerID); err != nil {
		s.logWorker(workerID, ColorRed, "Service scan failed for %s: %v", ip, err)
		// Try a simpler scan as fallback
		s.logWorker(workerID, ColorYellow, "Attempting basic service detection as fallback...")
		cmd = exec.CommandContext(s.ctx, "nmap", "-sV", fmt.Sprintf("-p%s", portList),
			"-oN", filepath.Join(outputDir, "3-services-basic.txt"), ip)
		s.runCommandForWorker(cmd, "Basic service detection", 60, workerID)
		return
	}
	
	// Wait a moment for file to be fully written
	time.Sleep(500 * time.Millisecond)
	
	// Verify output file exists and is complete
	if !s.verifyScanCompletion(filepath.Join(outputDir, "3-services.txt")) {
		s.logWorker(workerID, ColorYellow, "Service scan incomplete for %s", ip)
	}
	
	// Parse services - try multiple approaches
	s.parseServices(filepath.Join(outputDir, "3-services.txt"), result)
	
	// If no services found, try parsing XML output
	if len(result.Services) == 0 {
		s.logWorker(workerID, ColorYellow, "No services parsed from text output, checking detailed scan...")
		// Re-read the file and look for any service info
		if data, err := os.ReadFile(filepath.Join(outputDir, "3-services.txt")); err == nil {
			s.parseServicesVerbose(string(data), result, ports)
		}
	}
	
	// Log services found
	if len(result.Services) > 0 {
		s.logWorker(workerID, ColorGreen, "Identified %d services on %s", len(result.Services), ip)
		// Show clean service info
		for port, service := range result.Services {
			// Clean up the service string for display
			cleanService := s.cleanServiceString(service)
			s.logWorker(workerID, ColorCyan, "  Port %s: %s", port, cleanService)
		}
	} else {
		s.logWorker(workerID, ColorYellow, "WARNING: No services identified on %s (but ports are open)", ip)
	}
	
	// Check for anonymous FTP
	for _, port := range ports {
		if port == "21" {
			s.checkFTPForWorker(ip, outputDir, workerID)
			break
		}
	}
}

func (s *Scanner) vulnScan(ip string, ports []string, outputDir string, workerID int) []string {
	if len(ports) == 0 {
		return nil
	}
	
	portList := strings.Join(ports, ",")
	// Increase timeout for vuln scans
	timeout := 120 + (len(ports) * 15)
	if timeout > 600 {
		timeout = 600
	}
	
	cmd := exec.CommandContext(s.ctx, "nmap", "--script", "vuln",
		fmt.Sprintf("-p%s", portList), "-Pn",
		"-oN", filepath.Join(outputDir, "4-vulns.txt"),
		ip)
	
	if err := s.runCommandForWorker(cmd, "Running vulnerability scripts", timeout, workerID); err != nil {
		s.logWorker(workerID, ColorRed, "Vulnerability scan failed for %s: %v", ip, err)
		// Create empty file to indicate scan was attempted
		os.WriteFile(filepath.Join(outputDir, "4-vulns.txt"), 
			[]byte(fmt.Sprintf("# Vulnerability scan failed for %s\n# Error: %v\n", ip, err)), 0644)
		return nil
	}
	
	// Verify output file exists and is complete
	if !s.verifyScanCompletion(filepath.Join(outputDir, "4-vulns.txt")) {
		s.logWorker(workerID, ColorYellow, "Vulnerability scan incomplete for %s", ip)
	}
	
	return s.parseVulns(filepath.Join(outputDir, "4-vulns.txt"))
}

func (s *Scanner) smbScan(ip, outputDir string, workerID int) {
	smbPorts := []string{}
	if ports, ok := s.results.Load(ip); ok {
		if r, ok := ports.(*Result); ok {
			for _, port := range r.TCPPorts {
				if port == "445" || port == "139" {
					smbPorts = append(smbPorts, port)
				}
			}
		}
	}
	
	if len(smbPorts) == 0 {
		return
	}
	
	portList := strings.Join(smbPorts, ",")
	cmd := exec.CommandContext(s.ctx, "nmap", "--script", "smb-vuln*,smb-enum-shares,smb-enum-users",
		fmt.Sprintf("-p%s", portList), "-Pn",
		"-oN", filepath.Join(outputDir, "5-smb.txt"),
		ip)
	
	if err := s.runCommandForWorker(cmd, "Enumerating SMB services", 120, workerID); err != nil {
		s.logWorker(workerID, ColorRed, "SMB scan failed for %s: %v", ip, err)
		return
	}
	
	// Verify output file exists and is complete
	if !s.verifyScanCompletion(filepath.Join(outputDir, "5-smb.txt")) {
		s.logWorker(workerID, ColorYellow, "SMB scan incomplete for %s", ip)
	}
	
	s.logWorker(workerID, ColorYellow, "[TIP] SMB next steps: smbclient -L //%s | enum4linux -a %s", ip, ip)
}

func (s *Scanner) udpScan(ip, outputDir string, workerID int) []string {
	// Check if we can use sudo
	if !s.canUseSudo() {
		s.logWorker(workerID, ColorYellow, "UDP scan requires sudo privileges - skipping")
		// Create file indicating UDP scan was skipped
		os.WriteFile(filepath.Join(outputDir, "6-udp.txt"), 
			[]byte(fmt.Sprintf("# UDP scan skipped for %s - requires sudo privileges\n", ip)), 0644)
		return nil
	}
	
	cmd := exec.CommandContext(s.ctx, "sudo", "nmap", "-sU", "--top-ports", "100",
		"--open", "-Pn",
		"-oN", filepath.Join(outputDir, "6-udp.txt"),
		"-oG", filepath.Join(outputDir, ".udp.gnmap"),
		ip)
	
	if err := s.runCommandForWorker(cmd, "Scanning top 100 UDP ports", 180, workerID); err != nil {
		s.logWorker(workerID, ColorRed, "UDP scan failed for %s: %v", ip, err)
		// Create file indicating UDP scan failed
		os.WriteFile(filepath.Join(outputDir, "6-udp.txt"), 
			[]byte(fmt.Sprintf("# UDP scan failed for %s\n# Error: %v\n", ip, err)), 0644)
		return nil
	}
	
	// Verify output file exists and is complete
	if !s.verifyScanCompletion(filepath.Join(outputDir, "6-udp.txt")) {
		s.logWorker(workerID, ColorYellow, "UDP scan incomplete for %s", ip)
	}
	
	ports := s.parsePorts(filepath.Join(outputDir, ".udp.gnmap"))
	
	// Check for important UDP services
	for _, port := range ports {
		switch port {
		case "161":
			s.logWorker(workerID, ColorYellow, "SNMP detected on %s - try: snmpwalk -c public -v1 %s", ip, ip)
		case "69":
			s.logWorker(workerID, ColorYellow, "TFTP detected on %s - try: tftp %s", ip, ip)
		case "53":
			s.logWorker(workerID, ColorYellow, "DNS detected on %s - try: dnsrecon -d %s", ip, ip)
		}
	}
	
	return ports
}

func (s *Scanner) runCommandForWorker(cmd *exec.Cmd, desc string, timeout int, workerID int) error {
	// Start the command
	if err := cmd.Start(); err != nil {
		if s.config.Verbose {
			s.logWorker(workerID, ColorRed, "Failed to start command: %v", err)
		}
		return err
	}
	
	// Create done channel
	done := make(chan error)
	go func() {
		done <- cmd.Wait()
	}()
	
	// Wait for completion or timeout
	select {
	case err := <-done:
		if err != nil {
			if s.ctx.Err() != nil {
				return fmt.Errorf("scan cancelled")
			}
			if s.config.Verbose {
				s.logWorker(workerID, ColorRed, "Command failed: %v", err)
			}
			return err
		}
		return nil
	case <-time.After(time.Duration(timeout) * time.Second):
		cmd.Process.Kill()
		return fmt.Errorf("scan timeout after %d seconds", timeout)
	case <-s.ctx.Done():
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return fmt.Errorf("scan cancelled")
	}
}

func (s *Scanner) checkFTPForWorker(ip, outputDir string, workerID int) {
	s.logWorker(workerID, ColorYellow, "FTP Service Detected - Checking for anonymous access...")
	
	// Check main service scan first
	servicesFile := filepath.Join(outputDir, "3-services.txt")
	if data, err := os.ReadFile(servicesFile); err == nil {
		if strings.Contains(string(data), "Anonymous FTP login allowed") {
			s.logWorker(workerID, ColorRed, "ANONYMOUS FTP LOGIN ALLOWED on %s!", ip)
			return
		}
	}
	
	// Run dedicated FTP scan
	cmd := exec.CommandContext(s.ctx, "nmap", "-p21", "--script=ftp-anon,ftp-syst,ftp-bounce",
		"-T3", ip, "-oN", filepath.Join(outputDir, "ftp-detailed.txt"))
	
	if err := s.runCommandForWorker(cmd, "Checking FTP anonymous access", 30, workerID); err == nil {
		if data, err := os.ReadFile(filepath.Join(outputDir, "ftp-detailed.txt")); err == nil {
			if strings.Contains(string(data), "Anonymous FTP login allowed") {
				s.logWorker(workerID, ColorRed, "ANONYMOUS FTP LOGIN ALLOWED on %s!", ip)
			} else {
				s.logWorker(workerID, ColorGreen, "Anonymous FTP login not allowed on %s", ip)
			}
		}
	}
}

// Parsing functions
func (s *Scanner) parsePorts(grepFile string) []string {
	ports := []string{}
	
	file, err := os.Open(grepFile)
	if err != nil {
		if s.config.Verbose {
			fmt.Printf("%s[DEBUG] Failed to open grep file %s: %v%s\n", ColorGray, grepFile, err, ColorReset)
		}
		return ports
	}
	defer file.Close()
	
	re := regexp.MustCompile(`(\d+)/open`)
	scanner := bufio.NewScanner(file)
	
	portMap := make(map[string]bool)
	for scanner.Scan() {
		matches := re.FindAllStringSubmatch(scanner.Text(), -1)
		for _, match := range matches {
			if len(match) > 1 {
				portMap[match[1]] = true
			}
		}
	}
	
	for port := range portMap {
		ports = append(ports, port)
	}
	
	return ports
}

func (s *Scanner) parseServices(serviceFile string, result *Result) {
	file, err := os.Open(serviceFile)
	if err != nil {
		if s.config.Verbose {
			fmt.Printf("%s[DEBUG] Failed to open service file %s: %v%s\n", ColorGray, serviceFile, err, ColorReset)
		}
		return
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	// Match port/protocol, state, service name, and version info
	re := regexp.MustCompile(`^(\d+)/tcp\s+open\s+(\S+)\s*(.*)`)
	
	for scanner.Scan() {
		line := scanner.Text()
		
		if matches := re.FindStringSubmatch(line); len(matches) > 0 {
			port := matches[1]
			service := matches[2]
			versionInfo := strings.TrimSpace(matches[3])
			
			// Build the full service string
			fullService := service
			if versionInfo != "" {
				// Remove syn-ack, ttl, and other network flags
				versionInfo = regexp.MustCompile(`\s*(syn-ack|ttl \d+)\s*`).ReplaceAllString(versionInfo, " ")
				versionInfo = strings.TrimSpace(versionInfo)
				if versionInfo != "" {
					fullService = service + " " + versionInfo
				}
			}
			
			result.Services[port] = fullService
			
			if s.config.Verbose {
				fmt.Printf("%s[DEBUG] Parsed - Port: %s, Service: %s%s\n", 
					ColorGray, port, fullService, ColorReset)
			}
		}
	}
}

// Clean service string for display
func (s *Scanner) cleanServiceString(service string) string {
	// Remove network flags and script output
	service = regexp.MustCompile(`\s*(syn-ack|ttl \d+)\s*`).ReplaceAllString(service, " ")
	
	// Find the main service info before any script output
	if idx := strings.Index(service, "|"); idx > 0 {
		service = service[:idx]
	}
	
	// Clean up multiple spaces
	service = regexp.MustCompile(`\s+`).ReplaceAllString(service, " ")
	
	return strings.TrimSpace(service)
}

// Additional parsing method for when the standard parsing fails
func (s *Scanner) parseServicesVerbose(content string, result *Result, ports []string) {
	lines := strings.Split(content, "\n")
	
	for _, port := range ports {
		// Look for any line containing the port number
		portPattern := fmt.Sprintf(`%s/tcp\s+open\s+(\S+)`, port)
		re := regexp.MustCompile(portPattern)
		
		for _, line := range lines {
			if matches := re.FindStringSubmatch(line); len(matches) > 0 {
				service := matches[1]
				// Look for version info in the same or next lines
				version := ""
				for i, vline := range lines {
					if vline == line && i+1 < len(lines) {
						// Check next line for version info
						nextLine := lines[i+1]
						if !strings.Contains(nextLine, "/tcp") && strings.TrimSpace(nextLine) != "" {
							version = strings.TrimSpace(nextLine)
						}
					}
				}
				
				if _, exists := result.Services[port]; !exists {
					result.Services[port] = fmt.Sprintf("%s %s", service, version)
				}
			}
		}
		
		// If still no service found, mark as unknown
		if _, exists := result.Services[port]; !exists {
			result.Services[port] = "unknown"
		}
	}
}

func (s *Scanner) parseVulns(vulnFile string) []string {
	vulns := []string{}
	
	data, err := os.ReadFile(vulnFile)
	if err != nil {
		if s.config.Verbose {
			fmt.Printf("%s[DEBUG] Failed to read vuln file %s: %v%s\n", ColorGray, vulnFile, err, ColorReset)
		}
		return vulns
	}
	
	content := string(data)
	if strings.Contains(content, "VULNERABLE") {
		// Extract vulnerability information
		lines := strings.Split(content, "\n")
		for _, line := range lines {
			if strings.Contains(line, "VULNERABLE") {
				vulns = append(vulns, strings.TrimSpace(line))
			}
		}
	}
	
	return vulns
}

// Helper functions
func (s *Scanner) hasSMBPorts(ports []string) bool {
	for _, port := range ports {
		if port == "445" || port == "139" {
			return true
		}
	}
	return false
}

func (s *Scanner) canUseSudo() bool {
	cmd := exec.Command("sudo", "-n", "true")
	return cmd.Run() == nil
}

func (s *Scanner) verifyScanCompletion(filename string) bool {
	data, err := os.ReadFile(filename)
	if err != nil {
		return false
	}
	
	content := string(data)
	return strings.Contains(content, "Nmap done") || strings.Contains(content, "# Nmap done")
}

func (s *Scanner) createSummary(ip, outputDir string, result *Result) {
	summaryFile := filepath.Join(outputDir, "summary.txt")
	file, err := os.Create(summaryFile)
	if err != nil {
		return
	}
	defer file.Close()
	
	fmt.Fprintf(file, "NHUNTP Scan Summary - %s\n", ip)
	fmt.Fprintf(file, "=========================\n")
	fmt.Fprintf(file, "Date: %s\n\n", time.Now().Format("2006-01-02 15:04:05"))
	
	if len(result.TCPPorts) > 0 {
		fmt.Fprintf(file, "TCP Ports: %s\n", strings.Join(result.TCPPorts, ","))
	} else {
		fmt.Fprintf(file, "TCP Ports: None found\n")
	}
	
	if len(result.UDPPorts) > 0 {
		fmt.Fprintf(file, "UDP Ports: %s\n\n", strings.Join(result.UDPPorts, ","))
	} else {
		fmt.Fprintf(file, "UDP Ports: None found\n\n")
	}
	
	// Check for critical findings
	anonymousFTP := false
	for port, service := range result.Services {
		if port == "21" && (strings.Contains(strings.ToLower(service), "ftp") || strings.Contains(strings.ToLower(service), "vsftpd")) {
			// Check the actual service scan file for anonymous FTP
			servicesFile := filepath.Join(outputDir, "3-services.txt")
			if data, err := os.ReadFile(servicesFile); err == nil {
				if strings.Contains(string(data), "Anonymous FTP login allowed") {
					fmt.Fprintf(file, "CRITICAL FINDING: Anonymous FTP access allowed!\n\n")
					anonymousFTP = true
					break
				}
			}
		}
	}
	
	if len(result.Services) > 0 {
		fmt.Fprintf(file, "Services:\n")
		for port, service := range result.Services {
			// Clean up service string for summary
			serviceParts := strings.Fields(service)
			cleanService := service
			if len(serviceParts) > 0 {
				cleanService = serviceParts[0]
				// Add version if it's not a flag
				for i := 1; i < len(serviceParts) && i < 3; i++ {
					if !strings.Contains(serviceParts[i], "syn-ack") && 
					   !strings.Contains(serviceParts[i], "ttl") &&
					   !strings.HasPrefix(serviceParts[i], "|") {
						cleanService += " " + serviceParts[i]
					} else {
						break
					}
				}
			}
			fmt.Fprintf(file, "  %s/tcp: %s\n", port, cleanService)
		}
	} else {
		fmt.Fprintf(file, "Services: No services identified\n")
	}
	
	if len(result.Vulns) > 0 {
		fmt.Fprintf(file, "\nVULNERABILITIES DETECTED:\n")
		for _, vuln := range result.Vulns {
			fmt.Fprintf(file, "  - %s\n", vuln)
		}
	} else {
		fmt.Fprintf(file, "\nVulnerabilities: None detected\n")
	}
	
	// Add scan recommendations
	fmt.Fprintf(file, "\n\nNext Steps:\n")
	if len(result.TCPPorts) > 0 {
		for _, port := range result.TCPPorts {
			switch port {
			case "80", "443", "8080", "8443":
				fmt.Fprintf(file, "- Web enumeration on port %s: gobuster dir -u http://%s:%s -w /usr/share/wordlists/dirb/common.txt\n", port, ip, port)
			case "445":
				fmt.Fprintf(file, "- SMB enumeration: enum4linux -a %s\n", ip)
			case "21":
				if !anonymousFTP {
					fmt.Fprintf(file, "- FTP brute force: hydra -L users.txt -P passwords.txt ftp://%s\n", ip)
				} else {
					fmt.Fprintf(file, "- FTP anonymous access: ftp %s (user: anonymous)\n", ip)
				}
			case "22":
				fmt.Fprintf(file, "- SSH brute force (if needed): hydra -L users.txt -P passwords.txt ssh://%s\n", ip)
			}
		}
	}
	
	fmt.Fprintf(file, "\nFor detailed service information, check 3-services.txt\n")
}

// Utility functions
func expandTargets(target string) ([]string, error) {
	targets := []string{}
	
	// Check for CIDR notation
	if strings.Contains(target, "/") {
		_, network, err := net.ParseCIDR(target)
		if err != nil {
			return nil, err
		}
		
		// Get local IP to exclude
		localIP := getLocalIP()
		
		// Generate all IPs in the network
		for ip := network.IP.Mask(network.Mask); network.Contains(ip); inc(ip) {
			ipStr := ip.String()
			if ipStr != localIP && !strings.HasSuffix(ipStr, ".0") && !strings.HasSuffix(ipStr, ".255") {
				targets = append(targets, ipStr)
			}
		}
		return targets, nil
	}
	
	// Check for range notation (10.10.10.1-20)
	if strings.Contains(target, "-") && strings.Count(target, ".") == 3 {
		parts := strings.Split(target, ".")
		if len(parts) == 4 && strings.Contains(parts[3], "-") {
			base := strings.Join(parts[:3], ".")
			rangeParts := strings.Split(parts[3], "-")
			if len(rangeParts) == 2 {
				start, end := 0, 0
				fmt.Sscanf(rangeParts[0], "%d", &start)
				fmt.Sscanf(rangeParts[1], "%d", &end)
				
				for i := start; i <= end && i <= 255; i++ {
					targets = append(targets, fmt.Sprintf("%s.%d", base, i))
				}
				return targets, nil
			}
		}
	}
	
	// Single IP
	if net.ParseIP(target) != nil {
		return []string{target}, nil
	}
	
	return nil, fmt.Errorf("invalid target format")
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func getLocalIP() string {
	// Try to get from hostname -I
	if out, err := exec.Command("hostname", "-I").Output(); err == nil {
		ips := strings.Fields(string(out))
		if len(ips) > 0 {
			return ips[0]
		}
	}
	
	// Fallback to interface detection
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	
	return ""
}

func detectGateway() string {
	// Try to get default gateway
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err == nil {
		fields := strings.Fields(string(out))
		if len(fields) > 2 {
			return fields[2]
		}
	}
	return "10.10.10.1" // Default fallback
}

func detectVPNInterface() string {
	// Common VPN interface names
	vpnInterfaces := []string{"tun0", "tap0", "ppp0", "vpn0"}
	
	for _, iface := range vpnInterfaces {
		if _, err := net.InterfaceByName(iface); err == nil {
			return iface
		}
	}
	
	return "tun0" // Default
}

func getDifference(slice1, slice2 []string) []string {
	diff := []string{}
	m := make(map[string]bool)
	
	for _, item := range slice2 {
		m[item] = true
	}
	
	for _, item := range slice1 {
		if !m[item] {
			diff = append(diff, item)
		}
	}
	
	return diff
}

// Network monitoring helper functions
func getActiveConnections(ip string) int {
	// Use ss to count established connections to the target IP
	cmd := exec.Command("ss", "-tn", "state", "established", 
		fmt.Sprintf("dst %s", ip))
	
	output, err := cmd.Output()
	if err != nil {
		return 0
	}
	
	// Count lines (excluding header)
	lines := strings.Split(string(output), "\n")
	count := 0
	for _, line := range lines {
		if strings.TrimSpace(line) != "" && strings.Contains(line, ip) {
			count++
		}
	}
	
	return count
}

// Check if nmap process is still running for this target
func isNmapRunning(targetIP string) bool {
	cmd := exec.Command("pgrep", "-f", fmt.Sprintf("nmap.*%s", targetIP))
	output, _ := cmd.Output()
	return len(strings.TrimSpace(string(output))) > 0
}

func shortenIP(ip string) string {
	// Shorten IP for display (10.10.10.5 -> 10.5)
	parts := strings.Split(ip, ".")
	if len(parts) == 4 {
		// If in same subnet, just show last octet
		if strings.HasPrefix(ip, "10.10.10.") {
			return "10." + parts[3]
		} else if strings.HasPrefix(ip, "10.11.") {
			return parts[2] + "." + parts[3]
		} else if strings.HasPrefix(ip, "192.168.") {
			return parts[2] + "." + parts[3]
		}
	}
	return ip
}

func shortPhase(phase string) string {
	// Shorten phase names for display
	switch phase {
	case "tcp-fast":
		return "tcp"
	case "tcp-full":
		return "full"
	case "service":
		return "svc"
	case "vuln":
		return "vln"
	case "smb":
		return "smb"
	case "udp":
		return "udp"
	case "starting":
		return "init"
	default:
		return phase
	}
}

// Tunnel monitoring
func (tm *TunnelMonitor) monitor(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tm.check()
		}
	}
}

func (tm *TunnelMonitor) check() {
	if tm.gateway == "" {
		return
	}
	
	// Ping tunnel gateway
	cmd := exec.Command("ping", "-c", "3", "-W", "1", tm.gateway)
	output, err := cmd.Output()
	
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	if err != nil {
		tm.healthy = false
		return
	}
	
	// Parse ping output
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "min/avg/max") {
			// Extract average latency
			parts := strings.Split(line, "/")
			if len(parts) > 4 {
				fmt.Sscanf(parts[4], "%f", &tm.latency)
			}
		} else if strings.Contains(line, "% packet loss") {
			// Extract packet loss
			fmt.Sscanf(line, "%*[^0-9]%f%% packet loss", &tm.packetLoss)
		}
	}
	
	// Determine health
	tm.healthy = tm.packetLoss < 10 && tm.latency < 200
}

func (tm *TunnelMonitor) isHealthy() bool {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.healthy
}

func (tm *TunnelMonitor) getStats() (float64, float64) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.latency, tm.packetLoss
}

// Display functions
func printBanner(targetCount int) {
	fmt.Printf("%s╔══════════════════════════════════════╗%s\n", ColorPurple, ColorReset)
	fmt.Printf("%s║     NHUNTP Scanner - Go Edition      ║%s\n", ColorPurple, ColorReset)
	fmt.Printf("%s║        Blazing Fast & Safe           ║%s\n", ColorPurple, ColorReset)
	fmt.Printf("%s╚══════════════════════════════════════╝%s\n\n", ColorPurple, ColorReset)
	
	fmt.Printf("%s[*] Starting scan of %d target(s)%s\n", ColorCyan, targetCount, ColorReset)
	fmt.Printf("%s[*] Press Ctrl+C to stop gracefully%s\n\n", ColorCyan, ColorReset)
}

func printSummary(scanner *Scanner, targets []string, duration time.Duration) {
	fmt.Printf("\n%s╔══════════════════════════════════════╗%s\n", ColorCyan, ColorReset)
	fmt.Printf("%s║           SCAN COMPLETE              ║%s\n", ColorCyan, ColorReset)
	fmt.Printf("%s╚══════════════════════════════════════╝%s\n\n", ColorCyan, ColorReset)
	
	fmt.Printf("Total Time: %s%02d:%02d%s\n", 
		ColorWhite, int(duration.Minutes()), int(duration.Seconds())%60, ColorReset)
	
	// Show completed hosts
	scanner.stats.mu.Lock()
	completed := scanner.stats.CompletedHosts
	total := scanner.stats.TotalHosts
	scanner.stats.mu.Unlock()
	
	fmt.Printf("Hosts Scanned: %s%d/%d%s\n", ColorGreen, completed, total, ColorReset)
	
	// Show hosts with findings
	hostsWithPorts := 0
	hostsWithVulns := 0
	hostsWithWebPorts := []string{}
	hostsWithSMB := []string{}
	
	scanner.results.Range(func(key, value interface{}) bool {
		if result, ok := value.(*Result); ok {
			if len(result.TCPPorts) > 0 || len(result.UDPPorts) > 0 {
				hostsWithPorts++
				
				// Check for web ports
				for _, port := range result.TCPPorts {
					if port == "80" || port == "443" || port == "8080" || port == "8443" {
						hostsWithWebPorts = append(hostsWithWebPorts, result.IP)
						break
					}
				}
				
				// Check for SMB
				for _, port := range result.TCPPorts {
					if port == "445" || port == "139" {
						hostsWithSMB = append(hostsWithSMB, result.IP)
						break
					}
				}
			}
			if len(result.Vulns) > 0 {
				hostsWithVulns++
			}
		}
		return true
	})
	
	fmt.Printf("Hosts with open ports: %s%d%s\n", ColorYellow, hostsWithPorts, ColorReset)
	if hostsWithVulns > 0 {
		fmt.Printf("Hosts with vulnerabilities: %s%d%s\n", ColorRed, hostsWithVulns, ColorReset)
	}
	
	if len(hostsWithWebPorts) > 0 {
		fmt.Printf("\n%sWeb servers found on:%s %s\n", ColorCyan, ColorReset, strings.Join(hostsWithWebPorts, ", "))
	}
	
	if len(hostsWithSMB) > 0 {
		fmt.Printf("%sSMB servers found on:%s %s\n", ColorCyan, ColorReset, strings.Join(hostsWithSMB, ", "))
	}
	
	fmt.Printf("\n%s[+] Results saved in %s%s\n", ColorGreen, scanner.config.OutputDir, ColorReset)
}
