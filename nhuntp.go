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

// Scanner performs the actual scanning
type Scanner struct {
	config  *ScanConfig
	tunnel  *TunnelMonitor
	wg      sync.WaitGroup
	results sync.Map
	ctx     context.Context
	cancel  context.CancelFunc
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
	go func() {
		<-sigChan
		fmt.Printf("\n%s[!] Scan interrupted, cleaning up...%s\n", ColorYellow, ColorReset)
		cancel()
	}()
	
	// Validate and expand targets
	targets, err := expandTargets(config.Target)
	if err != nil {
		log.Fatalf("%s[!] Invalid target: %v%s", ColorRed, err, ColorReset)
	}
	
	// Create scanner
	scanner := NewScanner(config, ctx)
	
	// Print banner
	printBanner(len(targets))
	
	// Start tunnel monitoring if not in fast mode
	if !config.FastMode && config.TunnelGW != "" {
		go scanner.tunnel.monitor(ctx)
	}
	
	// Execute scans
	startTime := time.Now()
	scanner.scanTargets(targets)
	
	// Print summary
	duration := time.Since(startTime)
	printSummary(targets, duration)
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
		ctx: ctx,
	}
	s.ctx, s.cancel = context.WithCancel(ctx)
	return s
}

func (s *Scanner) scanTargets(targets []string) {
	// Create output directory if needed
	if err := os.MkdirAll(s.config.OutputDir, 0755); err != nil {
		log.Fatalf("%s[!] Failed to create output directory: %v%s", ColorRed, err, ColorReset)
	}
	
	// Worker pool
	targetChan := make(chan string, len(targets))
	
	// Start workers
	for i := 0; i < s.config.MaxWorkers; i++ {
		s.wg.Add(1)
		go s.worker(targetChan)
	}
	
	// Feed targets
	for _, target := range targets {
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

func (s *Scanner) worker(targets <-chan string) {
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
			
			s.scanHost(target)
		}
	}
}

func (s *Scanner) scanHost(ip string) {
	outputDir := filepath.Join(s.config.OutputDir, fmt.Sprintf("nmap-%s", ip))
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Printf("%s[!] Failed to create directory for %s: %v%s\n", ColorRed, ip, err, ColorReset)
		return
	}
	
	result := &Result{
		IP:       ip,
		Services: make(map[string]string),
	}
	
	fmt.Printf("%s[*] Starting scan for %s%s\n", ColorCyan, ip, ColorReset)
	
	// Phase 1: Fast TCP scan
	s.printPhase(1, "Fast TCP Discovery (Top 1000)")
	tcpPorts := s.fastTCPScan(ip, outputDir)
	if len(tcpPorts) > 0 {
		result.TCPPorts = tcpPorts
		s.displayPorts(tcpPorts)
		
		// Phase 2: Full port scan (if not in fast mode)
		if !s.config.FastMode {
			s.printPhase(2, "Full TCP Port Scan (65535 ports)")
			allPorts := s.fullPortScan(ip, outputDir)
			if len(allPorts) > len(tcpPorts) {
				result.TCPPorts = allPorts
				fmt.Printf("    %s[+]%s Additional ports found: %s\n", ColorGreen, ColorReset, strings.Join(allPorts[len(tcpPorts):], ","))
			}
		}
		
		// Phase 3: Service enumeration
		s.printPhase(3, "Service & Version Detection")
		s.serviceScan(ip, result.TCPPorts, outputDir, result)
		
		// Phase 4: Vulnerability scan
		s.printPhase(4, "Vulnerability Assessment")
		vulns := s.vulnScan(ip, result.TCPPorts, outputDir)
		if len(vulns) > 0 {
			result.Vulns = vulns
			fmt.Printf("    %s[!] VULNERABILITIES DETECTED!%s\n", ColorRed, ColorReset)
		}
		
		// Phase 5: SMB enumeration if applicable
		if s.hasSMBPorts(result.TCPPorts) {
			s.printPhase(5, "SMB Enumeration")
			s.smbScan(ip, outputDir)
		}
	}
	
	// Phase 6: UDP scan (if not skipped)
	if !s.config.SkipUDP {
		s.printPhase(6, "UDP Scan (Top 100)")
		udpPorts := s.udpScan(ip, outputDir)
		if len(udpPorts) > 0 {
			result.UDPPorts = udpPorts
		}
	}
	
	// Save results
	s.results.Store(ip, result)
	s.createSummary(ip, outputDir, result)
	
	fmt.Printf("%s[✓] Completed scan for %s%s\n", ColorGreen, ip, ColorReset)
}

func (s *Scanner) fastTCPScan(ip, outputDir string) []string {
	cmd := exec.CommandContext(s.ctx, "nmap", "-T4", "-F", "-Pn", "--open",
		"-oN", filepath.Join(outputDir, "1-fast-scan.txt"),
		"-oG", filepath.Join(outputDir, ".fast-scan.gnmap"),
		ip)
	
	if err := s.runCommand(cmd, "Scanning top 1000 TCP ports", 30); err != nil {
		return nil
	}
	
	return s.parsePorts(filepath.Join(outputDir, ".fast-scan.gnmap"))
}

func (s *Scanner) fullPortScan(ip, outputDir string) []string {
	cmd := exec.CommandContext(s.ctx, "nmap", "-p-", "--max-rate=1000", "--max-retries=1",
		"-T4", "-Pn", "--open",
		"-oN", filepath.Join(outputDir, "2-full-ports.txt"),
		"-oG", filepath.Join(outputDir, ".full-port.gnmap"),
		ip)
	
	if err := s.runCommand(cmd, "Scanning all TCP ports", 120); err != nil {
		return nil
	}
	
	return s.parsePorts(filepath.Join(outputDir, ".full-port.gnmap"))
}

func (s *Scanner) serviceScan(ip string, ports []string, outputDir string, result *Result) {
	if len(ports) == 0 {
		return
	}
	
	portList := strings.Join(ports, ",")
	cmd := exec.CommandContext(s.ctx, "nmap", "-sC", "-sV", "--version-intensity", "9",
		"-T3", fmt.Sprintf("-p%s", portList),
		"-oN", filepath.Join(outputDir, "3-services.txt"),
		ip)
	
	if err := s.runCommand(cmd, "Detecting services and versions", 90); err != nil {
		return
	}
	
	// Parse services
	s.parseServices(filepath.Join(outputDir, "3-services.txt"), result)
	
	// Check for anonymous FTP
	for _, port := range ports {
		if port == "21" {
			s.checkFTP(ip, outputDir)
			break
		}
	}
}

func (s *Scanner) vulnScan(ip string, ports []string, outputDir string) []string {
	if len(ports) == 0 {
		return nil
	}
	
	portList := strings.Join(ports, ",")
	cmd := exec.CommandContext(s.ctx, "nmap", "--script", "vuln",
		fmt.Sprintf("-p%s", portList), "-Pn",
		"-oN", filepath.Join(outputDir, "4-vulns.txt"),
		ip)
	
	if err := s.runCommand(cmd, "Running vulnerability scripts", 90); err != nil {
		return nil
	}
	
	return s.parseVulns(filepath.Join(outputDir, "4-vulns.txt"))
}

func (s *Scanner) smbScan(ip, outputDir string) {
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
	
	s.runCommand(cmd, "Enumerating SMB services", 60)
	
	fmt.Printf("\n    %s[TIP] Next steps for SMB:%s\n", ColorYellow, ColorReset)
	fmt.Printf("    %s• smbclient -L //%s%s\n", ColorGray, ip, ColorReset)
	fmt.Printf("    %s• enum4linux -a %s%s\n", ColorGray, ip, ColorReset)
	fmt.Printf("    %s• smbmap -H %s%s\n", ColorGray, ip, ColorReset)
}

func (s *Scanner) udpScan(ip, outputDir string) []string {
	// Check if we can use sudo
	if !s.canUseSudo() {
		fmt.Printf("    %s[!] UDP scan requires sudo privileges%s\n", ColorYellow, ColorReset)
		return nil
	}
	
	cmd := exec.CommandContext(s.ctx, "sudo", "nmap", "-sU", "--top-ports", "100",
		"--open", "-Pn",
		"-oN", filepath.Join(outputDir, "6-udp.txt"),
		"-oG", filepath.Join(outputDir, ".udp.gnmap"),
		ip)
	
	if err := s.runCommand(cmd, "Scanning top 100 UDP ports", 120); err != nil {
		return nil
	}
	
	ports := s.parsePorts(filepath.Join(outputDir, ".udp.gnmap"))
	
	// Check for important UDP services
	for _, port := range ports {
		switch port {
		case "161":
			fmt.Printf("    %s[!]%s SNMP detected - try: %ssnmpwalk -c public -v1 %s%s\n",
				ColorYellow, ColorReset, ColorGray, ip, ColorReset)
		case "69":
			fmt.Printf("    %s[!]%s TFTP detected - try: %stftp %s%s\n",
				ColorYellow, ColorReset, ColorGray, ip, ColorReset)
		case "53":
			fmt.Printf("    %s[!]%s DNS detected - try: %sdnsrecon -d %s%s\n",
				ColorYellow, ColorReset, ColorGray, ip, ColorReset)
		}
	}
	
	return ports
}

func (s *Scanner) runCommand(cmd *exec.Cmd, desc string, timeout int) error {
	fmt.Printf("    %s[*]%s %s\n", ColorYellow, ColorReset, desc)
	if s.config.Verbose {
		fmt.Printf("    %sCommand: %s%s\n", ColorGray, strings.Join(cmd.Args, " "), ColorReset)
	}
	
	// Create progress ticker
	done := make(chan error)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	start := time.Now()
	
	// Run command
	go func() {
		done <- cmd.Run()
	}()
	
	// Show progress
	for {
		select {
		case err := <-done:
			elapsed := time.Since(start)
			if err != nil {
				fmt.Printf("\r    %s[!]%s Failed after %02d:%02d\n",
					ColorRed, ColorReset, int(elapsed.Minutes()), int(elapsed.Seconds())%60)
				return err
			}
			fmt.Printf("\r    %s[✓]%s Completed in %02d:%02d\n",
				ColorGreen, ColorReset, int(elapsed.Minutes()), int(elapsed.Seconds())%60)
			return nil
		case <-ticker.C:
			elapsed := time.Since(start)
			percent := int(elapsed.Seconds()) * 100 / timeout
			if percent > 100 {
				percent = 99
			}
			fmt.Printf("\r    %s[*]%s Scanning... %s[%02d:%02d]%s %s%3d%%%s ",
				ColorYellow, ColorReset, ColorWhite, int(elapsed.Minutes()), int(elapsed.Seconds())%60,
				ColorReset, ColorWhite, percent, ColorReset)
		case <-s.ctx.Done():
			cmd.Process.Kill()
			return fmt.Errorf("scan cancelled")
		}
	}
}

// Helper functions

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

func (s *Scanner) parsePorts(grepFile string) []string {
	ports := []string{}
	
	file, err := os.Open(grepFile)
	if err != nil {
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
		return
	}
	defer file.Close()
	
	scanner := bufio.NewScanner(file)
	re := regexp.MustCompile(`^(\d+)/tcp\s+open\s+(\S+)\s*(.*)`)
	
	for scanner.Scan() {
		line := scanner.Text()
		if matches := re.FindStringSubmatch(line); len(matches) > 0 {
			port := matches[1]
			service := matches[2]
			version := strings.TrimSpace(matches[3])
			
			result.Services[port] = fmt.Sprintf("%s %s", service, version)
			
			// Display with colors
			var color string
			switch {
			case strings.Contains(service, "http"):
				color = ColorCyan
			case strings.Contains(service, "ssh"):
				color = ColorGreen
			case strings.Contains(service, "ftp"):
				color = ColorYellow
			case strings.Contains(service, "smb") || strings.Contains(service, "netbios"):
				color = ColorPurple
			case strings.Contains(service, "ms-wbt-server"):
				color = ColorRed
			default:
				color = ColorWhite
			}
			
			fmt.Printf("    %sPort %-6s %-15s %s%s\n", color, port+"/tcp", service, version, ColorReset)
		}
	}
}

func (s *Scanner) parseVulns(vulnFile string) []string {
	vulns := []string{}
	
	data, err := os.ReadFile(vulnFile)
	if err != nil {
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

func (s *Scanner) checkFTP(ip, outputDir string) {
	fmt.Printf("\n    %s[*] FTP Service Detected - Checking for anonymous access...%s\n",
		ColorYellow, ColorReset)
	
	// Check main service scan first
	servicesFile := filepath.Join(outputDir, "3-services.txt")
	if data, err := os.ReadFile(servicesFile); err == nil {
		if strings.Contains(string(data), "Anonymous FTP login allowed") {
			fmt.Printf("    %s[!] ANONYMOUS FTP LOGIN ALLOWED!%s\n", ColorRed, ColorReset)
			return
		}
	}
	
	// Run dedicated FTP scan
	cmd := exec.CommandContext(s.ctx, "nmap", "-p21", "--script=ftp-anon,ftp-syst,ftp-bounce",
		"-T3", ip, "-oN", filepath.Join(outputDir, "ftp-detailed.txt"))
	
	if err := cmd.Run(); err == nil {
		if data, err := os.ReadFile(filepath.Join(outputDir, "ftp-detailed.txt")); err == nil {
			if strings.Contains(string(data), "Anonymous FTP login allowed") {
				fmt.Printf("    %s[!] ANONYMOUS FTP LOGIN ALLOWED!%s\n", ColorRed, ColorReset)
			} else {
				fmt.Printf("    %s[+] Anonymous FTP login not allowed%s\n", ColorGreen, ColorReset)
			}
		}
	}
}

func (s *Scanner) displayPorts(ports []string) {
	fmt.Printf("\n    %sDiscovered TCP Ports:%s\n", ColorWhite, ColorReset)
	fmt.Printf("    %s──────────────────────────%s\n", ColorGray, ColorReset)
	
	for _, port := range ports {
		var service, color string
		switch port {
		case "21":
			service, color = "FTP", ColorYellow
		case "22":
			service, color = "SSH", ColorGreen
		case "80":
			service, color = "HTTP", ColorCyan
		case "443":
			service, color = "HTTPS", ColorCyan
		case "445", "139":
			service, color = "SMB", ColorPurple
		case "3389":
			service, color = "RDP", ColorRed
		default:
			service, color = "", ColorBlue
		}
		
		if service != "" {
			fmt.Printf("    %s●%s Port %s%s%s - %s%s%s\n",
				ColorBlue, ColorReset, ColorWhite, port, ColorReset, color, service, ColorReset)
		} else {
			fmt.Printf("    %s●%s Port %s%s%s\n",
				ColorBlue, ColorReset, ColorWhite, port, ColorReset)
		}
	}
	
	fmt.Printf("\n    %s[+]%s Found ports: %s%s%s\n",
		ColorGreen, ColorReset, ColorWhite, strings.Join(ports, ","), ColorReset)
}

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

func (s *Scanner) printPhase(num int, title string) {
	fmt.Printf("\n%s┌─────────────────────────────────────────────────────────────┐%s\n",
		ColorCyan, ColorReset)
	fmt.Printf("%s│%s %sPHASE %d: %s%s\n", ColorCyan, ColorReset, ColorWhite, num, title, ColorReset)
	fmt.Printf("%s└─────────────────────────────────────────────────────────────┘%s\n\n",
		ColorCyan, ColorReset)
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
	
	fmt.Fprintf(file, "TCP Ports: %s\n", strings.Join(result.TCPPorts, ","))
	fmt.Fprintf(file, "UDP Ports: %s\n\n", strings.Join(result.UDPPorts, ","))
	
	// Check for critical findings
	for port, service := range result.Services {
		if port == "21" && strings.Contains(service, "Anonymous") {
			fmt.Fprintf(file, "CRITICAL FINDING: Anonymous FTP access allowed!\n\n")
			break
		}
	}
	
	fmt.Fprintf(file, "Services:\n")
	for port, service := range result.Services {
		fmt.Fprintf(file, "  %s/tcp: %s\n", port, service)
	}
	
	if len(result.Vulns) > 0 {
		fmt.Fprintf(file, "\nVULNERABILITIES DETECTED - See 4-vulns.txt\n")
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

func printSummary(targets []string, duration time.Duration) {
	fmt.Printf("\n%s╔══════════════════════════════════════╗%s\n", ColorCyan, ColorReset)
	fmt.Printf("%s║           SCAN COMPLETE              ║%s\n", ColorCyan, ColorReset)
	fmt.Printf("%s╚══════════════════════════════════════╝%s\n\n", ColorCyan, ColorReset)
	
	fmt.Printf("Total Time: %s%02d:%02d%s\n", 
		ColorWhite, int(duration.Minutes()), int(duration.Seconds())%60, ColorReset)
	fmt.Printf("Targets Scanned: %s%d%s\n", ColorGreen, len(targets), ColorReset)
	
	fmt.Printf("\n%s[✓] Results saved in output directories%s\n", ColorGreen, ColorReset)
}
