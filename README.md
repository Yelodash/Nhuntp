# Nhuntp

Scanner using nmap command chaining, clean output and only using Nmap.

usage

```
# Compile for current system
go build -o nhuntp nhuntp.go

# Cross-compile for Linux (from any OS)
GOOS=linux GOARCH=amd64 go build -o nhuntp nhuntp.go

# Strip debug info for smaller binary (~8MB)
go build -ldflags="-s -w" -o nhuntp nhuntp.go
```

```
# Single IP
./nhuntp -t 10.10.10.5

# Subnet with 5 concurrent workers
./nhuntp -t 10.10.10.0/24 -w 5

# IP range with custom output directory
./nhuntp -t 10.10.10.1-20 -o results/

# Fast mode (top 1000 ports only)
./nhuntp -t 10.10.10.0/24 -fast -no-udp

# With tunnel gateway monitoring
./nhuntp -t 10.10.10.0/24 -gw 10.10.10.1
```

output structure:

```
output_dir/
├── nmap-10.10.10.5/
│   ├── 1-fast-scan.txt
│   ├── 2-full-ports.txt
│   ├── 3-services.txt
│   ├── 4-vulns.txt
│   ├── 5-smb.txt
│   ├── 6-udp.txt
│   └── summary.txt
└── nmap-10.10.10.8/
    └── ...
```
