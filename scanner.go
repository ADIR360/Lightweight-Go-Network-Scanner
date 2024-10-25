package main

import (
    "bufio"
    "fmt"
    "log"
    "net"
    "os"
    "strings"
    "sync"
    "time"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

type scanResult struct {
    port    int
    open    bool
    service string
    banner  string
}

type arpResult struct {
    IP  net.IP
    MAC net.HardwareAddr
}

// Known services based on common ports (for simple service fingerprinting)
var commonServices = map[int]string{
    21:  "FTP",
    22:  "SSH",
    23:  "Telnet",
    25:  "SMTP",
    80:  "HTTP",
    443: "HTTPS",
}

func main() {
    if len(os.Args) < 2 {
        fmt.Println("Usage: go run scanner.go <IP Address>")
        return
    }

    target := os.Args[1]
    var wg sync.WaitGroup
    results := make(chan scanResult, 100)

    // Range of ports to scan; can be customized
    ports := []int{21, 22, 23, 25, 80, 443, 8080}
    startTime := time.Now()

    fmt.Println("Starting Port Scan...")
    for _, port := range ports {
        wg.Add(1)
        go func(p int) {
            defer wg.Done()
            scanPort(target, p, results)
        }(port)
    }

    go func() {
        wg.Wait()
        close(results)
    }()

    for res := range results {
        if res.open {
            fmt.Printf("Port %d (%s) is open - Banner: %s\n", res.port, res.service, res.banner)
        } else {
            fmt.Printf("Port %d is closed.\n", res.port)
        }
    }

    fmt.Printf("\nPort scan completed in %v\n\n", time.Since(startTime))
    fmt.Println("Starting ARP Scan...")

    devices := arpScan("en0") // I am using "en0" instead of "eth0" or "wlan" check in your system accordingly and replace

    for _, device := range devices {
        fmt.Printf("Device IP: %s, MAC: %s\n", device.IP, device.MAC)
    }

    fmt.Println("ARP scan completed.")
}

// scanPort checks if a port is open, grabs the banner if possible, and identifies the service.
func scanPort(host string, port int, results chan<- scanResult) {
    address := fmt.Sprintf("%s:%d", host, port)
    conn, err := net.DialTimeout("tcp", address, 2*time.Second)

    result := scanResult{
        port:    port,
        open:    false,
        service: commonServices[port],
        banner:  "",
    }

    if err != nil {
        results <- result
        return
    }
    defer conn.Close()
    result.open = true

    conn.SetReadDeadline(time.Now().Add(2 * time.Second))
    reader := bufio.NewReader(conn)
    banner, err := reader.ReadString('\n')
    if err == nil && len(strings.TrimSpace(banner)) > 0 {
        result.banner = strings.TrimSpace(banner)
    } else {
        result.banner = "No banner retrieved"
    }

    results <- result
}

// arpScan performs an ARP scan on the specified network interface and returns IP and MAC addresses of connected devices.
func arpScan(iface string) []arpResult {
    handle, err := pcap.OpenLive(iface, 1600, false, pcap.BlockForever)
    if err != nil {
        log.Fatal(err)
    }
    defer handle.Close()

    srcMAC := net.HardwareAddr{0x02, 0x42, 0xac, 0x11, 0x00, 0x02}  // Replace with your MAC
    srcIP := net.IPv4(192, 168, 29, 31) // Use your local IP
    dstMAC := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

    arpRequest := &layers.ARP{
        AddrType:          layers.LinkTypeEthernet,
        Protocol:          layers.EthernetTypeIPv4,
        HwAddressSize:     6,
        ProtAddressSize:   4,
        Operation:         layers.ARPRequest,
        SourceHwAddress:   srcMAC,
        SourceProtAddress: srcIP,
        DstHwAddress:      dstMAC,
    }

    eth := &layers.Ethernet{
        SrcMAC:       srcMAC,
        DstMAC:       dstMAC,
        EthernetType: layers.EthernetTypeARP,
    }

    buffer := gopacket.NewSerializeBuffer()
    gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, eth, arpRequest)

    if err := handle.WritePacketData(buffer.Bytes()); err != nil {
        log.Fatal(err)
    }

    devices := []arpResult{}

    // Set a timeout for listening for packets
    timeout := time.After(3 * time.Second) // Set timeout to 3 seconds
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

    go func() {
        for packet := range packetSource.Packets() {
            if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
                arp, _ := arpLayer.(*layers.ARP)
                devices = append(devices, arpResult{
                    IP:  net.IP(arp.SourceProtAddress),
                    MAC: net.HardwareAddr(arp.SourceHwAddress),
                })
            }
        }
    }()

    <-timeout // Wait for timeout to occur
    return devices
}
