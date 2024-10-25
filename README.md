# Go Network Scanner

A simple ARP network scanner written in Go that discovers devices connected to the same network by sending ARP requests and listening for responses.

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Code Overview](#code-overview)
- [Contributing](#contributing)
- [License](#license)

## Features
- Performs ARP scans to identify devices on the local network.
- Displays IP addresses and MAC addresses of discovered devices.
- Optimized for speed with a timeout mechanism for waiting on responses.

## Installation

### Prerequisites
- Go (version 1.16 or later)
- [gopacket](https://github.com/google/gopacket)

### Steps
1. Clone the repository:
   
   ```bash
   git clone https://github.com/yourusername/go-network-scanner.git
   cd go-network-scanner
2. Initialize a Go module:

    
    go mod init go-network-scanner

3. Install the necessary dependencies:

    
     go get -u github.com/google/gopacket
     go get -u github.com/google/gopacket/pcap
   
## Usage

Build the project:

     ```bash
     go build -o network_scanner
2.Run the scanner with root privileges to access network interfaces:

    
    sudo ./network_scanner
3.Provide your network interface name as an argument (e.g., en0):

    
    sudo ./network_scanner en0
    
## Code Overview
### Main Functionality
The scanner sends ARP requests to the specified network interface and listens for ARP replies.
It captures the IP and MAC addresses of responding devices and displays them.
### Key Functions
arpScan(iface string) []arpResult: Performs the ARP scanning on the specified interface and returns a list of discovered devices.
### Timeout Mechanism
The scan process includes a timeout to avoid getting stuck while waiting for responses.
### Contributing
Contributions are welcome! If you have suggestions for improvements or additional features, please create a pull request or open an issue.

## Fork the repository.
1.Create your feature branch:
    
    git checkout -b feature/YourFeature
2.Commit your changes:

    git commit -m 'Add some feature'
3.Push to the branch:

    git push origin feature/YourFeature
Open a pull request.

## License
This project is licensed under the MIT License - see the LICENSE file for details.
