#!/bin/bash

# Check if the file has a .pcap extension
if [[ $1 == *.pcap ]]; then
    echo "Performing analysis for file: $1"

    # Run TShark analysis on the file
    protocol_output=$(tshark -r "$1" -Y "frame.number" -T fields -e frame.number -e frame.protocols)
    portscan_output=$(tshark -r "$1" -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e frame.number -e ip.src -e tcp.srcport)
    ping_output=$(tshark -r "$1" -Y "icmp" -T fields -e frame.number -e ip.src)
    download_output=$(tshark -r "$1" -Y "http.response.code==200" -T fields -e frame.number -e http.request.uri)
    ddos_output=$(tshark -r "$1" -Y "ip.dst==your_server_ip && tcp.flags.syn==1" -T fields -e frame.number -e ip.src)
    dos_output=$(tshark -r "$1" -Y "ip.dst==your_server_ip && (tcp.flags.syn==1 || icmp)" -T fields -e frame.number -e ip.src)
    bufferoverflow_output=$(tshark -r "$1" -Y "tcp.flags.push==1 && data.data contains '41414141'" -T fields -e frame.number -e ip.src)
    mitm_output=$(tshark -r "$1" -Y "ip.dst==your_server_ip && (tcp.flags.ack==1 && tcp.flags.syn==1) || (tcp.flags.rst==1 && tcp.flags.ack==1)" -T fields -e frame.number -e ip.src)

    # Display protocol types with their numbers
    echo "Protocol Types:"
    echo "$protocol_output"

    # Check for port scanning
    if [[ -n "$portscan_output" ]]; then
        echo "Port scanning detected:"
        echo "$portscan_output"
    else
        echo "No port scanning detected."
    fi

    # Check for ping packets
    if [[ -n "$ping_output" ]]; then
        echo "Ping packets detected:"
        echo "$ping_output"
    else
        echo "No ping packets detected."
    fi

    # Check for file downloads and compute hash
    if [[ -n "$download_output" ]]; then
        echo "File downloads detected:"
        while read -r line; do
            frame_number=$(echo "$line" | awk '{print $1}')
            uri=$(echo "$line" | awk '{print $2}')

            echo "Downloading file: $uri"
            wget -q -O "$frame_number" "$uri"
            
            # Compute hash of the downloaded file
            hash=$(md5sum "$frame_number" | awk '{print $1}')

            # Write hash to a text file
            echo "$frame_number: $hash" >> hash_values.txt

            echo "Downloaded file hash: $hash"
        done <<< "$download_output"
    else
        echo "No file downloads detected."
    fi

    # Check for DDoS attacks
    if [[ -n "$ddos_output" ]]; then
        echo "DDoS attacks detected:"
        echo "$ddos_output"
    else
        echo "No DDoS attacks detected."
    fi

    # Check for DoS attacks
    if [[ -n "$dos_output" ]]; then
        echo "DoS attacks detected:"
        echo "$dos_output"
    else
        echo "No DoS attacks detected."
    fi

    # Check for buffer overflow attacks
    if [[ -n "$bufferoverflow_output" ]]; then
        echo "Buffer overflow attacks detected:"
        echo "$bufferoverflow_output"
    else
        echo "No buffer overflow attacks detected."
    fi

    # Check for Man-in-the-Middle attacks
    if [[ -n "$mitm_output" ]]; then
        echo "Man-in-the-Middle attacks detected:"
        echo "$mitm_output"
    else
        echo "No Man-in-the-Middle attacks detected."
    fi

    echo "Analysis completed."
else
    echo "Invalid file format. Only .pcap files are supported."
fi
