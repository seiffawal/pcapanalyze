param (
    [Parameter(Mandatory = $true)]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$FilePath
)

# Check if the file has a .pcap extension
if ($FilePath -like "*.pcap") {
    Write-Host "Performing analysis for file: $FilePath"

    # Run TShark analysis on the file
    $protocol_output = & tshark -r $FilePath -Y "frame.number" -T fields -e frame.number -e frame.protocols
    $portscan_output = & tshark -r $FilePath -Y "tcp.flags.syn==1 -and tcp.flags.ack==0" -T fields -e frame.number -e ip.src -e tcp.srcport
    $ping_output = & tshark -r $FilePath -Y "icmp" -T fields -e frame.number -e ip.src
    $download_output = & tshark -r $FilePath -Y "http.response.code==200" -T fields -e frame.number -e http.request.uri
    $ddos_output = & tshark -r $FilePath -Y "ip.dst==your_server_ip -and tcp.flags.syn==1" -T fields -e frame.number -e ip.src
    $dos_output = & tshark -r $FilePath -Y "ip.dst==your_server_ip -and (tcp.flags.syn==1 -or icmp)" -T fields -e frame.number -e ip.src
    $bufferoverflow_output = & tshark -r $FilePath -Y "tcp.flags.push==1 -and data.data -like '*41414141*'" -T fields -e frame.number -e ip.src
    $mitm_output = & tshark -r $FilePath -Y "ip.dst==your_server_ip -and (tcp.flags.ack==1 -and tcp.flags.syn==1) -or (tcp.flags.rst==1 -and tcp.flags.ack==1)" -T fields -e frame.number -e ip.src

    # Display protocol types with their numbers
    Write-Host "Protocol Types:"
    $protocol_output

    # Check for port scanning
    if ($portscan_output) {
        Write-Host "Port scanning detected:"
        $portscan_output
    } else {
        Write-Host "No port scanning detected."
    }

    # Check for ping packets
    if ($ping_output) {
        Write-Host "Ping packets detected:"
        $ping_output
    } else {
        Write-Host "No ping packets detected."
    }

    # Check for file downloads and compute hash
    if ($download_output) {
        Write-Host "File downloads detected:"
        foreach ($line in $download_output) {
            $frame_number = ($line -split ' ')[0]
            $uri = ($line -split ' ')[1]

            Write-Host "Downloading file: $uri"
            Invoke-WebRequest -Uri $uri -OutFile "$frame_number"

            # Compute hash of the downloaded file
            $hash = Get-FileHash -Path "$frame_number" -Algorithm MD5 | Select-Object -ExpandProperty Hash

            # Write hash to a text file
            Add-Content -Path "hash_values.txt" -Value "$frame_number: $hash"

            Write-Host "Downloaded file hash: $hash"
        }
    } else {
        Write-Host "No file downloads detected."
    }

    # Check for DDoS attacks
    if ($ddos_output) {
        Write-Host "DDoS attacks detected:"
        $ddos_output
    } else {
        Write-Host "No DDoS attacks detected."
    }

    # Check for DoS attacks
    if ($dos_output) {
        Write-Host "DoS attacks detected:"
        $dos_output
    } else {
        Write-Host "No DoS attacks detected."
    }

    # Check for buffer overflow attacks
    if ($bufferoverflow_output) {
        Write-Host "Buffer overflow attacks detected:"
        $bufferoverflow_output
    } else {
        Write-Host "No buffer overflow attacks detected."
    }

    # Check for Man-in-the-Middle attacks
    if ($mitm_output) {
        Write-Host "Man-in-the-Middle attacks detected:"
        $mitm_output
    } else {
        Write-Host "No Man-in-the-Middle attacks detected."
    }

    Write-Host "Analysis completed."
} else {
    Write-Host "Invalid file format. Only .pcap files are supported."
}
