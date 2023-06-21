param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$filePath
)

# Check if the file has a .pcap extension
if ($filePath -like "*.pcap") {
    Write-Host "Performing analysis for file: $filePath"

    # Run TShark analysis on the file
    $protocol_output = & tshark -r $filePath -Y "frame.number" -T fields -e frame.number -e frame.protocols
    $portscan_output = & tshark -r $filePath -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e frame.number -e ip.src -e tcp.srcport
    $ping_output = & tshark -r $filePath -Y "icmp" -T fields -e frame.number -e ip.src
    $download_output = & tshark -r $filePath -Y "http.response.code==200" -T fields -e frame.number -e http.request.uri

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
        $download_output | ForEach-Object {
            $line = $_
            $frame_number = $line.Split(' ')[0]
            $uri = $line.Split(' ')[1]

            Write-Host "Downloading file: $uri"
            Invoke-WebRequest -Uri $uri -OutFile "$frame_number"

            # Compute hash of the downloaded file
            $hash = Get-FileHash "$frame_number" -Algorithm MD5 | Select-Object -ExpandProperty Hash

            # Write hash to a text file
            "$frame_number: $hash" | Out-File -Append -FilePath "hash_values.txt"

            Write-Host "Downloaded file hash: $hash"
        }
    } else {
        Write-Host "No file downloads detected."
    }

    Write-Host "Analysis completed."
} else {
    Write-Host "Invalid file format. Only .pcap files are supported."
}
