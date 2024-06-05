# pcapanalyze
Network Analysis and File Download Detection Script

Description:
This GitHub repository contains a powerful network analysis and file download detection script developed in PowerShell. The script enables network administrators, security analysts, and incident responders to efficiently analyze PCAP files and detect various network activities, including port scans, ping packets (ICMP), and file downloads.

Key Features:

    Comprehensive network analysis: The script utilizes TShark, a popular network protocol analyzer, to perform in-depth analysis of PCAP files. It identifies protocol types, detects port scanning activities, analyzes ping packets, and detects file downloads.
    Port scanning detection: The script analyzes TCP packets to identify potential port scanning activity, helping identify security vulnerabilities and potential threats.
    Ping packet detection: ICMP packets, commonly used for network diagnostics and troubleshooting, are identified and analyzed to provide valuable insights into network performance.
    File download detection and hashing: The script identifies HTTP responses with a 200 status code, downloads the files, calculates their MD5 hashes, and records the frame number and hash value in a text file. This feature aids in identifying potentially malicious downloads or unauthorized file transfers.

Benefits:

    Streamlined analysis workflow: The script automates the process of network analysis, saving time and effort for network administrators and security professionals.
    Timely incident response: By detecting port scanning, ping packets, and file downloads, the script enables quick identification of potential security incidents, facilitating prompt response and mitigation.
    Enhanced network security: By uncovering network vulnerabilities and identifying unauthorized file transfers, the script helps improve overall network security posture.

Compatibility and Usage:

    The script is developed in PowerShell, making it compatible with Windows operating systems.
    TShark, a command-line network protocol analyzer, is required to run the script and must be installed and accessible within the command-line environment.
    Users need to provide the full path to the PCAP file as an input parameter when running the script.


