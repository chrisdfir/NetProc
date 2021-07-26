![image](https://user-images.githubusercontent.com/18665523/126923874-572fd8af-6d10-465c-9d7d-dced1768ae69.png)

Correlates running processes to point-in-time network traffic for triage analysis of Windows hosts.

## Objectives
* Extract and correlate process metadata to ingress and egress network traffic on the Windows host.
* Provide relevant data for security-relevant analysis, manually or via SIEM.
* Parse all the things.

## Prerequisites
* Python3

## Output
NetProc.py gathers network traffic and affiliated process information for quick security analysis. This data is gathered and captured in a CSV file saved in the execution directory. Headers for this dataset are as follows:
* Hostname
* Process Time Creation
* Username
* Parent Process ID
* Parent Process Name
* Process ID
* Process Name
* SHA256 Hash
* Command Line
* Connection Status
* Source IP
* Source Port
* Destination IP
* Destination Port
* Country Code
* ASN
* WHOIS Description


## Instructions
1. With Python3 installed, run the following command from a Windows terminal with Administrative privileges.

```python
pip install -r .\requirements.txt
python .\netproc.py
```
