# SentinelPi - A click-based Security Monitor for Raspberry Pi

A CLI security daemon + toolkit for Raspberry Pi that monitors the system for suspicious activity and hardware events.

Modules to implement: 
1) USB Device Monitoring = usb
2) Network Monitoring = net
3) Filesystem Integrity = fs
4) Process Anomaly Detection = proc
5) Alerting and Automatic Logs

Crucially, program is intended and optimized for Raspberry Pi/Linux-based edge devices but runs on macOS as well in a reduced feature set for development, testing, demonstration of detection, alerting and analysis.  

Idea: 
```
CLI -> Modules (data collection) -> Events -> Logging
                                       \/
                                    Analyzers 
                                       \/
                                     Alerts
                                       \/
                                    Responders 
```
Pipeline explained
1) What processes exist right now? = Events (collect facts)
2) Is any process behaving weird? = Analyzers + Anomaly Detection (reason + flag)
3) Who should care with what severity? = Alerting (alert)
4) What should be done about the process? = Responders (act/trigger)

## Core Features

## Technical Stack

## Getting Started

### Installation

### Example CLI

## Project Structure

## Why This Project?

## Contact 

## License

## Demo