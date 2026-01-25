from sentinelpi.platform import detect_platform

def main():
    platform = detect_platform()
    print(platform.pretty_name, platform.supports_usb_monitoring)

if __name__ == "__main__":
    main()