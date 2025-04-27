import win32evtlog  # For log access
import win32evtlogutil  # For log utilities
import win32con  # For constants

def read_event_logs(server='localhost', log_type='Application'):
    """
    Reads Windows Event Logs from the specified log type.
    
    Parameters:
        - server: Target machine (use 'localhost' for local)
        - log_type: Log type (e.g., 'System', 'Security', 'Application')
    """
    try:
        # Open event log
        log_handle = win32evtlog.OpenEventLog(server, log_type)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        print(f"\nReading {log_type} logs from {server}...")

        # Read logs in chunks
        while True:
            events = win32evtlog.ReadEventLog(log_handle, flags, 0)
            if not events:
                break

            for event in events:
                print(f"Event ID: {event.EventID}")
                print(f"Source: {event.SourceName}")
                print(f"Time Generated: {event.TimeGenerated}")
                print(f"Category: {event.EventCategory}")
                print(f"Description: {event.StringInserts}")
                print("-" * 50)

        win32evtlog.CloseEventLog(log_handle)

    except Exception as e:
        print(f"Error reading event logs: {e}")

# Example usage
read_event_logs(log_type='Security')  # Change to 'System', 'Application', etc.