"""CDP/LLDP neighbor output parsing for Catalyst Center plugin."""

import re


def parse_cdp_neighbors(output):
    """Parse 'show cdp neighbors detail' output into structured data.

    Args:
        output: Raw CLI output from 'show cdp neighbors detail'.

    Returns:
        List of dicts with keys: device_id, ip_address, platform,
        local_interface, remote_interface, capabilities.
    """
    neighbors = []
    # Split on the separator line between neighbor entries
    entries = re.split(r"-{10,}", output)

    for entry in entries:
        if not entry.strip():
            continue

        neighbor = {}

        # Device ID (hostname)
        match = re.search(r"Device ID:\s*(\S+)", entry)
        if match:
            neighbor["device_id"] = match.group(1)
        else:
            continue  # Skip entries without a device ID

        # IP address (first one found)
        match = re.search(r"IP(?:v4)? [Aa]ddress:\s*(\d+\.\d+\.\d+\.\d+)", entry)
        if match:
            neighbor["ip_address"] = match.group(1)
        else:
            neighbor["ip_address"] = ""

        # Platform
        match = re.search(r"Platform:\s*(.+?)(?:,|\s*$)", entry, re.MULTILINE)
        if match:
            neighbor["platform"] = match.group(1).strip()
        else:
            neighbor["platform"] = ""

        # Local interface
        match = re.search(r"Interface:\s*(\S+)", entry)
        if match:
            neighbor["local_interface"] = match.group(1).rstrip(",")
        else:
            neighbor["local_interface"] = ""

        # Remote interface (Port ID)
        match = re.search(r"Port ID\s*\(outgoing port\):\s*(\S+)", entry)
        if match:
            neighbor["remote_interface"] = match.group(1)
        else:
            neighbor["remote_interface"] = ""

        # Capabilities
        match = re.search(r"Capabilities:\s*(.+?)$", entry, re.MULTILINE)
        if match:
            neighbor["capabilities"] = match.group(1).strip()
        else:
            neighbor["capabilities"] = ""

        neighbor["protocol"] = "CDP"
        neighbors.append(neighbor)

    return neighbors


def parse_lldp_neighbors(output):
    """Parse 'show lldp neighbors detail' output into structured data.

    Args:
        output: Raw CLI output from 'show lldp neighbors detail'.

    Returns:
        List of dicts with keys: device_id, ip_address, platform,
        local_interface, remote_interface, capabilities.
    """
    neighbors = []
    # Split on the separator line or "Local Intf:" pattern
    entries = re.split(r"-{10,}", output)

    for entry in entries:
        if not entry.strip():
            continue

        neighbor = {}

        # System Name (hostname)
        match = re.search(r"System Name:\s*(\S+)", entry)
        if match:
            neighbor["device_id"] = match.group(1)
        else:
            # Try Chassis id as fallback
            match = re.search(r"Chassis id:\s*(\S+)", entry)
            if match:
                neighbor["device_id"] = match.group(1)
            else:
                continue

        # Management IP
        match = re.search(r"Management Addresses?:\s*\n\s*IP:\s*(\d+\.\d+\.\d+\.\d+)", entry)
        if match:
            neighbor["ip_address"] = match.group(1)
        else:
            # Try alternate format
            match = re.search(r"IP:\s*(\d+\.\d+\.\d+\.\d+)", entry)
            if match:
                neighbor["ip_address"] = match.group(1)
            else:
                neighbor["ip_address"] = ""

        # System Description (platform)
        match = re.search(r"System Description:\s*\n\s*(.+?)$", entry, re.MULTILINE)
        if match:
            neighbor["platform"] = match.group(1).strip()[:80]
        else:
            neighbor["platform"] = ""

        # Local interface
        match = re.search(r"Local Intf:\s*(\S+)", entry)
        if match:
            neighbor["local_interface"] = match.group(1)
        else:
            neighbor["local_interface"] = ""

        # Remote interface (Port id)
        match = re.search(r"Port id:\s*(\S+)", entry)
        if match:
            neighbor["remote_interface"] = match.group(1)
        else:
            # Try Port Description
            match = re.search(r"Port Description:\s*(\S+)", entry)
            if match:
                neighbor["remote_interface"] = match.group(1)
            else:
                neighbor["remote_interface"] = ""

        # System Capabilities
        match = re.search(r"System Capabilities:\s*(.+?)$", entry, re.MULTILINE)
        if match:
            neighbor["capabilities"] = match.group(1).strip()
        else:
            neighbor["capabilities"] = ""

        neighbor["protocol"] = "LLDP"
        neighbors.append(neighbor)

    return neighbors


def normalize_interface_name(name):
    """Normalize interface name abbreviations to full names.

    Handles common Cisco abbreviations:
        Gi -> GigabitEthernet
        Te -> TenGigabitEthernet
        Fa -> FastEthernet
        etc.
    """
    if not name:
        return name

    abbreviations = {
        "Gi": "GigabitEthernet",
        "Gig": "GigabitEthernet",
        "GE": "GigabitEthernet",
        "Te": "TenGigabitEthernet",
        "Ten": "TenGigabitEthernet",
        "Tw": "TwoGigabitEthernet",
        "Twe": "TwentyFiveGigabitEthernet",
        "Hu": "HundredGigabitEthernet",
        "Fo": "FortyGigabitEthernet",
        "Fa": "FastEthernet",
        "Eth": "Ethernet",
        "Et": "Ethernet",
        "Po": "Port-channel",
        "Lo": "Loopback",
        "Vl": "Vlan",
        "mgmt": "mgmt",
    }

    for abbr, full in sorted(abbreviations.items(), key=lambda x: -len(x[0])):
        if name.startswith(abbr) and len(name) > len(abbr) and name[len(abbr)].isdigit():
            return full + name[len(abbr):]

    return name


def abbreviate_interface_name(name):
    """Convert a full interface name back to its common abbreviation.

    Handles:
        GigabitEthernet -> Gi
        FastEthernet -> Fa
        TenGigabitEthernet -> Te
        etc.
    """
    if not name:
        return name

    full_to_abbr = {
        "GigabitEthernet": "Gi",
        "FastEthernet": "Fa",
        "TenGigabitEthernet": "Te",
        "TwoGigabitEthernet": "Tw",
        "TwentyFiveGigabitEthernet": "Twe",
        "HundredGigabitEthernet": "Hu",
        "FortyGigabitEthernet": "Fo",
        "Ethernet": "Et",
        "Port-channel": "Po",
        "Loopback": "Lo",
        "Vlan": "Vl",
    }

    for full, abbr in sorted(full_to_abbr.items(), key=lambda x: -len(x[0])):
        if name.startswith(full):
            return abbr + name[len(full):]

    return name


def get_interface_name_variants(name):
    """Return a list of possible name variants for an interface.

    CDP/LLDP may report "FastEthernet0/0" but NetBox may store "Fa0/0" or vice versa.
    Returns all reasonable variants to try when looking up an interface.
    """
    if not name:
        return []

    normalized = normalize_interface_name(name)
    abbreviated = abbreviate_interface_name(normalized)

    variants = [name]
    if normalized != name:
        variants.append(normalized)
    if abbreviated != name and abbreviated != normalized:
        variants.append(abbreviated)

    return variants
