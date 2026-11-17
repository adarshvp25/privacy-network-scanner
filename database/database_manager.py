
import sqlite3
from datetime import datetime

DATABASE_PATH = "database/network_scanner.db"


def get_connection():
    """Create a connection to the SQLite database."""

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():
    """Create tables and safely add new columns."""

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_time TEXT NOT NULL,
            network_range TEXT,
            total_devices INTEGER
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            ip_address TEXT,
            mac_address TEXT,
            manufacturer TEXT,
            hostname TEXT,
            device_type TEXT,
            open_ports TEXT,
            camera_indicator TEXT,
            risk_level TEXT,
            security_findings TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)

    # Migrate existing databases without deleting records.
    existing_columns = {
        row["name"]
        for row in cursor.execute("PRAGMA table_info(devices)").fetchall()
    }

    new_columns = {
        "confidence": "TEXT",
        "indicators": "TEXT",
        "risk_score": "INTEGER DEFAULT 0",
        "recommendations": "TEXT"
    }

    for column_name, column_type in new_columns.items():

        if column_name not in existing_columns:
            cursor.execute(
                f"ALTER TABLE devices ADD COLUMN {column_name} {column_type}"
            )

    connection.commit()
    connection.close()


def save_scan(network_range, devices):
    """Save a scan and all its device information."""

    connection = get_connection()
    cursor = connection.cursor()

    try:
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        cursor.execute("""
            INSERT INTO scans (scan_time, network_range, total_devices)
            VALUES (?, ?, ?)
        """, (scan_time, network_range, len(devices)))

        scan_id = cursor.lastrowid

        for device in devices:

            cursor.execute("""
                INSERT INTO devices (
                    scan_id,
                    ip_address,
                    mac_address,
                    manufacturer,
                    hostname,
                    device_type,
                    open_ports,
                    camera_indicator,
                    risk_level,
                    security_findings,
                    confidence,
                    indicators,
                    risk_score,
                    recommendations
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                device.get("ip"),
                device.get("mac"),
                device.get("vendor"),
                device.get("hostname"),
                device.get("device_type"),
                ", ".join(map(str, device.get("open_ports", []))),
                None,
                device.get("risk_level"),
                "; ".join(device.get("findings", [])),
                device.get("confidence", "Low"),
                "; ".join(device.get("indicators", [])),
                device.get("risk_score", 0),
                "; ".join(device.get("recommendations", []))
            ))

        connection.commit()

        return scan_id

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def get_scan_history():
    """Retrieve previous scans."""

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT * FROM scans
        ORDER BY id DESC
    """)

    scans = [dict(row) for row in cursor.fetchall()]

    connection.close()

    return scans


def get_scan_details(scan_id):
    """Retrieve devices belonging to a particular scan."""

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT * FROM devices
        WHERE scan_id = ?
    """, (scan_id,))

    devices = [dict(row) for row in cursor.fetchall()]

    connection.close()

    return devices


def get_device_details(device_id):
    """Retrieve details of one discovered device."""

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute("""
        SELECT devices.*, scans.scan_time, scans.network_range
        FROM devices
        JOIN scans ON devices.scan_id = scans.id
        WHERE devices.id = ?
    """, (device_id,))

    result = cursor.fetchone()

    connection.close()

    return dict(result) if result else None


def clear_scan_history():
    """Delete all scan records and reset the Scan ID counter."""

    connection = get_connection()
    cursor = connection.cursor()

    try:
        # Delete associated device records first.
        cursor.execute("DELETE FROM devices")

        # Delete all scan records.
        cursor.execute("DELETE FROM scans")

        # Reset the AUTOINCREMENT counter.
        cursor.execute("""
            DELETE FROM sqlite_sequence
            WHERE name = 'scans'
        """)

        connection.commit()
        return True

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()
    """Delete all scan records and reset their auto-increment IDs."""

    connection = get_connection()
    cursor = connection.cursor()

    try:
        # Delete device records first.
        cursor.execute("DELETE FROM devices")

        # Delete all scan records.
        cursor.execute("DELETE FROM scans")

        # Reset SQLite auto-increment counters.
        cursor.execute("""
            DELETE FROM sqlite_sequence
            WHERE name IN ('scans', 'devices')
        """)

        connection.commit()
        return True

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()

    """Delete all saved scans and their associated device records."""

    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute("DELETE FROM devices")
        cursor.execute("DELETE FROM scans")

        connection.commit()
        return True

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()