
from flask import (
    Flask,
    render_template,
    request,
    abort,
    session,
    redirect,
    url_for,
    flash
)

from core.network_detector import get_network_details
from core.device_discovery import discover_devices
from core.device_identifier import identify_device
from core.security_assessment import assess_device
from core.router_manager import get_blocking_capability

from database.database_manager import (
    initialize_database,
    save_scan,
    get_scan_history,
    get_scan_details,
    get_device_details,
    clear_scan_history
)


app = Flask(__name__)

# Secret key for session data and flash messages.
app.secret_key = "network-scanner-local-secret-key"

# Initialize SQLite database.
initialize_database()


@app.route("/", methods=["GET", "POST"])
def dashboard():

    # Default initial dashboard state.
    network = None
    blocking = None
    devices = []
    scan_error = None
    scan_performed = False

    if request.method == "POST":

        # Clear previous temporary scan data.
        session.pop("scan_results", None)
        session.pop("scan_error", None)
        session.pop("scan_network", None)
        session.pop("scan_performed", None)

        try:
            # Detect network after the user starts scanning.
            network = get_network_details()

            if network.get("error"):

                session["scan_error"] = network["error"]

            else:

                # Discover devices on the detected network.
                result = discover_devices(network["network"])

                if isinstance(result, dict) and "error" in result:

                    session["scan_error"] = result["error"]

                else:

                    for device in result:

                        identification = identify_device(
                            device["mac"],
                            device["ip"],
                            network.get("gateway")
                        )

                        device.update(identification)

                        assessment = assess_device(device)
                        device.update(assessment)

                        devices.append(device)

                    # Save scan results to SQLite.
                    save_scan(network["network"], devices)

                    # Store results temporarily for display.
                    session["scan_results"] = devices

            # Store detected network information.
            session["scan_network"] = network

            # A completed attempt counts even if no devices are found.
            session["scan_performed"] = True

        except Exception as error:

            app.logger.exception("Network scan failed")

            session["scan_error"] = (
                f"An error occurred during scanning: {error}"
            )

            if network is not None:
                session["scan_network"] = network

            session["scan_performed"] = True

        # Redirect to GET after processing POST.
        return redirect(url_for("dashboard"))

    # Retrieve temporary scan data once.
    devices = session.pop("scan_results", [])
    scan_error = session.pop("scan_error", None)
    network = session.pop("scan_network", None)
    scan_performed = session.pop("scan_performed", False)

    # Show blocking status only when network detection succeeds.
    if scan_performed and network and not network.get("error"):
        blocking = get_blocking_capability(network)

    # Calculate summary statistics.
    total_devices = len(devices)

    high_risk = sum(
        1 for device in devices
        if device["risk_level"] == "High"
    )

    medium_risk = sum(
        1 for device in devices
        if device["risk_level"] == "Medium"
    )

    low_risk = sum(
        1 for device in devices
        if device["risk_level"] == "Low"
    )

    return render_template(
        "index.html",
        network=network,
        blocking=blocking,
        devices=devices,
        scan_error=scan_error,
        scan_performed=scan_performed,
        total_devices=total_devices,
        high_risk=high_risk,
        medium_risk=medium_risk,
        low_risk=low_risk
    )


# View scan history.
@app.route("/history")
def history():

    scans = get_scan_history()

    return render_template(
        "history.html",
        scans=scans
    )


# Delete all scan history.
@app.route("/history/delete", methods=["POST"])
def delete_history():

    # Check whether records exist before deleting.
    scans = get_scan_history()

    if not scans:
        return redirect(url_for("history"))

    try:
        clear_scan_history()

        flash(
            "All scan history has been deleted successfully.",
            "success"
        )

    except Exception:
        app.logger.exception("Unable to delete scan history")

        flash(
            "An error occurred while deleting scan history.",
            "error"
        )

    return redirect(url_for("history"))


# View details of a particular scan.
@app.route("/history/<int:scan_id>")
def scan_details(scan_id):

    scans = get_scan_history()

    selected_scan = next(
        (scan for scan in scans if scan["id"] == scan_id),
        None
    )

    if selected_scan is None:
        abort(404)

    devices = get_scan_details(scan_id)

    return render_template(
        "scan_details.html",
        scan=selected_scan,
        devices=devices
    )


# View details of a particular device.
@app.route("/device/<int:device_id>")
def device_details(device_id):

    device = get_device_details(device_id)

    if device is None:
        abort(404)

    return render_template(
        "device_details.html",
        device=device
    )


if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
