#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59657);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/08/28 00:43:14 $");

  script_name(english:"Network UPS Tools Detection");
  script_summary(english:"Sends a VER command to get version information");

  script_set_attribute(attribute:"synopsis", value:
"A UPS monitoring tool is running on the remote host.");
  script_set_attribute(attribute:"description", value:
"Network UPS Tools, a UPS monitoring tool, is running on the remote
host.");

  script_set_attribute(attribute:"see_also", value:"http://www.networkupstools.org/");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:networkupstools:nut");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/nut", 3493);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app = "Network UPS Tools";

# Get the ports that NUT have been found on.
port = get_service(svc:"nut", default:3493, exit_on_fail:TRUE);

# Find out if the port is open.
if (!get_port_state(port))
  audit(AUDIT_PORT_CLOSED, port);

# Connect to the port.
soc = open_sock_tcp(port);
if (!soc)
  audit(AUDIT_SVC_FAIL, app, port);

# Request the version information and receive the response.
send(socket:soc, data:'VER\r\n');
banner = recv(socket:soc, length:1024);
banner = chomp(banner);

# Extract the version number out of the banner.
matches = eregmatch(string:banner, pattern:"^Network UPS Tools upsd ([0-9.]*)");
if (isnull(matches))
  audit(AUDIT_SERVICE_VER_FAIL, 'Network UPS Tools', port);
ver = matches[1];

# Save the installation information for later.
key = "nut/" + port + "/";
set_kb_item(name:key + "banner", value:banner);
set_kb_item(name:key + "version", value:ver);

# Report our findings.
if (report_verbosity > 0)
{
  report =
    '\n  Source  : ' + banner +
    '\n  Version : ' + ver +
    '\n';
}

security_note(port:port, extra:report);

