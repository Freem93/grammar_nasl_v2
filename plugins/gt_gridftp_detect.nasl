#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59733);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/08/28 00:43:13 $");

  script_name(english:"Globus Toolkit GridFTP Server Detection");
  script_summary(english:"Checks version reported in FTP banner");

  script_set_attribute(attribute:"synopsis", value:
"An FTP server is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host has an installation of GridFTP server, which offers
file transfer functionality.");

  script_set_attribute(attribute:"see_also", value:"http://www.globus.org/toolkit/docs/latest-stable/gridftp/");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:globus:globus_toolkit");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21, 2811);

  exit(0);
}

include("audit.inc");
include("ftp_func.inc");
include("global_settings.inc");
include("misc_func.inc");

app = "Globus Toolkit GridFTP Server";
kb = "Globus_Toolkit/GridFTP/";

# Get the ports that FTP servers have been found on, defaulting to
# what GridFTP uses in the provided configuration file.
port = get_ftp_port(default:2811);

# Get the FTP banner from the KB.
banner = get_ftp_banner(port:port);
if (isnull(banner))
  audit(AUDIT_NO_BANNER, port);
banner = chomp(banner);

# Check if it's GridFTP.
regex = "GridFTP +Server +([.\d]+)";
if (banner !~ regex)
  audit(AUDIT_NOT_DETECT, app, port);

# Parse the version string.
match = eregmatch(string:banner, pattern:regex);
if (isnull(match))
  audit(AUDIT_SERVICE_VER_FAIL, 'GridFTP', port);
ver = match[1];

# Store what we've discovered in the KB.
set_kb_item(name:kb + "Installed", value:TRUE);

kb += port + "/";
set_kb_item(name:kb + "Banner", value:banner);
set_kb_item(name:kb + "Version", value:ver);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  Version source    : ' + banner +
    '\n  Installed version : ' + ver +
    '\n';
}

security_note(port:port, extra:report);
