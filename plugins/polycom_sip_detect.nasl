#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70067);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/09/23 15:16:31 $");

  script_name(english:"Polycom SIP Detection");
  script_summary(english:"Detects Polycom SIP Service");

  script_set_attribute(attribute:"synopsis", value:"The remote host is running a PBX.");
  script_set_attribute(attribute:"description", value:
"One or more Polycom SIP services are listening on the remote host. 
This is an indication that the remote host is a Polycom device.");
  script_set_attribute(attribute:"see_also", value:"http://www.polycom.com/");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:polycom:hdx_system_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("sip_detection.nasl");
  script_require_ports("Services/sip", "Services/udp/sip");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Put together a list of all TCP and UDP ports that were identified as
# SIP.
i = 0;
ports = make_list();
foreach proto (make_list("tcp", "udp"))
{
  if (proto == "tcp")
    list = get_kb_list("Services/sip");
  else
    list = get_kb_list("Services/" + proto + "/sip");

  if (isnull(list))
    continue;

  list = make_list(list);
  foreach port (list)
    ports[i++] = make_list(proto, port);
}

if (i == 0)
  exit(0, "The remote host does not appear to have any SIP services.");

# Branch, taking one protocol:port pair each.
pair = branch(ports);
proto = pair[0];
port = pair[1];

if (proto == "tcp")
  banner = get_kb_item("sip/banner/" + port);
else
  banner = get_kb_item("sip/banner/" + proto + "/" + port);

if (isnull(banner))
  exit(0, "Failed to find a SIP banner on " + proto + " port " + port + ".");

matches = eregmatch(string:banner, pattern:"^Polycom (ITP|HDX|VSX) ([^(]+) \(Release - (([0-9._]+)-\d+)\)$");
if (isnull(matches)) audit(AUDIT_HOST_NONE, "Polycom HDX SIP services");

kb = "sip/polycom/" + tolower(matches[1]);
pair = proto + "/" + port;
set_kb_item(name:kb, value:pair);
set_kb_item(name:kb + "/" + pair + "/model", value:matches[2]);
set_kb_item(name:kb + "/" + pair + "/full_version", value:matches[3]);
set_kb_item(name:kb + "/" + pair + "/version", value:matches[4]);

report =
  '\nNessus found the following Polycom SIP service :' +
  '\n' +
  '\n  SIP banner : ' + banner +
  '\n  Model      : ' + matches[2] +
  '\n  Version    : ' + matches[3] +
  '\n';

security_note(port:port, protocol:proto, extra:report);
