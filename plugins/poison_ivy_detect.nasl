#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69320);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/04/25 14:31:39 $");
  script_name(english:"Poison Ivy Detection");
  script_summary(english:"Detects an installation of the Poison Ivy server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host runs a potentially malicious remote administration
tool.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a Poison Ivy client.  Poison Ivy is a Remote
Administration Tool (RAT) used to control computers infected by malware. 
The 'client' is the component used to control those computers.  It is
associated with malicious activity.");
  script_set_attribute(attribute:"see_also", value:"http://www.poisonivy-rat.com/");
  # https://www.microsoft.com/security/portal/threat/encyclopedia/entry.aspx?Name=Backdoor%3AWin32%2FPoisonivy.I
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?34182a5d");
  # https://web.archive.org/web/20160630215250/https://www.securityweek.com/poison-ivy-kit-enables-easy-malware-customization-attackers
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac402881");

  script_set_attribute(
    attribute:"solution",
    value:
"Ensure that use of this software is intentional.  If not, remove the
software and scan potentially affected hosts with malware removal
software."
  );
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:poisonivy:poisonivy");
  script_set_attribute(attribute:"malware", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 3460);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

function detect_poison_ivy()
{
  local_var soc;
  soc = _FCT_ANON_ARGS[0];

  send(socket:soc, data:crap(length:0x100, data:raw_string(0)));

  # Skip the first 0x100 bytes.
  local_var response;
  response = recv(socket:soc, length:0x100);
  if (isnull(response) || strlen(response) < 0x100)
    return FALSE;

  # Read and check magic.
  response = recv(socket:soc, length:4);
  if (isnull(response) || response != '\xD0\x15\x00\x00')
    return FALSE;

  return TRUE;
}

port = 3460;
if (thorough_tests && !get_kb_item("global_settings/disable_service_discovery"))
{
  port = get_unknown_svc(port);
  if (!port) audit(AUDIT_SVC_KNOWN);
}
if (known_service(port:port)) exit(0, "The service on port " + port + " has already been identified.");
if (!get_tcp_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

detected = detect_poison_ivy(soc);

close(soc);

if (!detected) audit(AUDIT_NOT_DETECT, "Poison Ivy", port);

register_service(port:port, ipproto:"tcp", proto:"poison_ivy");

security_note(port:port);
