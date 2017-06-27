#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59731);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/11/12 00:42:54 $");

  script_name(english:"MikroTik RouterOS Winbox Detection");
  script_summary(english:"Detects a Winbox server");

  script_set_attribute(attribute:"synopsis", value:
"A configuration service is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote port is used by Winbox, a remote management tool, to
administer devices running MikroTik RouterOS.");
  script_set_attribute(attribute:"see_also", value:"http://wiki.mikrotik.com/wiki/Manual:Winbox");
  script_set_attribute(attribute:"solution", value:"Limit access to this port to authorized hosts.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:mikrotik:winbox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 8291);

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

if (thorough_tests && !get_kb_item("global_settings/disable_service_discovery"))
{
  port = get_unknown_svc(port);
  if (!port) audit(AUDIT_SVC_KNOWN);
  if (!silent_service(port)) exit(0, "The service listening on port "+port+" is not silent.");
}
else port = 8291;

if (known_service(port:port)) exit(0, "The service on port " + port + " has already been identified.");
if (!get_tcp_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

payload = "index" + crap(length:6, data:mkbyte(0)) + 
    mkbyte(0) + mkbyte(0xff) + 
    mkbyte(0xed) + crap(length:4, data:mkbyte(0));
req = mkbyte(strlen(payload)) + mkbyte(2) + payload;
send(socket:soc, data:req);

res_1 = recv(socket:soc, length:2, min:2);
if (strlen(res_1) == 0) audit(AUDIT_RESP_NOT, port);
if (strlen(res_1) != 2) exit(0, "Failed to read 2 bytes from the service on port "+port+".");
if (getbyte(blob:res_1, pos:1) != 2) exit(0, "The response from the service on port "+port+" does not look like it's from Winbox.");


# Read the rest of the packet.
len = getbyte(blob:res_1, pos:0);
res_2 = recv(socket:soc, length:len, min:len);
if (strlen(res_2) == 0) audit(AUDIT_RESP_NOT, port);
if (strlen(res_2) != len) exit(0, "Failed to read "+len+" bytes from the service on port "+port+".");
if (
  stridx(res_2, "index" + crap(length:6, data:mkbyte(0))) != 0 ||
  getbyte(blob:res_2, pos:0x0b) != 1 ||
  getbyte(blob:res_2, pos:0x0c) != 0 ||
  getbyte(blob:res_2, pos:0x0d) + 0x12 != len ||
  substr(res_2, 0x0e, 0x11) != crap(length:4, data:mkbyte(0))
) exit(0, "The service on port "+port+" is not a Winbox service.");

# Register and report the service.
register_service(port:port, proto:"mikrotik_winbox");

report = "";

subres = substr(res_2, 0x12);
if ("roteros.dll" >< subres)
{
  foreach line (split(subres, keep:FALSE))
  {
    fields = split(line, sep:" ", keep:FALSE);
    if (
      fields[0] =~ "^[0-9]+$" &&
      fields[1] =~ "^[0-9]+$" &&
      fields[2] =~ "^[a-z][a-z0-9_]+\.dll$" &&
      fields[3] =~ "^[0-9]+\.[0-9.]+$"
    )
    {
      report += '\n  Filename : ' + fields[2] +
                '\n  Version  : ' + fields[3] +
                '\n  Size     : ' + fields[1] +
                # '\n  Checksum : ' + fields[0] + 
                '\n';
      if (fields[2] == "roteros.dll") 
      {
        set_kb_item(name:"MikroTik/Winbox/" + port + "/Version", value:fields[3]);
      }
    }
  }
}

if (report_verbosity > 0 && report) security_note(port:port, extra:report);
else security_note(port);
