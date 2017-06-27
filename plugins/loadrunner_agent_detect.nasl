#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24326);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/06/04 20:59:44 $");

  script_name(english:"HP LoadRunner Agent Service Detection");
  script_summary(english:"Attempts to initialize a connection to an HP LoadRunner Agent.");

  script_set_attribute(attribute:"synopsis", value:
"An HP LoadRunner Agent is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"An HP LoadRunner Agent is listening on the remote host. This agent
enables a LoadRunner Controller to communicate with the LoadRunner
Load Generator on the remote host for performance testing. Note that
Hewlett-Packard acquired LoadRunner in November 2006 as part of its
acquisition of Mercury Interactive.");
  # http://www8.hp.com/us/en/software-solutions/loadrunner-load-testing/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bfc4e1a5");
  # http://web.archive.org/web/20070810111650/http://www.mercury.com/us/products/performance-center/loadrunner/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7ea6b97b");
  script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port to hosts using the LoadRunner
Controller.");
  script_set_attribute(attribute:"risk_factor", value:"None" );

  script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:loadrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:mercury_loadrunner_agent");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 443, 54345);

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") ) {
  port = get_unknown_svc(54345);
  if (!port) audit(AUDIT_SVC_KNOWN);
}
else port = 54345;

if (known_service(port:port)) audit(AUDIT_SVC_KNOWN);
if (!get_tcp_port_state(port)) audit(AUDIT_PORT_CLOSED,port);
if ( safe_checks() && port == 4786 ) exit(1, "Not probing port 4786 due to cisco-sa-20110928-smart-install."); # Cerb#EIP-64406-216

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL,port);

function mk_padded_string(str)
{
  return mkdword(strlen(str)) + str + crap(data:mkbyte(0), length:4-(strlen(str) % 4));
}

# Define some constants.
guid = base64(str:rand_str(length:17));
pid = rand() % 0xffff;
tid = rand() % 0xffff;
rand16 = crap(16);
server_name = "nessus";
server_ip = this_host();
server_port = get_source_port(soc);

# Initialize a connection.
#
# - first part.
req1 = mkdword(0x19);
send(socket:soc, data:req1);
# - second part.
req2_1 = guid + "0";

req2_2 = 
      mkdword(7) + 
      mk_padded_string(
        str:server_name + ";" + pid + ";" + tid
      ) +
      mk_padded_string(
        str:string(
          "(-server_type=8)",
          "(-server_name=", server_name, ")",
          "(-server_full_name=", server_name, ")",
          "(-server_ip_name=", server_ip, ")",
          "(-server_port=", server_port, ")",
          "(-server_fd_secondary=4)",
          "(-guid_identifier=", guid, ")"
        )
      ) +
      mkdword(0x7530);
req2_2 = mkdword(4 + strlen(req2_2)) + req2_2;
req2_2 = 
    mkdword(0x1c) +
    mkdword(0x05) + 
    mkdword(0x01) + 
    rand16 +
    req2_2;
req2_2 = mkdword(strlen(req2_2)) + req2_2;

req2 = req2_1 + req2_2;
send(socket:soc, data:req2);

found = 0;
secure = FALSE;
# If the result is a dword and equal to 0x1c or 0x28 (v9.5)

res = recv(socket:soc, length:4);
if (strlen(res) == 4 && getdword(blob:res, pos:0) == 0x1c)
{
  # Read the rest of the packet.
  res = recv(socket:soc, length:512);

  # If the first two dwords in that are 0x0c and 0x02...
  if (strlen(res) > 8 && getdword(blob:res, pos:0) == 0x0c && getdword(blob:res, pos:4) == 0x01)
  {
    found = 1;
    set_kb_item(name:"loadrunner_agent/" + port + "/insecure_channel", value:TRUE);
  }
}
# v9.5 
else if (strlen(res) == 4 && getdword(blob:res, pos:0) == 0x28)
{
 # Read the rest of the packet.
  res = recv(socket:soc, length:512);

  if (strlen(res) >= 34 && getword(blob:res, pos:30) == 0x7530 &&  getdword(blob:res, pos:34) == 0xffffffff)
  {
    found = 1;
    set_kb_item(name:"loadrunner_agent/" + port + "/insecure_channel", value:TRUE);
  }
}
# Or if the result is a dword and equal to 0x2c ...secure channel enabled.
# 2015/06/01: This no longer seems to be valid for newer versions (~v11)
else if (strlen(res) == 4 && getdword(blob:res, pos:0) == 0x2c)
{
  res = recv(socket:soc, length:512);
  if (strlen(res) >= 38 && (getword(blob:res, pos:30) == 0x7530 &&  getdword(blob:res, pos:38) == 0xffffffff))
  {
    found = 1;
    set_kb_item(name:"loadrunner_agent/" + port + "/secure_channel", value:TRUE);
    secure = TRUE;
  }
}
# New versions (~11) just use SSL which is detected by find_service
if(get_port_transport(port) !=  ENCAPS_IP)
{
  set_kb_item(name:"loadrunner_agent/" + port + "/secure_channel", value:TRUE);
  secure = TRUE;
}
close(soc);

if (found)
{
  register_service(port:port, ipproto:"tcp", proto:"loadrunner_agent");
  report = NULL;
  if(report_verbosity > 0)
  {
    report = '\n  HP LoadRunner was found to be listening';
    if(secure)
      report += ' and has a secure channel enabled';
    report += '.\n';
  }
  security_note(port:port,extra:report);
  exit(0);
}
else
  audit(AUDIT_NOT_DETECT,"HP LoadRunner",port);
