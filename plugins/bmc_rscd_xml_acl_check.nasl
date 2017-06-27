#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90999);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/07/05 21:28:59 $");

  script_name(english:"BMC Server Automation RSCD Agent Weak ACL XML-RPC Arbitrary Command Execution");
  script_summary(english:"Attempts to execute an XML-RPC command.");

  script_set_attribute(attribute:"synopsis", value:
"The RSCD agent running on the remote host is affected by a remote
command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The RSCD agent running on the remote host does not have access
controls in place to prevent an attacker from executing XML-RPC
commands. An unauthenticated, remote attacker can exploit this to
execute arbitrary commands in the context of the user in which the
connections are mapped.");
  script_set_attribute(attribute:"see_also", value:"http://www.bmc.com/it-solutions/bladelogic-server-automation.html");
  script_set_attribute(attribute:"see_also", value:"https://docs.bmc.com/docs/display/bsa88/Home");
  script_set_attribute(attribute:"solution", value:
"Apply more restrictive access controls to the export file.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bmc:bladelogic_server_automation_rscd_agent");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("bmc_rscd_detect.nbin");
  script_require_ports(4750,"Services/bladelogic_rscd");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("x509_func.inc");
include("misc_func.inc");
include("byte_func.inc");
include("gunzip.inc");
include("bmc_rscd.inc");

appname = 'bladelogic_rscd';
port = get_service(svc:appname, default:4750, exit_on_fail:TRUE);
if(get_port_transport(port) != ENCAPS_IP) audit(AUDIT_LISTEN_NOT_VULN, appname, port);
if (!get_tcp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "tcp");

# Connect and send intro
soc = rscd_connect(type:"TLSRPC", port:port);
resp = send_xml_intro(soc:soc, port:port);

# If we are given access than the ACL excludes us
if (isnull(resp))
{
  close(soc);
  audit(AUDIT_INST_VER_NOT_VULN, appname);
}

payload = '<?xml version="1.0" encoding="UTF-8"?>\n' +
 '<methodCall>\n' +
 '  <methodName>RemoteServer.getHostOverview</methodName>\n' + 
 '</methodCall>';
send_xmlrpc(payload:payload, soc:soc, port:port);

# The response will have compressed XML
resp = recv(socket:soc, length:1024);
close(soc);

# There is no reason that this shouldn't succeed
if ("HTTP/1.1 200 OK" >!< resp) audit(AUDIT_RESP_BAD, port);

decompressed = decompress_payload(resp:resp);
if ("agentInstallDir" >!< decompressed) audit(AUDIT_RESP_BAD, port);

security_report_v4(
  port:port,
  severity:SECURITY_HOLE,
  request:make_list("https://" + get_host_ip() + ":" + port + "/xmlrpc"),
  cmd:"RemoteServer.getHostOverview",
  output:decompressed);
