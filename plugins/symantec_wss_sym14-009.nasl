#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74153);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_cve_id("CVE-2014-1649");
  script_bugtraq_id(67189);
  script_osvdb_id(106923);

  script_name(english:"Symantec Workspace Streaming < 7.5 SP1 XMLRPC Request Remote Code Execution (SYM14-009)");
  script_summary(english:"Checks Symantec Workspace Streaming server version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has software installed that is affected by a remote
code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Workspace Streaming server (formerly known as
Altiris Streaming System) installed on the remote Windows host is
affected by a remote code execution vulnerability. This issue is
caused by improper validation of HTTPS XMLRPC requests by the
Management Agent (as_agent.exe) component. A remote, unauthenticated
attacker could exploit this issue to execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-127/");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20140512_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29fe896e");
  script_set_attribute(attribute:"solution", value:"Upgrade to 7.5 SP1 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Symantec Workspace Streaming ManagementAgentServer.putFile XMLRPC Request Arbitrary File Upload');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:workspace_streaming");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:appstream");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_workspace_streaming_installed.nbin");
  script_require_keys("SMB/symantec_workspace_streaming_server/Installed");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app = "Symantec Workspace Streaming server";
kb_base = "SMB/symantec_workspace_streaming_server/";

version = get_kb_item_or_exit(kb_base + "Version");
path    = get_kb_item_or_exit(kb_base + "Path");

fix = "7.5.0.749";
if (ver_compare(ver:version, fix:fix, strict:FALSE) >= 0) audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix + ' (7.5 SP1)' +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
