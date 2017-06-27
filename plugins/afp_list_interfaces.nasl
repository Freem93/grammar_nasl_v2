#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79419);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/09/26 16:33:57 $");

  script_cve_id("CVE-2014-4426");
  script_bugtraq_id(70623);
  script_osvdb_id(113429);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2014-10-16-1");

  script_name(english:"AFP Server Network Interface Enumeration");
  script_summary(english:"Displays the list of network interfaces on the server.");

  script_set_attribute(attribute:'synopsis', value:"Remote users can view other network addresses.");
  script_set_attribute(attribute:'description', value:
"The AFP File Server in Apple OS X prior to version 10.10 allows remote
attackers to discover the network addresses of all interfaces via an
unspecified command to one interface.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/kb/HT6535");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2014/Oct/100");
  script_set_attribute(attribute:"solution", value:"Upgrade to OS X version 10.10 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("asip-status.nasl");

  script_require_ports("Services/appleshare");
  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("afp_func.inc");
include("misc_func.inc");

port = get_service(svc:"appleshare", default:548, exit_on_fail:TRUE);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

ret = OpenSession(soc);
if (isnull(ret) || DSI_LastError() != 0) audit(AUDIT_SVC_FAIL, "appleshare", port);

status = GetStatus();

if (isnull(status))
{
  CloseSession();

  audit(AUDIT_SVC_FAIL, "appleshare", port);
}

parsed_status = GetStatusParseReply(status);
CloseSession();

if (isnull(parsed_status) || parsed_status["address_list_count"] == 0) audit(AUDIT_OS_SP_NOT_VULN);

report = "";

if (report_verbosity > 0)
{
  report = '\nThe following interfaces can be found :\n\n';

  for (i = 0; i < parsed_status["address_list_count"]; i++)
  {
    report += '    ' + parsed_status["address_list"][i] + '\n';
  }
}

report = "It was possible to discover all interfaces via AFP file sharing on the affected host." + report;

security_warning(port:port, extra:report);
