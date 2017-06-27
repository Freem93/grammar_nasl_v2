#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94961);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/01/24 17:46:05 $");

  script_cve_id("CVE-2016-0396");
  script_bugtraq_id(94155);
  script_osvdb_id(146863);
  script_name(english:"IBM BigFix Platform 9.x < 9.5.3 Remote Command Injection");
  script_summary(english:"Checks the version of the IBM BigFix Web Reports.");

  script_set_attribute(attribute:"synopsis", value:
"An infrastructure management application running on the remote host
is affected by a remote command injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IBM BigFix Platform
application running on the remote host is 9.x prior to 9.5.3. It is,
therefore, affected by a command injection vulnerability in the Web
Reports component. An unauthenticated, remote attacker can exploit
this to inject commands that are executed with privileges that are
unnecessary and higher than expected. Note that if the Web Reports
component is installed as a stand-alone application without other
BigFix components, then it not affected by the vulnerability.

IBM BigFix was formerly known as Tivoli Endpoint Manager, IBM Endpoint
Manager, and IBM BigFix Endpoint Manager.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21993206");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM BigFix Platform version 9.5.3 or later. Alternatively,
as a workaround, ensure that Web Reports is installed remotely on a
distinct and isolated machine that can be locked down (i.e., isolated
from the root server and other BigFix components).");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:bigfix_platform");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:bigfix_webreports");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("ibm_bigfix_webreports_detect.nbin");
  script_require_keys("installed_sw/IBM BigFix Web Reports", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

# Web Reports is vulnerable only when installed with
# other BigFix component(s)
if (report_paranoia < 2) audit(AUDIT_PARANOID);

appname = "IBM BigFix Web Reports";
port = get_http_port(default:8080);

install = get_install_from_kb(
  appname : appname,
  port    : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
install_url = build_url(port:port, qs:dir);

version = install["ver"];
if (version == UNKNOWN_VER) 
  audit(AUDIT_UNKNOWN_WEB_APP_VER, appname, install_url);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if(max_index(ver) < 3) 
  audit(AUDIT_VER_NOT_GRANULAR, appname, port, version);

# 9.0, 9.1, 9.2 all vuln
# 9.5: fixed in 9.5.3.x  
# assume version < 9.x not vulnerable as they are not listed
# in the advisory
if (
    ver[0] == 9 &&
    ((ver[1] == 0 || ver[1] == 1 || ver[1] == 2)  
     || (ver[1] == 5 && ver[2] < 3 )
    )
)
{
  report =
    '\n  URL               : ' + install_url +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 9.5.3.x\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else 
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, version);
}
