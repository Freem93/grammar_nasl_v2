#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67247);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/17 21:12:11 $");

  script_cve_id("CVE-2007-1036", "CVE-2012-5417");
  script_bugtraq_id(56348);
  script_osvdb_id(33744, 86845);
  script_xref(name:"CERT", value:"632656");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtz44924");
  script_xref(name:"CISCO-BUG-ID", value:"CSCua31204");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20121031-dcnm");

  script_name(english:"Cisco Prime Data Center Network Manager RMI Remote Code Execution (uncredentialed check)");
  script_summary(english:"Checks DCNM version number");

  script_set_attribute(attribute:"synopsis", value:
"A network management system on the remote host has a remote code
execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Cisco
Prime Data Center Network Manager (DCNM) installed on the remote host
has a remote code execution vulnerability. Unauthorized users have
access to the JBoss Application Server Remote Method Invocation
services. A remote, unauthenticated attacker could exploit this to
execute arbitrary code as SYSTEM (on Windows) or root (on Linux).

This plugin determines if DCNM is vulnerable by checking the version
number displayed in the web interface. The web interface is not
available in older versions of DCNM.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20121031-dcnm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d3b9ebfb");
  script_set_attribute(attribute:"solution", value:"Upgrade to Cisco Prime Data Center Network Manager 6.1(2) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-12-667");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'JBoss JMX Console Deployer Upload and Execute');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_data_center_network_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_prime_dcnm_web_detect.nasl");
  script_require_keys("installed_sw/cisco_dcnm_web");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

appname = "Cisco Prime DCNM";
app_id  = "cisco_dcnm_web";
get_install_count(app_name:app_id, exit_if_zero:TRUE);

port = get_http_port(default:80);
install = get_single_install(app_name:app_id, port:port, exit_if_unknown_ver:TRUE);

url = build_url(qs:install['path'], port:port);
ver = install['version'];

match = eregmatch(string:ver, pattern:"^([0-9.]+)\(([^)]+)\)");
if (isnull(match)) exit(1, "Failed to parse the version ("+ver+").");

major = match[1];
build = match[2];

if (
  ver_compare(ver:major, fix:'6.1', strict:FALSE) > 0 ||  # < 6.1.x
  (major == '6.1' && build !~ '^1([^0-9]|$)') # 6.1.x < 6.1(2)
) audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, ver);

if (report_verbosity > 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : 6.1(2)\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
