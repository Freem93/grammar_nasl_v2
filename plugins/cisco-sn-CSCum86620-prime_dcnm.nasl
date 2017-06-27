#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77681);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/02 19:32:50 $");

  script_cve_id("CVE-2014-3329");
  script_bugtraq_id(68926);
  script_osvdb_id(109610);
  script_xref(name:"CISCO-BUG-ID", value:"CSCum86620");

  script_name(english:"Cisco Prime Data Center Network Manager 6.x XSS (uncredentialed check)");
  script_summary(english:"Checks the DCNM version number.");

  script_set_attribute(attribute:"synopsis", value:
"A network management system on the remote host is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Cisco
Prime Data Center Network Manager (DCNM) installed on the remote host
is affected by a cross-site scripting vulnerability due to
insufficient validation of input parameters by its web server
component. Using a specially crafted URL, a remote attacker could
inject arbitrary script or HTML code.

This plugin determines if DCNM is vulnerable by checking the version
number displayed in the web interface. The web interface is not
available in older versions of DCNM.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2014-3329
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?188ffbab");
  script_set_attribute(attribute:"solution", value:"Apply the vendor patch referenced in Cisco bug CSCum86620.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_data_center_network_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

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

# Affected :
# 6.1 Base, (1) | 6.2 (1), (3), (5), (5a) | 6.3 (1), (2)
# 6.3(0.9)
if (
  # 6.1 Base, (1)
  major == '6.1' && build =~ "^[01]$" ||
  # 6.2 (1), (3), (5)
  major == '6.2' && build =~ "^[135]$" ||
  # 6.2 (5a)
  major == '6.2' && build == "5a" ||
  # 6.3 (1), (2)
  major == '6.3' && build =~ "^[12]$" ||
  # 6.3(0.9)
  major == '6.3' && build == "0.9"
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : See solution' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, ver);
