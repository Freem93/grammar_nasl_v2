#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77682);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/02 19:32:50 $");

  script_cve_id("CVE-2014-3329");
  script_bugtraq_id(68926);
  script_osvdb_id(109610);
  script_xref(name:"CISCO-BUG-ID", value:"CSCum86620");

  script_name(english:"Cisco Prime Data Center Network Manager 6.x XSS (credentialed check)");
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
inject arbitrary script or HTML code.");
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

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_data_center_network_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("cisco_prime_dcnm_installed_win.nasl", "cisco_prime_dcnm_installed_linux.nasl");
  script_require_ports("installed_sw/Cisco Prime DCNM");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

appname = "Cisco Prime DCNM";

get_install_count(app_name:appname, exit_if_zero:TRUE);
install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);

ver  = install['version'];
path = install['path'];
display_ver = install['display_version'];

# Affected :
# 6.1 Base, (1) | 6.2 (1), (3), (5), (5a) | 6.3 (1), (2)
# 6.3(0.9)
if (
  # 6.1 Base, (1)
  ver =~ "^6\.1\.[01](\.0)?$" ||
  # 6.2 (1), (3)
  ver =~ "^6\.2\.[13](\.0)?$" ||
  # 6.2 (5), (5a)
  ver =~ "^6\.2\.(5(\.0)?|5\.1)$" ||
  # 6.3 (1), (2) and 6.3(0.9)
  ver =~ "^6\.3\.(0\.9|[12](\.0)?)$"
)
{
  # Could be Windows or *nix
  port = get_kb_item('SMB/transport');
  if (!port) port = 0;

  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + display_ver +
      '\n  Fixed version     : See solution' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, display_ver, path);
