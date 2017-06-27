#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67248);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/17 21:12:11 $");

  script_cve_id("CVE-2007-1036", "CVE-2012-5417");
  script_bugtraq_id(56348);
  script_osvdb_id(33744, 86845);
  script_xref(name:"CERT", value:"632656"); # original vulnerability in JBoss
  script_xref(name:"CISCO-BUG-ID", value:"CSCtz44924");
  script_xref(name:"CISCO-BUG-ID", value:"CSCua31204");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20121031-dcnm");

  script_name(english:"Cisco Prime Data Center Network Manager RMI Remote Code Execution (credentialed check)");
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
execute arbitrary code as SYSTEM (on Windows) or root (on Linux).");
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

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_data_center_network_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

fix = '6.1.2.0';
display_fix = '6.1(2)';

if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, appname, display_ver);

# Could be Windows or *nix
port = get_kb_item('SMB/transport');
if (!port) port = 0;

if (report_verbosity > 0)
{
  if (isnull(display_ver))
    display_ver = ver;

  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + display_ver +
    '\n  Fixed version     : ' + display_fix + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
