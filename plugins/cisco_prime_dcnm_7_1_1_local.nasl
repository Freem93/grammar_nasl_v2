#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82701);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/04/27 19:46:26 $");

  script_cve_id("CVE-2015-0666");
  script_bugtraq_id(73479);
  script_osvdb_id(120184);
  script_xref(name:"CISCO-BUG-ID", value:"CSCus00241");
  script_xref(name:"IAVB", value:"2015-B-0043");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150401-dcnm");

  script_name(english:"Cisco Prime Data Center Network Manager < 7.1(1) Directory Traversal Vulnerability");
  script_summary(english:"Checks the DCNM version number.");

  script_set_attribute(attribute:"synopsis", value:
"A network management system on the remote host is affected by a
directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Cisco Prime Data
Center Network Manager (DCNM) installed on the remote host is affected
by a directory traversal vulnerability in the fmserver servlet due to
improper validation of user-supplied information. An unauthenticated,
remote attacker, using a crafted file pathname, can read arbitrary
files from the filesystem outside of a restricted path.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150401-dcnm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4477eb6");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37810");
  script_set_attribute(attribute:"solution", value:"Upgrade to Cisco Prime Data Center Network Manager 7.1(1) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_data_center_network_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

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

# Cisco Prime DCNM releases 6.3(1) and later, prior to release 7.1(1)
if (
  (ver_compare(ver:ver, fix:'6.3.1.0', strict:FALSE) < 0 ||
   ver_compare(ver:ver, fix:'7.1.1.0', strict:FALSE) >= 0)
) audit(AUDIT_INST_VER_NOT_VULN, appname, display_ver);

port = get_kb_item('SMB/transport');
if (!port) port = 0;

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : 7.1(1)\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
