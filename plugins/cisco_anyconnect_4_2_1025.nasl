#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87894);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/28 18:15:08 $");

  script_cve_id("CVE-2015-6322");
  script_bugtraq_id(77055);
  script_osvdb_id(128673);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv48563");
  script_xref(name:"CISCO-SA", value: "cisco-sa-20151008-asmc");

  script_name(english:"Cisco AnyConnect Secure Mobility Client 2.x < 3.1.13015.0 / 4.x < 4.2.1035.0 Arbitrary File Manipulation");
  script_summary(english:"Checks the version of the Cisco AnyConnect client.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an arbitrary file manipulation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Cisco AnyConnect Secure Mobility Client installed on the remote
host is version 2.x or 3.x prior to 3.1.13015.0 or 4.x prior to
4.2.1035.0. It is, therefore, affected by an arbitrary file
manipulation vulnerability due to missing source path validation in
interprocess communication (IPC) commands. A local attacker can
exploit this, via crafted IPC messages, to move arbitrary files with
elevated privileges, resulting in a loss of integrity and a denial of
service condition.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20151008-asmc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?20e0379d");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuv48563");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco AnyConnect Secure Mobility Client version
3.1.13015.0 / 4.2.1035.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_anyconnect_vpn_installed.nasl");
  script_require_keys("installed_sw/Cisco AnyConnect Secure Mobility Client", "SMB/Registry/Enumerated");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_name = "Cisco AnyConnect Secure Mobility Client";

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
path = install['path'];
ver  = install['version'];

if (ver =~ "^4\." && (ver_compare(ver:ver, fix:'4.2.1035.0', strict:FALSE) < 0))
  fix = '4.2.1035.0';
else if (ver =~ "^[2-3]\." && ver_compare(ver:ver, fix:'3.1.13015.0', strict:FALSE) < 0)
  fix = '3.1.13015.0';
else
  fix = NULL;

if (!isnull(fix))
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, ver, path);
