#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85266);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/04/27 19:46:26 $");

  script_cve_id("CVE-2015-0664", "CVE-2015-0665");
  script_bugtraq_id(73120);
  script_osvdb_id(119611, 119613);
  script_xref(name:"CISCO-BUG-ID", value:"CSCus79173");
  script_xref(name:"CISCO-BUG-ID", value:"CSCus79195");

  script_name(english:"Cisco AnyConnect Secure Mobility Client < 3.1.8009.0 / 4.0.x < 4.0.2052.0 / 4.1.x < 4.1.28.0 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of the Cisco AnyConnect client.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Cisco AnyConnect Secure Mobility Client installed on the remote
host is a version prior to 3.1.8009.0, or is version 4.0.x prior to
4.0.2052.0, or version 4.1.x prior to 4.1.28.0. It is, therefore,
affected by the following vulnerabilities :

  - A flaw exists due to not sanitizing the input of IPC
    commands. A local attacker, using a specially crafted
    IPC command, can exploit this to write to arbitrary user
    space memory and execute code with escalated privileges.
    (CVE-2015-0664)

  - A path traversal flaw exists due to the Hostscan module
    not properly sanitizing user input in certain IPC
    commands. A local, authenticated attacker, using a
    specially crafted IPC command, can exploit this to
    traverse outside restricted paths and write or overwrite
    arbitrary files. (CVE-2015-0665)");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37861");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37862");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco AnyConnect Secure Mobility Client version
3.1.8009.0 / 4.0.2052.0 / 4.1.28.0 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

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

fix = '';

if (ver =~ "^4\.1\." && (ver_compare(ver:ver, fix:'4.1.28.0', strict:FALSE) < 0))
  fix = '4.1.28.0';
else if (ver =~ "^4\.0\." && (ver_compare(ver:ver, fix:'4.0.2052.0', strict:FALSE) < 0))
  fix = '4.0.2052.0';
else if (ver_compare(ver:ver, fix:'3.1.8009.0', strict:FALSE) < 0)
  fix = '3.1.8009.0';

if (!empty(fix))
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
