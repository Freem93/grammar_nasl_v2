#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81979);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id("CVE-2015-0662");
  script_bugtraq_id(73123);
  script_osvdb_id(119609);
  script_xref(name:"CISCO-BUG-ID", value:"CSCus79385");

  script_name(english:"Mac OS X : Cisco AnyConnect Secure Mobility Client < 3.1.10010.0 / 4.0.x < 4.0.4014.0 / 4.1.x < 4.1.4011.0 Code Execution Vulnerability");
  script_summary(english:"Checks the version of the Cisco AnyConnect client.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Cisco AnyConnect Secure Mobility Client installed on the remote
Mac OS X host is a version prior to 3.1.10010.0, or is version 4.0.x
prior to 4.0.4014.0, or version 4.1.x prior to 4.1.4011.0. It is,
therefore, affected by a flaw that allows unauthenticated IPC commands
to install software as root. A local attacker, by sending a specially
crafted IPC command, can exploit this to execute arbitrary programs
with elevated privileges.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37860");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco AnyConnect Secure Mobility Client version
3.1.10010.0 / 4.0.4014.0 / 4.1.4011.0 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_cisco_anyconnect_installed.nasl");
  script_require_keys("installed_sw/Cisco AnyConnect Secure Mobility Client", "Host/MacOSX/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("Host/MacOSX/Version");

appname = "Cisco AnyConnect Secure Mobility Client";

install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);
path = install['path'];
ver  = install['version'];

fix = '';

if (ver =~ "^4\.1\." && (ver_compare(ver:ver, fix:'4.1.4011.0', strict:FALSE) < 0))
  fix = '4.1.4011.0';
else if (ver =~ "^4\.0\." && (ver_compare(ver:ver, fix:'4.0.4014.0', strict:FALSE) < 0))
  fix = '4.0.4014.0';
else if (ver_compare(ver:ver, fix:'3.1.10010.0', strict:FALSE) < 0)
  fix = '3.1.10010.0';

if (!empty(fix))
{
  if (report_verbosity > 0)
  {
    report +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, ver, path);
