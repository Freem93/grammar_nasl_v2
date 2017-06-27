#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85542);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id("CVE-2015-4289");
  script_bugtraq_id(76125);
  script_osvdb_id(125590);
  script_xref(name:"CISCO-BUG-ID", value:"CSCut93920");

  script_name(english:"Mac OS X : Cisco AnyConnect Secure Mobility Client 3.x < 3.1.10010.0 / 4.x < 4.1.4011.0 Arbitrary File Write");
  script_summary(english:"Checks the version of the Cisco AnyConnect client.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an arbitrary file write vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Cisco AnyConnect Secure Mobility Client installed on the remote
Mac OS X host is version 3.x prior to 3.1.10010.0 or 4.x prior to
4.1.4011.0. It is, therefore, affected by a flaw due to improper
sanitization of user-supplied input. An unauthenticated, remote
attacker can exploit this issue, by convincing a user to connect to a
malicious head-end system, to traverse outside a restricted path and
thus write or overwrite arbitrary files in the active user's context.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=40175");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Cisco AnyConnect Secure Mobility Client version
3.1.10010.0 / 4.1.4011.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/19");

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

if (ver =~ "^4\.[01]\." && (ver_compare(ver:ver, fix:'4.1.4011.0', strict:FALSE) < 0))
  fix = '4.1.4011.0';
else if (ver =~ "^3\." &&ver_compare(ver:ver, fix:'3.1.10010.0', strict:FALSE) < 0)
  fix = '3.1.10010.0';
else
  fix = NULL;

if (!isnull(fix))
{
  if (report_verbosity > 0)
  {
    report +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, ver, path);
