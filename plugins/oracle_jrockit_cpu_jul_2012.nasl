#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78086);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/09 15:44:48 $");

  script_cve_id("CVE-2012-3135");
  script_bugtraq_id(54494);
  script_osvdb_id(82874, 82883, 82884, 82885, 82886);

  script_name(english:"Oracle JRockit R27 < R27.7.3.6 / R28 < R28.2.4.14 Unspecified Vulnerability (July 2012 CPU)");
  script_summary(english:"Checks the version of jvm.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
affected by an unspecified vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of Oracle JRockit that is affected by an
unspecified vulnerability related to the 'Multiple' protocol, which a
remote attacker can exploit to impact the host's confidentiality,
integrity, and availability.");
  # http://www.oracle.com/technetwork/topics/security/cpujul2012-392727.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd39edea");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version R27.7.3.6 / R28.2.4.14 or later as referenced in
the July 2012 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jrockit");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("oracle_jrockit_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Oracle JRockit");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app     = "Oracle JRockit";

install = get_single_install(app_name:app);
ver     = install['version'];
type    = install['type'];
path    = install['path'];

# 26 and below may not be supported, may not be affected --
# it's not listed as affected so we do not check it.
if (ver_compare(ver:ver, fix:"27", strict:FALSE) < 0) audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);

vulnerable = FALSE;
# Determine if the install is vulnerable, splitting the cases into
# v27 and below, and v28 above.
if (ver_compare(ver:ver, fix:"28", strict:FALSE) < 0)
{
  # Versions in the 27 branch below the fix are affected
  fix = "27.7.2"; # Vulnerable according to advisory
  fix_disp = "27.7.3.6"; # Version pulled from patch
  if (
    ver_compare(ver:ver,fix:"27",strict:FALSE) >= 0 &&
    ver_compare(ver:ver,fix:fix,strict:FALSE) <= 0
  ) vulnerable = TRUE;
}
else
{
  # Versions in the 28 branch
  fix = "28.2.3"; # Vulnerable according to advisory
  fix_disp = "28.2.4.14"; # Version pulled from patch
  if (
    ver_compare(ver:ver,fix:"28",strict:FALSE) >= 0 &&
    ver_compare(ver:ver,fix:fix,strict:FALSE) <= 0
  ) vulnerable = TRUE;
}

# The DLL we're looking at is a level deeper in the JDK, since it
# keeps a subset of the JRE in a subdirectory.
if (type == "JDK")  path += "\jre";

path += "\bin\jrockit\jvm.dll";

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (vulnerable)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Type              : ' + type +
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix_disp +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);
