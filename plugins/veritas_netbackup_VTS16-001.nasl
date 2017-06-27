#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91126);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/05/19 14:17:02 $");

  script_cve_id("CVE-2015-6550", "CVE-2015-6551", "CVE-2015-6552");
  script_osvdb_id(137984, 137985, 137986);

  script_name(english:"Veritas NetBackup 7.x < 7.7.2 Multiple Vulnerabilities (VTS16-001)");
  script_summary(english:"Checks the version and hotfixes of NetBackup.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a back-up management application installed that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Veritas NetBackup installation on the remote Windows host is 7.x
prior to version 7.7.2 or is missing a vendor supplied hotfix. It is,
therefore, affected by multiple vulnerabilities :

  - A remote command execution vulnerability exists in the
    bpcd service due to a failure to properly sanitize
    user-supplied input. An unauthenticated, remote attacker
    can exploit this to execute arbitrary commands.
    (CVE-2015-6550)

  - An information disclosure vulnerability exists due to
    insufficient protection of communication between the NBU
    server and the administration console. A
    man-in-the-middle attacker can exploit this to disclose
    sensitive information including login credentials.
    (CVE-2015-6551)

  - An unspecified flaw exists that allows a remote attacker
    to execute arbitrary RPC calls. (CVE-2015-6552)");
  script_set_attribute(attribute:"see_also", value:"https://www.veritas.com/content/support/en_US/security/VTS16-001.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Veritas NetBackup version 7.7.2 or later. Alternatively,
apply the vendor-supplied hotfix as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:veritas:netbackup");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("veritas_netbackup_installed.nbin");
  script_require_keys("installed_sw/NetBackup");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = "NetBackup";

install = get_single_install(
  app_name : app,
  exit_if_unknown_ver : TRUE
);
path    = install["path"];
version = install["version"];
type    = install["Install type"];
patches = install["Patches"];

port = get_kb_item('SMB/transport');
if (!port) port = 445;

hotfix = NULL;
fix = NULL;

if (report_paranoia == 2) potential = TRUE;
else potential = FALSE;

if (version =~ "^7\.7\.2(\.0)?$")
{
  if (potential) hotfix = "ET3871154";
}
else if (version =~ "^7\.7\.1(\.0)?$")
{
  fix = "7.7.2";
  if (potential) hotfix = "ET3871154";
}
else if (version =~ "^7\.7(\.0)?(\.0)?$")
{
  hotfix = "ET3864869";
}
else if (version =~ "^7\.6\.1(\.[0-2])?$")
{
  if (version =~ "^7\.6\.1(\.[01])?$")
    fix = "7.6.1.2";
  hotfix = "ET3865353";
}
else if (version =~ "^7\.6\.0(\.[0-4])?$")
{
  if (version =~ "^7\.6\.0(\.[0-3])?$")
    fix = "7.6.0.4";
  hotfix = "ET3865357";
}
else if (version =~ "^(7\.5\.0(\.[0-7])?$|7\.[01]\.)")
{
  if (version =~ "^(7\.5\.0(\.[0-6])?$|7\.[01]\.)")
    fix = "7.5.0.7";
  hotfix = "ET3865362";
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

vuln = FALSE;
missing = FALSE;

if (hotfix && (empty_or_null(patches) || hotfix >!< patches)) missing = TRUE;

if (fix && missing) # Needs upgrade + hotfix
{
  report =
    '\n  Path                  : ' + path    +
    '\n  Installed version     : ' + version +
    '\n  Installed type        : ' + type    +
    '\n  Minimum fixed version : ' + fix     +
    '\n  Missing hotfix        : ' + hotfix  + '\n';
  vuln = TRUE;
}
else if (fix) # Just needs upgrade
{
  report =
    '\n  Path                  : ' + path    +
    '\n  Installed version     : ' + version +
    '\n  Installed type        : ' + type    +
    '\n  Minimum fixed version : ' + fix     + '\n';
  vuln = TRUE;
}
else if (missing) # Missing hotfix
{
  report =
    '\n  Path              : ' + path    +
    '\n  Installed version : ' + version +
    '\n  Installed type    : ' + type    +
    '\n  Missing hotfix    : ' + hotfix  + '\n';
  vuln = TRUE;
}

if (potential)
{
  report += '\n  Please note that this hotfix only applies in environments where the Java' +
            '\n  interface is used to communicate with backend systems.\n';
}

if (vuln)
{
  if (report_verbosity > 0) security_hole(port:0, extra:report);
  else security_hole(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
