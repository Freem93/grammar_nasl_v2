#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76590);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/29 20:42:34 $");

  script_cve_id(
    "CVE-2012-1531",
    "CVE-2012-3202",
    "CVE-2012-5081",
    "CVE-2012-5083",
    "CVE-2012-5085"
  );
  script_bugtraq_id(56025, 56033, 56050, 56067, 56071);
  script_osvdb_id(86344, 86345, 86369, 86374);

  script_name(english:"Oracle JRockit R27 < R27.7.4.5 / R28 < R28.2.5.20 Multiple Vulnerabilities (October 2012 CPU)");
  script_summary(english:"Checks version of jvm.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of Oracle JRockit that is affected by
multiple vulnerabilities that could allow a remote attacker to execute
arbitrary code via unspecified vectors.");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2012-1515893.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1cef09be");
  script_set_attribute(attribute:"solution", value:"Upgrade to version R27.7.4.5 / R28.2.5.20 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jrockit");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("oracle_jrockit_installed.nasl");
  script_require_keys("installed_sw/Oracle JRockit");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app     = "Oracle JRockit";
get_install_count(app_name:app, exit_if_zero:TRUE);
install = get_single_install(app_name:app);
ver     = install['version'];
type    = install['type'];
path    = install['path'];

# 26 and below may not be supported, may not be affected --
# it's not listed as affected so we do not check it.
if (ver_compare(ver:ver, fix:"27", strict:FALSE) < 0) audit(AUDIT_INST_VER_NOT_VULN, app);

if (ver_compare(ver:ver, fix:"28", strict:FALSE) < 0)
{
  compare = "27.7.4";
  fix     = "27.7.4.5";
}
else
{
  compare = "28.2.5";
  fix     = "28.2.5.20";
}

if (ver_compare(ver:ver, fix:compare, strict:FALSE) >= 0) audit(AUDIT_INST_VER_NOT_VULN, app);

# The DLL we're looking at is a level deeper in the JDK, since it
# keeps a subset of the JRE in a subdirectory.
if (type == "JDK")  path += "\jre";

path += "\bin\jrockit\jvm.dll";

report =
  '\n  Type              : ' + type +
  '\n  Path              : ' + path +
  '\n  Installed version : ' + ver +
  '\n  Fixed version     : ' + fix +
  '\n';

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (report_verbosity > 0) security_hole(port:port, extra:report);
else security_hole(port);
