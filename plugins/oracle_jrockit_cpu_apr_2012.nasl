#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76683);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/07 20:46:55 $");

  script_cve_id(
    "CVE-2012-1695",
    "CVE-2012-0497",
    "CVE-2012-0498",
    "CVE-2012-0499",
    "CVE-2011-3563",
    "CVE-2012-0501",
    "CVE-2011-5035"
  );
  script_bugtraq_id(
    57087,
    52009,
    52019,
    52016,
    52012,
    52013,
    51194
  );
  script_osvdb_id(
    81407,
    89190,
    78114,
    79225,
    79226,
    79228,
    79235,
    79236
  );

  script_name(english:"Oracle JRockit R27 < R27.7.2.5 / R28 < R28.2.3.13 Multiple Vulnerabilities (April 2012 CPU)");
  script_summary(english:"Checks the version of jvm.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of Oracle JRockit that is affected by
multiple vulnerabilities that could allow a remote attacker to
compromise system confidentiality and integrity via unspecified
vectors.");
  script_set_attribute(attribute:"solution", value:"Upgrade to version R27.7.2.5 / R28.2.3.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  # http://www.oracle.com/technetwork/topics/security/cpuapr2012-366314.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9865fa8a");
script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jrockit");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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
  compare = "27.7.2";
  fix     = "27.7.2.5";
}
else
{
  compare = "28.2.3";
  fix     = "28.2.3.13";
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
