#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96627);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/01/27 15:06:51 $");

  script_cve_id(
    "CVE-2016-5546",
    "CVE-2016-5547",
    "CVE-2016-5552",
    "CVE-2017-3241",
    "CVE-2017-3252",
    "CVE-2017-3253"
  );
  script_bugtraq_id(
    95488,
    95498,
    95506,
    95509,
    95512,
    95521
  );
  script_osvdb_id(
    150417,
    150419,
    150420,
    150423,
    150425,
    150426
  );

  script_name(english:"Oracle JRockit R28.3.12 Multiple Vulnerabilities (January 2017 CPU)");
  script_summary(english:"Checks the version of jvm.dll.");

  script_set_attribute(attribute:"synopsis", value:
"A programming platform installed on the remote Windows host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle JRockit installed on the remote Windows host is
R28.3.12. It is, therefore, affected by multiple vulnerabilities :

  - An unspecified flaw exists in the Libraries subcomponent
    that allows an unauthenticated, remote attacker to
    impact integrity. (CVE-2016-5546)

  - An unspecified flaw exists in the Libraries subcomponent
    that allows an unauthenticated, remote attacker to cause
    a denial of service condition. (CVE-2016-5547)

  - An unspecified flaw exists in the Networking
    subcomponent that allows an unauthenticated, remote
    attacker to impact integrity. (CVE-2016-5552)

  - An unspecified flaw exists in the RMI subcomponent that
    allows an unauthenticated, remote attacker to execute
    arbitrary code.  (CVE-2017-3241)

  - An unspecified flaw exists in the JAAS subcomponent that
    allows an unauthenticated, remote attacker to impact
    integrity. (CVE-2017-3252)

  - An unspecified flaw exists in the 2D subcomponent that
    allows an unauthenticated, remote attacker to cause a
    denial of service condition. (CVE-2017-3253)

Note that CVE-2017-3241 can only be exploited by supplying
data to APIs in the specified component without using
untrusted Java Web Start applications or untrusted Java
applets, such as through a web service. Note that
CVE-2016-5546, CVE-2016-5547, CVE-2016-5552, CVE-2017-3252,
and CVE-2017-3253 can be exploited through sandboxed Java
Web Start applications and sandboxed Java applets. They can
also be exploited by supplying data to APIs in the specified
component without using sandboxed Java Web Start
applications or sandboxed Java applets, such as through a
web service.");
  # http://www.oracle.com/technetwork/security-advisory/cpujan2017-2881727.html#AppendixJAVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?951bfdb7");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JRockit version R28.3.13 or later as referenced in
the January 2017 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jrockit");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("oracle_jrockit_installed.nasl");
  script_require_keys("installed_sw/Oracle JRockit");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app     = "Oracle JRockit";
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
ver     = install['version'];
type    = install['type'];
path    = install['path'];

if (ver =~ "^28(\.3)?$") audit(AUDIT_VER_NOT_GRANULAR, app, ver);
if (ver !~ "^28\.3($|[^0-9])") audit(AUDIT_NOT_INST, app + " 28.3.x");

# Affected :
# 28.3.12
if (ver =~ "^28\.3\.12($|[^0-9])")
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  # The DLL we're looking at is a level deeper in the JDK, since it
  # keeps a subset of the JRE in a subdirectory.
  if (type == "JDK")  path += "\jre";
  path += "\bin\jrockit\jvm.dll";

  report =
    '\n  Type              : ' + type +
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver  +
    '\n  Fixed version     : 28.3.13'  +
    '\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);
