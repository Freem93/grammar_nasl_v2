#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86474);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/28 18:52:13 $");

  script_cve_id(
    "CVE-2015-4803",
    "CVE-2015-4872",
    "CVE-2015-4893",
    "CVE-2015-4911"
  );
  script_osvdb_id(
    129137,
    129138,
    129139,
    129140
  );

  script_name(english:"Oracle JRockit R28 < R28.3.8 Multiple Vulnerabilities (October 2015 CPU)");
  script_summary(english:"Checks the version of jvm.dll.");

  script_set_attribute(attribute:"synopsis", value:
"A programming platform installed on the remote Windows host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle JRockit installed on the remote Windows host is
R28 prior to R28.3.8. It is, therefore, affected by multiple
vulnerabilities :

  - Multiple denial of service vulnerabilities exist due to
    multiple unspecified flaws in the JAXP subcomponent. A
    remote attacker can exploit these flaws to cause a
    denial of service condition. (CVE-2015-4803,
    CVE-2015-4893, CVE-2015-4911)

  - An unspecified flaw exists in the Security subcomponent
    that allows a remote attacker to impact integrity.
    (CVE-2015-4872)");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75a4a4fb");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JRockit version R28.3.8 or later as referenced in
the October 2015 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jrockit");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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
# 28.3.7.x
if (ver =~ "^28\.3\.7($|[^0-9])")
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    # The DLL we're looking at is a level deeper in the JDK, since it
    # keeps a subset of the JRE in a subdirectory.
    if (type == "JDK")  path += "\jre";
    path += "\bin\jrockit\jvm.dll";

    report =
      '\n  Type              : ' + type +
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver  +
      '\n  Fixed version     : 28.3.8'  +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);
