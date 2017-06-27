#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(99588);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/04/21 17:27:37 $");

  script_cve_id(
    "CVE-2017-3509",
    "CVE-2017-3511",
    "CVE-2017-3512",
    "CVE-2017-3514",
    "CVE-2017-3526",
    "CVE-2017-3533",
    "CVE-2017-3539",
    "CVE-2017-3544"
  );
  script_bugtraq_id(
    97727,
    97729,
    97731,
    97733,
    97737,
    97740,
    97745,
    97752
  );
  script_osvdb_id(
    155830,
    155831,
    155832,
    155833,
    155834,
    155835,
    155836,
    155837
  );
  script_xref(name:"IAVA", value:"2017-A-0116");

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (April 2017 CPU)");
  script_summary(english:"Checks the version of the JRE.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 6 Update 151, 7 Update 141,
or 8 Update 131. It is, therefore, affected by multiple
vulnerabilities :

  - An unspecified flaw exists in the Networking
    subcomponent that allows an unauthenticated, remote
    attacker to impact confidentiality and integrity.
    (CVE-2017-3509)

  - An unspecified flaw exists in the JCE subcomponent that
    allows a local attacker to gain elevated privileges.
    This vulnerability does not affect Java SE version 6.
    (CVE-2017-3511)

  - An unspecified flaw exists in the AWT subcomponent
    that allows an unauthenticated, remote attacker to
    execute arbitrary code. This vulnerability does not
    affect Java SE version 6. (CVE-2017-3512)

  - An unspecified flaw exists in the AWT subcomponent
    that allows an unauthenticated, remote attacker to
    execute arbitrary code. (CVE-2017-3514)

  - An unspecified flaw exists in the JAXP subcomponent that
    allows an unauthenticated, remote attacker to cause a
    denial of service condition. (CVE-2017-3526)

  - Multiple unspecified flaws exist in the Networking
    subcomponent that allow an unauthenticated, remote
    attacker to gain update, insert, or delete access to
    unauthorized data. (CVE-2017-3533, CVE-2017-3544)

  - An unspecified flaw exists in the Security subcomponent
    that allows an unauthenticated, remote attacker to gain
    update, insert, or delete access to unauthorized data.
    (CVE-2017-3539)");
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html#AppendixJAVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5a48460e");
  # http://www.oracle.com/technetwork/java/javase/8u131-relnotes-3565278.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce35fa3a");
  # http://www.oracle.com/technetwork/java/javaseproducts/documentation/javase7supportreleasenotes-1601161.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4f2226dc");
  # http://www.oracle.com/technetwork/java/javase/documentation/overview-156328.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?726f7054");
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/3681811.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08e1362c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JDK / JRE 6 Update 151 / 7 Update 141 / 8 Update 131
or later. If necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 6 Update 95 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("sun_java_jre_installed.nasl");
  script_require_keys("SMB/Java/JRE/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Check each installed JRE.
installs = get_kb_list_or_exit("SMB/Java/JRE/*");

info = "";
vuln = 0;
installed_versions = "";

foreach install (list_uniq(keys(installs)))
{
  ver = install - "SMB/Java/JRE/";
  if (ver !~ "^[0-9.]+") continue;

  installed_versions = installed_versions + " & " + ver;

  # Fixes : (JDK|JRE) 8 Update 131 / 7 Update 141 / 6 Update 151
  if (
    ver =~ '^1\\.6\\.0_([0-9]|[0-9][0-9]|1[0-4][0-9]|150)([^0-9]|$)' ||
    ver =~ '^1\\.7\\.0_([0-9]|[0-9][0-9]|1[0-3][0-9]|140)([^0-9]|$)' ||
    ver =~ '^1\\.8\\.0_([0-9]|[0-9][0-9]|1[0-2][0-9]|130)([^0-9]|$)'
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.6.0_151 / 1.7.0_141 / 1.8.0_131\n';
  }
}

# Report if any were found to be vulnerable.
if (info)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    if (vuln > 1) s = "s of Java are";
    else s = " of Java is";

    report =
      '\n' +
      'The following vulnerable instance'+s+' installed on the\n' +
      'remote host :\n' +
      info;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else
{
  installed_versions = substr(installed_versions, 3);
  if (" & " >< installed_versions)
    exit(0, "The Java "+installed_versions+" installations on the remote host are not affected.");
  else
    audit(AUDIT_INST_VER_NOT_VULN, "Java", installed_versions);
}
