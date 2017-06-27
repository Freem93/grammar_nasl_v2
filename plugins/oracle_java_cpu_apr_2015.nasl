#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(82820);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/05/01 13:40:21 $");

  script_cve_id(
    "CVE-2015-0204",
    "CVE-2015-0458",
    "CVE-2015-0459",
    "CVE-2015-0460",
    "CVE-2015-0469",
    "CVE-2015-0470",
    "CVE-2015-0477",
    "CVE-2015-0478",
    "CVE-2015-0480",
    "CVE-2015-0484",
    "CVE-2015-0486",
    "CVE-2015-0488",
    "CVE-2015-0491",
    "CVE-2015-0492"
  );
  script_bugtraq_id(
    71936,
    74072,
    74083,
    74094,
    74097,
    74104,
    74111,
    74119,
    74129,
    74135,
    74141,
    74145,
    74147,
    74149
  );
  script_osvdb_id(
    15435,
    116794,
    120702,
    120703,
    120704,
    120705,
    120706,
    120709,
    120710,
    120711,
    120712,
    120713,
    120714
  );

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (April 2015 CPU) (FREAK)");
  script_summary(english:"Checks the version of the JRE.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 8 Update 45, 7 Update 79,
6 Update 95, or 5 Update 85. It is, therefore, affected by security
vulnerabilities in the following components :

  - 2D
  - Beans
  - Deployment
  - Hotspot
  - JavaFX
  - JCE
  - JSSE
  - Tools");
  # http://www.oracle.com/technetwork/topics/security/cpuapr2015-2365600.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15c09d3d");
  # Java SE JDK and JRE 8 Update 45
  # http://www.oracle.com/technetwork/java/javase/8u45-relnotes-2494160.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f0f6574");
  # Java SE JDK and JRE 7 Update 79
  # http://www.oracle.com/technetwork/java/javase/7u79-relnotes-2494161.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?35d2ad22");
  # Java SE JDK and JRE 6 Update 95
  # http://www.oracle.com/technetwork/java/javase/documentation/overview-156328.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?726f7054");
  #Java SE JDK and JRE 5.0 Update 85
  # http://www.oracle.com/technetwork/java/javase/documentation/overview-137139.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6086d976");
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com/#freak");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JDK / JRE 8 Update 45, 7 Update 79, 6 Update 95, or
5 Update 85 or later. If necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 5 Update 85 or later and 6 Update 95 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UR");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:U/RC:R");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");

  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

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

  # Fixes : (JDK|JRE) 8 Update 45 / 7 Update 79 / 6 Update 95 / 5 Update 85
  if (
    ver =~ '^1\\.5\\.0_([0-9]|[0-7][0-9]|8[0-4])([^0-9]|$)' ||
    ver =~ '^1\\.6\\.0_([0-9]|[0-8][0-9]|9[0-4])([^0-9]|$)' ||
    ver =~ '^1\\.7\\.0_([0-9]|[0-6][0-9]|7[0-8])([^0-9]|$)' ||
    ver =~ '^1\\.8\\.0_([0-9]|[0-3][0-9]|4[0-4])([^0-9]|$)'
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.5.0_85 / 1.6.0_95 / 1.7.0_79 / 1.8.0_45\n';
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
    exit(0, "The Java "+installed_versions+" installs on the remote host are not affected.");
  else
    audit(AUDIT_INST_VER_NOT_VULN, "Java", installed_versions);
}
