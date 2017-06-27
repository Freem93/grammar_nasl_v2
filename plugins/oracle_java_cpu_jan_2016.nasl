#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(88045);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/05/01 13:40:21 $");

  script_cve_id(
    "CVE-2015-7575",
    "CVE-2015-8126",
    "CVE-2016-0402",
    "CVE-2016-0448",
    "CVE-2016-0466",
    "CVE-2016-0475",
    "CVE-2016-0483",
    "CVE-2016-0494"
  );
  script_bugtraq_id(
    77568,
    79684
  );
  script_osvdb_id(
    130175,
    132305,
    133156,
    133157,
    133158,
    133159,
    133160,
    133161
  );

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (January 2016 CPU) (SLOTH)");
  script_summary(english:"Checks the version of the JRE.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 8 Update 71, 7 Update 95, or
6 Update 111. It is, therefore, affected by security vulnerabilities
in the following components :

  - 2D
  - AWT
  - JAXP
  - JMX
  - Libraries
  - Networking
  - Security");
  # http://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html#AppendixJAVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6dbd87f4");
  # Java SE JDK and JRE 8 Update 71
  # http://www.oracle.com/technetwork/java/javase/8u71-relnotes-2773756.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f13fe03");
  # Java SE JDK and JRE 7 Update 95
  # http://www.oracle.com/technetwork/java/javase/7u95-relnotes-2775806.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?796894ea");
  # Java SE JDK and JRE 6 Update 111
  # http://www.oracle.com/technetwork/java/javase/6u111-relnotes-2775857.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dafbe2d9");
  script_set_attribute(attribute:"see_also", value:"http://www.mitls.org/pages/attacks/SLOTH");
  script_set_attribute(attribute:"see_also", value:"http://www.mitls.org/downloads/transcript-collisions.pdf");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JDK / JRE 8 Update 71, 7 Update 95, 6 Update 111,
or later. If necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 6 Update 111 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");

  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

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

  # Fixes : (JDK|JRE) 8 Update 71 / 7 Update 95 / 6 Update 111
  if (
    ver =~ '^1\\.6\\.0_([0-9]|[0-9][0-9]|10[0-9]|110)([^0-9]|$)' ||
    ver =~ '^1\\.7\\.0_([0-9]|[0-8][0-9]|9[0-4])([^0-9]|$)' ||
    ver =~ '^1\\.8\\.0_([0-9]|[0-6][0-9]|70)([^0-9]|$)'
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.6.0_111 / 1.7.0_95 / 1.8.0_71\n';
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
