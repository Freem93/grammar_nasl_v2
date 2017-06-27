#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(84824);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/05/01 13:40:21 $");

  script_cve_id(
    "CVE-2015-2590",
    "CVE-2015-2596",
    "CVE-2015-2601",
    "CVE-2015-2613",
    "CVE-2015-2619",
    "CVE-2015-2621",
    "CVE-2015-2625",
    "CVE-2015-2627",
    "CVE-2015-2628",
    "CVE-2015-2632",
    "CVE-2015-2637",
    "CVE-2015-2638",
    "CVE-2015-2659",
    "CVE-2015-2664",
    "CVE-2015-2808",
    "CVE-2015-4000",
    "CVE-2015-4729",
    "CVE-2015-4731",
    "CVE-2015-4732",
    "CVE-2015-4733",
    "CVE-2015-4736",
    "CVE-2015-4748",
    "CVE-2015-4749",
    "CVE-2015-4760"
  );
  script_bugtraq_id(
    73684,
    74733,
    75784,
    75796,
    75812,
    75818,
    75823,
    75832,
    75833,
    75850,
    75854,
    75857,
    75861,
    75867,
    75871,
    75874,
    75877,
    75881,
    75883,
    75887,
    75890,
    75892,
    75893,
    75895
  );
  script_osvdb_id(
    117855,
    122331,
    124617,
    124618,
    124619,
    124620,
    124621,
    124622,
    124623,
    124624,
    124625,
    124627,
    124628,
    124629,
    124630,
    124631,
    124632,
    124633,
    124634,
    124635,
    124636,
    124637,
    124638,
    124639
  );

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (July 2015 CPU) (Bar Mitzvah)");
  script_summary(english:"Checks the version of the JRE.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 8 Update 51, 7 Update 85, or
6 Update 101. It is, therefore, affected by security vulnerabilities
in the following components :

  - 2D
  - CORBA
  - Deployment
  - Hotspot
  - Install
  - JCE
  - JMX
  - JNDI
  - JSSE
  - Libraries
  - RMI
  - Security");
  # http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html#AppendixJAVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?32ff7cd8");
  # Java SE JDK and JRE 8 Update 51
  # http://www.oracle.com/technetwork/java/javase/8u51-relnotes-2587590.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?70c37787");
  # Java SE JDK and JRE 7 Update 85
  # http://www.oracle.com/technetwork/java/javase/7u85-relnotes-2587591.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77a86ddc");
  # Java SE JDK and JRE 6 Update 101
  # http://www.oracle.com/technetwork/java/javase/documentation/overview-156328.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?726f7054");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JDK / JRE 8 Update 51, 7 Update 85, 6 Update 101,
or later. If necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 6 Update 95 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:UR");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:U/RC:R");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/17");

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

  # Fixes : (JDK|JRE) 8 Update 51 / 7 Update 85 / 6 Update 101
  if (
    ver =~ '^1\\.6\\.0_([0-9]|[0-9][0-9]|100)([^0-9]|$)' ||
    ver =~ '^1\\.7\\.0_([0-9]|[0-7][0-9]|8[0-4])([^0-9]|$)' ||
    ver =~ '^1\\.8\\.0_([0-9]|[0-4][0-9]|50)([^0-9]|$)'
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.6.0_101 / 1.7.0_85 / 1.8.0_51\n';
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
