#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76532);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/04/27 19:09:12 $");

  script_cve_id(
    "CVE-2014-2483",
    "CVE-2014-2490",
    "CVE-2014-4208",
    "CVE-2014-4209",
    "CVE-2014-4216",
    "CVE-2014-4218",
    "CVE-2014-4219",
    "CVE-2014-4220",
    "CVE-2014-4221",
    "CVE-2014-4223",
    "CVE-2014-4227",
    "CVE-2014-4244",
    "CVE-2014-4247",
    "CVE-2014-4252",
    "CVE-2014-4262",
    "CVE-2014-4263",
    "CVE-2014-4264",
    "CVE-2014-4265",
    "CVE-2014-4266",
    "CVE-2014-4268"
  );

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (July 2014 CPU)");
  script_summary(english:"Checks the version of the JRE.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 8 Update 11, 7 Update 65, 6
Update 81, or 5 Update 71. It is, therefore, affected by security
issues in the following components :

  - Deployment
  - Hotspot
  - JavaFX
  - JMX
  - Libraries
  - Security
  - Serviceability
  - Swing");
  # http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html#AppendixJAVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4743a1ef");
  # Java SE JDK and JRE 8 Update 11
  # http://www.oracle.com/technetwork/java/javase/8u11-relnotes-2232915.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?81911044");
  # Java SE JDK and JRE 7 Update 65
  # http://www.oracle.com/technetwork/java/javase/7u65-relnotes-2229169.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6de19bd1");
  # Java SE JDK and JRE 6 Update 81
  # http://www.oracle.com/technetwork/java/javase/documentation/overview-156328.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?726f7054");
  #Java SE JDK and JRE 5.0 Update 71
  # http://www.oracle.com/technetwork/java/javase/documentation/overview-137139.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6086d976");
  script_set_attribute(attribute:"solution", value:
"Update to JDK / JRE 8 Update 11, 7 Update 65, 6 Update 81, or 5 Update
71 or later and, if necessary, remove any affected versions.

Note that an extended support contract with Oracle is needed to obtain
JDK / JRE 5 Update 71 or later or 6 Update 81 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

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
unaffected = make_list();
vuln = 0;

foreach install (list_uniq(keys(installs)))
{
  ver = install - "SMB/Java/JRE/";
  if (ver !~ "^[0-9.]+") continue;

  # Fixes : (JDK|JRE) 8 Update 11 / 7 Update 65 / 6 Update 81 / 5 Update 71
  if (
    ver =~ '^1\\.5\\.0_(0[0-9]|[0-6][0-9]|70)([^0-9]|$)' ||
    ver =~ '^1\\.6\\.0_(0[0-9]|[0-7][0-9]|80)([^0-9]|$)' ||
    ver =~ '^1\\.7\\.0_(0[0-9]|[0-5][0-9]|6[0-4])([^0-9]|$)' ||
    ver =~ '^1\\.8\\.0_(0[0-9]|10)([^0-9]|$)'
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.5.0_71 / 1.6.0_81 / 1.7.0_65 / 1.8.0_11\n';
  }
  else
    unaffected = make_list(unaffected, ver);
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
      '\n' + 'The following vulnerable instance'+s+' installed on the' +
      '\n' + 'remote host :' +
      '\n' + 
      info;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "Oracle Java", unaffected);
