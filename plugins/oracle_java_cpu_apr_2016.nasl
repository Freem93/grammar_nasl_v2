#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(90625);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/05/01 13:40:21 $");

  script_cve_id(
    "CVE-2016-0686",
    "CVE-2016-0687",
    "CVE-2016-0695",
    "CVE-2016-3422",
    "CVE-2016-3425",
    "CVE-2016-3426",
    "CVE-2016-3427",
    "CVE-2016-3443",
    "CVE-2016-3449"
  );
  script_osvdb_id(
    137300,
    137301,
    137302,
    137303,
    137304,
    137305,
    137306,
    137307,
    137308
  );

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (April 2016 CPU)");
  script_summary(english:"Checks the version of the JRE.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 8 Update 91, 7 Update 101,
or 6 Update 115. It is, therefore, affected by security
vulnerabilities in the following subcomponents :

  - 2D
  - Deployment
  - Hotspot
  - JAXP
  - JCE
  - JMX
  - Security
  - Serialization");
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2016v3-2985753.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?855180af");
  # Java SE JDK and JRE 8 Update 91
  # http://www.oracle.com/technetwork/java/javase/8u91-relnotes-2949462.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?931fdd55");
  # Java SE JDK and JRE 7 Update 101
  # http://www.oracle.com/technetwork/java/javaseproducts/documentation/javase7supportreleasenotes-1601161.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4f2226dc");
  # Java SE JDK and JRE 6 Update 115
  # http://www.oracle.com/technetwork/java/javase/documentation/overview-156328.html#R160_115
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b7a1abe2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JDK / JRE 8 Update 91, 7 Update 101, or 6 Update 115
or later. If necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 6 Update 115 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");

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

  # Fixes : (JDK|JRE) 8 Update 91 / 7 Update 101 / 6 Update 115
  if (
    ver =~ '^1\\.6\\.0_([0-9]|[0-9][0-9]|10[0-9]|11[0-4])([^0-9]|$)' ||
    ver =~ '^1\\.7\\.0_([0-9]|[0-9][0-9]|100)([^0-9]|$)' ||
    ver =~ '^1\\.8\\.0_([0-9]|[0-8][0-9]|90)([^0-9]|$)'
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.6.0_115 / 1.7.0_101 / 1.8.0_91\n';
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
