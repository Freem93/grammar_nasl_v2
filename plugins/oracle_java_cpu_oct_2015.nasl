#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(86542);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/05/01 13:40:22 $");

  script_cve_id(
    "CVE-2015-4835",
    "CVE-2015-4881",
    "CVE-2015-4843",
    "CVE-2015-4883",
    "CVE-2015-4860",
    "CVE-2015-4805",
    "CVE-2015-4844",
    "CVE-2015-4901",
    "CVE-2015-4868",
    "CVE-2015-4810",
    "CVE-2015-4806",
    "CVE-2015-4871",
    "CVE-2015-4902",
    "CVE-2015-4840",
    "CVE-2015-4882",
    "CVE-2015-4842",
    "CVE-2015-4734",
    "CVE-2015-4903",
    "CVE-2015-4803",
    "CVE-2015-4893",
    "CVE-2015-4911",
    "CVE-2015-4872",
    "CVE-2015-4906",
    "CVE-2015-4916",
    "CVE-2015-4908"
  );
  script_bugtraq_id(
    77126,
    77148,
    77159,
    77160,
    77162,
    77163,
    77164,
    77181,
    77192,
    77194,
    77200,
    77207,
    77209,
    77211,
    77214,
    77221,
    77223,
    77225,
    77226,
    77229,
    77238,
    77241,
    77242
  );
  script_osvdb_id(
    129119,
    129120,
    129121,
    129122,
    129123,
    129124,
    129125,
    129126,
    129127,
    129128,
    129129,
    129130,
    129131,
    129132,
    129133,
    129134,
    129135,
    129136,
    129137,
    129138,
    129139,
    129140,
    129141,
    129142,
    129143
  );

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (October 2015 CPU)");
  script_summary(english:"Checks the version of the JRE.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 8 Update 65, 7 Update 91, or
6 Update 105. It is, therefore, affected by security vulnerabilities
in the following components :

  - 2D
  - CORBA
  - Deployment
  - JavaFX
  - JAXP
  - JGSS
  - Libraries
  - RMI
  - Security
  - Serialization");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2015-2367953.html#AppendixJAVA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e5158e8");
  # Java SE JDK and JRE 8 Update 65
  # http://www.oracle.com/technetwork/java/javase/8u65-relnotes-2687063.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3470d759");
  # Java SE JDK and JRE 7 Update 91
  # http://www.oracle.com/technetwork/java/javase/7u91-relnotes-2687180.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84866cdb");
  # Java SE JDK and JRE 6 Update 105
  # http://www.oracle.com/technetwork/java/javase/6u105-relnotes-2703317.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e6ca3d9a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JDK / JRE 8 Update 65, 7 Update 91, 6 Update 105,
or later. If necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 6 Update 95 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UR");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:U/RC:R");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
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

  # Fixes : (JDK|JRE) 8 Update 65 / 7 Update 91 / 6 Update 105
  if (
    ver =~ '^1\\.6\\.0_([0-9]|[0-9][0-9]|10[0-4])([^0-9]|$)' ||
    ver =~ '^1\\.7\\.0_([0-9]|[0-8][0-9]|90)([^0-9]|$)' ||
    ver =~ '^1\\.8\\.0_([0-9]|[0-5][0-9]|6[0-4])([^0-9]|$)'
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.6.0_105 / 1.7.0_91 / 1.8.0_65\n';
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
