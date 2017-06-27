#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(78481);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/05/01 13:40:22 $");

  script_cve_id(
    "CVE-2014-4288",
    "CVE-2014-6456",
    "CVE-2014-6457",
    "CVE-2014-6458",
    "CVE-2014-6466",
    "CVE-2014-6468",
    "CVE-2014-6476",
    "CVE-2014-6485",
    "CVE-2014-6492",
    "CVE-2014-6493",
    "CVE-2014-6502",
    "CVE-2014-6503",
    "CVE-2014-6504",
    "CVE-2014-6506",
    "CVE-2014-6511",
    "CVE-2014-6512",
    "CVE-2014-6513",
    "CVE-2014-6515",
    "CVE-2014-6517",
    "CVE-2014-6519",
    "CVE-2014-6527",
    "CVE-2014-6531",
    "CVE-2014-6532",
    "CVE-2014-6558",
    "CVE-2014-6562"
  );
  script_bugtraq_id(
    70456,
    70460,
    70468,
    70470,
    70484,
    70488,
    70507,
    70518,
    70519,
    70522,
    70523,
    70531,
    70533,
    70538,
    70544,
    70548,
    70552,
    70556,
    70560,
    70564,
    70565,
    70567,
    70569,
    70570,
    70572
  );
  script_osvdb_id(
    113315,
    113316,
    113317,
    113318,
    113319,
    113320,
    113321,
    113322,
    113323,
    113324,
    113325,
    113326,
    113327,
    113328,
    113329,
    113330,
    113331,
    113333,
    113334,
    113335,
    113336,
    113337,
    113338,
    113339
  );

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (October 2014 CPU)");
  script_summary(english:"Checks the version of the JRE.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is prior to 8 Update 25, 7 Update 71, 6
Update 85, or 5 Update 75. It is, therefore, affected by security
issues in the following components :

  - 2D
  - AWT
  - Deployment
  - Hotspot
  - JAXP
  - JSSE
  - JavaFX
  - Libraries
  - Security");
  # http://www.oracle.com/technetwork/topics/security/alerts-086861.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5bc1d772");
  # Java SE JDK and JRE 8 Update 25
  # http://www.oracle.com/technetwork/java/javase/8u25-relnotes-2296185.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d381294");
  # Java SE JDK and JRE 7 Update 71
  # http://www.oracle.com/technetwork/java/javase/7u71-relnotes-2296187.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?46d9d129");
  # Java SE JDK and JRE 6 Update 85
  # http://www.oracle.com/technetwork/java/javase/documentation/overview-156328.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?726f7054");
  # Java SE JDK and JRE 5.0 Update 75
  # http://www.oracle.com/technetwork/java/javase/documentation/overview-137139.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6086d976");
  script_set_attribute(attribute:"solution", value:
"Update to JDK / JRE 8 Update 25, 7 Update 71, 6 Update 85, or 5 Update
75 or later and, if necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 5 Update 75 or later or 6 Update 85 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/15");

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
vuln = 0;
installed_versions = "";

foreach install (list_uniq(keys(installs)))
{
  ver = install - "SMB/Java/JRE/";
  if (ver !~ "^[0-9.]+") continue;

  installed_versions = installed_versions + " & " + ver;

  # Fixes : (JDK|JRE) 8 Update 25 / 7 Update 71 / 6 Update 85 / 5 Update 75
  if (
    ver =~ '^1\\.5\\.0_(0?[0-9]|[0-6][0-9]|7[0-4])([^0-9]|$)' ||
    ver =~ '^1\\.6\\.0_(0?[0-9]|[0-7][0-9]|8[0-4])([^0-9]|$)' ||
    ver =~ '^1\\.7\\.0_(0?[0-9]|[0-6][0-9]|70)([^0-9]|$)'     ||
    ver =~ '^1\\.8\\.0_(0?[0-9]|1[0-9]|2[0-4])([^0-9]|$)'
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed versions    : 1.5.0_75 / 1.6.0_85 / 1.7.0_71 / 1.8.0_25\n';
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
