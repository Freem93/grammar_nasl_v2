#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(54997);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2017/05/01 13:40:21 $");

  script_cve_id(
    "CVE-2011-0786",
    "CVE-2011-0788",
    "CVE-2011-0802",
    "CVE-2011-0814",
    "CVE-2011-0815",
    "CVE-2011-0817",
    "CVE-2011-0862",
    "CVE-2011-0863",
    "CVE-2011-0864",
    "CVE-2011-0865",
    "CVE-2011-0866",
    "CVE-2011-0867",
    "CVE-2011-0868",
    "CVE-2011-0869",
    "CVE-2011-0871",
    "CVE-2011-0872",
    "CVE-2011-0873"
  );
  script_bugtraq_id(
    48133,
    48134,
    48135,
    48136,
    48137,
    48138,
    48139,
    48140,
    48141,
    48142,
    48143,
    48144,
    48145,
    48146,
    48147,
    48148,
    48149
  );
  script_osvdb_id(
    73069,
    73070,
    73071,
    73072,
    73073,
    73074,
    73075,
    73076,
    73077,
    73078,
    73079,
    73080,
    73081,
    73082,
    73083,
    73084,
    73085,
    73176
  );
  script_xref(name:"Secunia", value:"44784");

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (June 2011 CPU)");
  script_summary(english:"Checks version of the JRE");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
affected by multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is earlier than 6 Update 26 / 5.0 Update
30 / 1.4.2_32.  Such versions are potentially affected by security
issues in the following components :

  - AWT
  - Deployment
  - Deserialization
  - Hotspot
  - Java Runtime Environment
  - Networking
  - NIO
  - SAAJ
  - Sound
  - Swing");

  # http://www.oracle.com/technetwork/topics/security/javacpujune2011-313339.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8569058d");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-182/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-183/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-184/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-185/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-186/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-187/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-188/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-189/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-190/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-191/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-192/");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/518303/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/518304/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/518307/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/518305/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/518306/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/518309/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/518308/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/518315/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/518313/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/518312/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/518311/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/eol-135779.html");
  script_set_attribute(attribute:"solution", value:
"Update to JDK / JRE 6 Update 26, JDK 5.0 Update 30, SDK 1.4.2_32 or
later and remove, if necessary, any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK 5.0 Update 30 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

  script_dependencies("sun_java_jre_installed.nasl");
  script_require_keys("SMB/Java/JRE/Installed");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

# Check each installed JRE.
installs = get_kb_list("SMB/Java/JRE/*");
if (isnull(installs)) exit(1, "The 'SMB/Java/JRE/' KB item is missing.");

info = "";
vuln = 0;
installed_versions = "";

foreach install (list_uniq(keys(installs)))
{
  ver = install - "SMB/Java/JRE/";
  if (ver =~ "^[0-9.]+")
    installed_versions = installed_versions + " & " + ver;
  if (
    ver =~ '^1\\.6\\.0_([0-9]|[01][0-9]|2[0-5])([^0-9]|$)' ||
    ver =~ '^1\\.5\\.0_([0-9]|[0-2][0-9])([^0-9]|$)' ||
    ver =~ '^1\\.4\\.([01]_|2_([0-9]|[0-2][0-9]|3[01])([^0-9]|$))'
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.6.0_26 / 1.5.0_30 / 1.4.2_32\n';
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
    exit(0, "The Java "+installed_versions+" install on the remote host is not affected.");
}
