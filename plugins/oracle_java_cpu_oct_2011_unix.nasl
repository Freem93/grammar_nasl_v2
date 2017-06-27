#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(64846);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/07 22:01:24 $");

  script_cve_id(
    "CVE-2011-3389",
    "CVE-2011-3516",
    "CVE-2011-3521",
    "CVE-2011-3544",
    "CVE-2011-3545",
    "CVE-2011-3546",
    "CVE-2011-3547",
    "CVE-2011-3548",
    "CVE-2011-3549",
    "CVE-2011-3550",
    "CVE-2011-3551",
    "CVE-2011-3552",
    "CVE-2011-3553",
    "CVE-2011-3554",
    "CVE-2011-3555",
    "CVE-2011-3556",
    "CVE-2011-3557",
    "CVE-2011-3558",
    "CVE-2011-3560",
    "CVE-2011-3561"
  );
  script_bugtraq_id(
    49778,
    50118,
    50211,
    50215,
    50216,
    50218,
    50220,
    50223,
    50224,
    50226,
    50229,
    50231,
    50234,
    50236,
    50237,
    50239,
    50242,
    50243,
    50246,
    50248,
    50250
  );
  script_osvdb_id(
    74829,
    76495,
    76496,
    76497,
    76498,
    76499,
    76500,
    76501,
    76502,
    76503,
    76504,
    76505,
    76506,
    76507,
    76508,
    76509,
    76510,
    76511,
    76512,
    76513
  );
  script_xref(name:"EDB-ID", value:"18171");
  script_xref(name:"CERT", value:"864643");

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (October 2011 CPU) (BEAST) (Unix)");
  script_summary(english:"Checks version of the JRE");

  script_set_attribute(attribute:"synopsis", value:
"The remote Unix host contains a programming platform that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is earlier than 7 Update 1 / 6 Update 29
/ 5.0 Update 32 / 1.4.2_34.  As such, it is potentially affected by
security issues in the following components :

  - 2D
  - AWT
  - Deployment
  - Deserialization
  - Hotspot
  - Java Runtime Environment
  - JAXWS
  - JSSE
  - Networking
  - RMI
  - Scripting
  - Sound
  - Swing");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-305/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-306/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-307/");
  # http://www.oracle.com/technetwork/topics/security/javacpuoct2011-443431.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3fed43a3");
  # https://nealpoole.com/blog/2011/10/java-applet-same-origin-policy-bypass-via-http-redirect/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac4427f9");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/eol-135779.html");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2011/09/23/chromeandbeast.html");
  script_set_attribute(attribute:"solution", value:
"Update to JDK / JRE 7 Update 1 / 6 Update 29, JDK 5.0 Update 32, SDK
1.4.2_34 or later and remove, if necessary, any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK 5.0 Update 32 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Rhino Script Engine Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/22");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("sun_java_jre_installed_unix.nasl");
  script_require_keys("Host/Java/JRE/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Check each installed JRE.
installs = get_kb_list_or_exit("Host/Java/JRE/Unmanaged/*");

info = "";
vuln = 0;
vuln2 = 0;
installed_versions = "";
granular = "";
foreach install (list_uniq(keys(installs)))
{
  ver = install - "Host/Java/JRE/Unmanaged/";
  if (ver !~ "^[0-9.]+") continue;

  installed_versions = installed_versions + " & " + ver;

  if (
    ver =~ '^1\\.7\\.0_00([^0-9]|$)' ||
    ver =~ '^1\\.6\\.0_([0-9]|[01][0-9]|2[0-8])([^0-9]|$)' ||
    ver =~ '^1\\.5\\.0_([0-9]|[0-2][0-9]|3[01])([^0-9]|$)' ||
    ver =~ '^1\\.4\\.([01]_|2_([0-9]|[0-2][0-9]|3[0-3])([^0-9]|$))'
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.7.0_01 / 1.6.0_29 / 1.5.0_32 / 1.4.2_34\n';
  }
  else if (ver =~ "^[\d\.]+$")
  {
    dirs = make_list(get_kb_list(install));
    foreach dir (dirs)
      granular += "The Oracle Java version "+ver+" at "+dir+" is not granular enough to make a determination."+'\n';
  }
  else
  {
    dirs = make_list(get_kb_list(install));
    vuln2 += max_index(dirs);
  }

}

# Report if any were found to be vulnerable.
if (info)
{
  if (report_verbosity > 0)
  {
    if (vuln > 1) s = "s of Java are";
    else s = " of Java is";

    report =
      '\n' +
      'The following vulnerable instance'+s+' installed on the\n' +
      'remote host :\n' +
      info;
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  if (granular) exit(0, granular);
}
else
{
  if (granular) exit(0, granular);

  installed_versions = substr(installed_versions, 3);
  if (vuln2 > 1)
    exit(0, "The Java "+installed_versions+" installs on the remote host are not affected.");
  else
    exit(0, "The Java "+installed_versions+" install on the remote host is not affected.");
}
