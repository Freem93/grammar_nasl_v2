#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(64844);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/07 22:01:24 $");

  script_cve_id(
    "CVE-2010-4422",
    "CVE-2010-4447",
    "CVE-2010-4448",
    "CVE-2010-4450",
    "CVE-2010-4451",
    "CVE-2010-4452",
    "CVE-2010-4454",
    "CVE-2010-4462",
    "CVE-2010-4463",
    "CVE-2010-4465",
    "CVE-2010-4466",
    "CVE-2010-4467",
    "CVE-2010-4468",
    "CVE-2010-4469",
    "CVE-2010-4470",
    "CVE-2010-4471",
    "CVE-2010-4472",
    "CVE-2010-4473",
    "CVE-2010-4474",
    "CVE-2010-4475",
    "CVE-2010-4476"
  );
  script_bugtraq_id(
    46091,
    46386,
    46387,
    46388,
    46391,
    46393,
    46394,
    46395,
    46397,
    46398,
    46399,
    46400,
    46402,
    46403,
    46404,
    46405,
    46406,
    46407,
    46409,
    46410,
    46411
  );
  script_osvdb_id(
    70965,
    71193,
    71605,
    71606,
    71607,
    71608,
    71609,
    71610,
    71611,
    71612,
    71613,
    71614,
    71615,
    71616,
    71617,
    71618,
    71619,
    71620,
    71621,
    71622,
    71623
  );
  script_xref(name:"EDB-ID", value:"16990");

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (February 2011 CPU) (Unix)");
  script_summary(english:"Checks version of the JRE");

  script_set_attribute(attribute:"synopsis", value:
"The remote Unix host contains a programming platform that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is earlier than 6 Update 24 / 5.0 Update 28
/ 1.4.2_30.  Such versions are potentially affected by security issues
in the following components :

  - Deployment
  - HotSpot
  - Install
  - JAXP
  - Java Language
  - JDBC
  - Launcher
  - Networking
  - Security
  - Sound
  - Swing
  - XML Digital Signature
  - 2D");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-082");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-083");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-084");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-085");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-086");
  # http://www.oracle.com/technetwork/topics/security/javacpufeb2011-304611.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d6610d2");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/eol-135779.html");
  script_set_attribute(attribute:"solution", value:
"Update to JDK / JRE 6 Update 24, JDK 5.0 Update 28, SDK 1.4.2_30 or
later and remove, if necessary, any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK 5.0 Update 28 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Applet2ClassLoader Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/22");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"plugin_type", value:"local");
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
    ver =~ '^1\\.6\\.0_([0-9]|[01][0-9]|2[0-3])([^0-9]|$)' ||
    ver =~ '^1\\.5\\.0_([0-9]|[01][0-9]|2[0-7])([^0-9]|$)' ||
    ver =~ '^1\\.4\\.([01]_|2_([0-9]|[0-2][0-9])([^0-9]|$))'
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.6.0_24 / 1.5.0_28 / 1.4.2_30\n';
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
