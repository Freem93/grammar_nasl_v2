#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(65996);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/07 22:01:24 $");

  script_cve_id(
    "CVE-2013-0401",
    "CVE-2013-0402",
    "CVE-2013-1488",
    "CVE-2013-1491",
    "CVE-2013-1518",
    "CVE-2013-1537",
    "CVE-2013-1540",
    "CVE-2013-1557",
    "CVE-2013-1558",
    "CVE-2013-1561",
    "CVE-2013-1563",
    "CVE-2013-1564",
    "CVE-2013-1569",
    "CVE-2013-2383",
    "CVE-2013-2384",
    "CVE-2013-2394",
    "CVE-2013-2414",
    "CVE-2013-2415",
    "CVE-2013-2416",
    "CVE-2013-2417",
    "CVE-2013-2418",
    "CVE-2013-2419",
    "CVE-2013-2420",
    "CVE-2013-2421",
    "CVE-2013-2422",
    "CVE-2013-2423",
    "CVE-2013-2424",
    "CVE-2013-2425",
    "CVE-2013-2426",
    "CVE-2013-2427",
    "CVE-2013-2428",
    "CVE-2013-2429",
    "CVE-2013-2430",
    "CVE-2013-2431",
    "CVE-2013-2432",
    "CVE-2013-2433",
    "CVE-2013-2434",
    "CVE-2013-2435",
    "CVE-2013-2436",
    "CVE-2013-2438",
    "CVE-2013-2439",
    "CVE-2013-2440"
  );
  script_bugtraq_id(
    58397,
    58493,
    58504,
    58507,
    59088,
    59089,
    59124,
    59128,
    59131,
    59137,
    59141,
    59145,
    59149,
    59153,
    59154,
    59159,
    59162,
    59165,
    59166,
    59167,
    59170,
    59172,
    59175,
    59178,
    59179,
    59184,
    59185,
    59187,
    59190,
    59191,
    59194,
    59195,
    59203,
    59206,
    59208,
    59212,
    59213,
    59219,
    59220,
    59228,
    59234,
    59243
  );
  script_osvdb_id(
    91204,
    91205,
    91206,
    91472,
    92335,
    92336,
    92337,
    92338,
    92339,
    92340,
    92341,
    92342,
    92343,
    92344,
    92345,
    92346,
    92347,
    92348,
    92349,
    92350,
    92351,
    92352,
    92353,
    92354,
    92355,
    92356,
    92357,
    92358,
    92359,
    92360,
    92361,
    92362,
    92363,
    92364,
    92365,
    92366,
    92367,
    92368,
    92369,
    92370,
    92371,
    92372
  );
  script_xref(name:"EDB-ID", value:"24966");

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (April 2013 CPU) (Unix)");
  script_summary(english:"Checks version of the JRE");

  script_set_attribute(attribute:"synopsis", value:
"The remote Unix host contains a programming platform that is
potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is earlier than or equal to  7 Update 17,
6 Update 43 or 5 Update 41.  It is, therefore, potentially affected by
security issues in the following components :

  - 2D
  - AWT
  - Beans
  - Deployment
  - HotSpot
  - ImageIO
  - Install
  - JavaFX
  - JAXP
  - JAX-WS
  - JMX
  - Libraries
  - Networking
  - RMI");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-068/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-069/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-070/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-071/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-072/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-073/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-074/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-075/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-076/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-077/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-078/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-079/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-089/");
  # http://www.oracle.com/technetwork/topics/security/javacpuapr2013-1928497.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4b0871bd");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/eol-135779.html");
  script_set_attribute(attribute:"solution", value:
"Update to JDK / JRE 5 Update 45, 6 Update 45, 7 Update 21 or later
and, if necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 5 Update 45 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Reflection Type Confusion Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jdk");
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
    ver =~ '^1\\.5\\.0_([0-9]|[0-3][0-9]|4[01])([^0-9]|$)' ||
    ver =~ '^1\\.6\\.0_([0-9]|[0-3][0-9]|4[0-3])([^0-9]|$)' ||
    ver =~ '^1\\.7\\.0_(0[0-9]|1[0-7])([^0-9]|$)'
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.5.0_45 / 1.6.0_45 / 1.7.0_21\n';
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
