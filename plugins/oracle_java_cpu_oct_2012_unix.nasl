#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(64849);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/07 22:01:24 $");

  script_cve_id(
    "CVE-2012-1531",
    "CVE-2012-1532",
    "CVE-2012-1533",
    "CVE-2012-3143",
    "CVE-2012-3159",
    "CVE-2012-3216",
    "CVE-2012-4416",
    "CVE-2012-5067",
    "CVE-2012-5068",
    "CVE-2012-5069",
    "CVE-2012-5070",
    "CVE-2012-5071",
    "CVE-2012-5072",
    "CVE-2012-5073",
    "CVE-2012-5074",
    "CVE-2012-5075",
    "CVE-2012-5076",
    "CVE-2012-5077",
    "CVE-2012-5078",
    "CVE-2012-5079",
    "CVE-2012-5080",
    "CVE-2012-5081",
    "CVE-2012-5082",
    "CVE-2012-5083",
    "CVE-2012-5084",
    "CVE-2012-5085",
    "CVE-2012-5086",
    "CVE-2012-5087",
    "CVE-2012-5088",
    "CVE-2012-5089"
  );
  script_bugtraq_id(
    55501,
    56025,
    56033,
    56039,
    56043,
    56046,
    56051,
    56054,
    56055,
    56056,
    56057,
    56058,
    56059,
    56061,
    56063,
    56065,
    56066,
    56067,
    56068,
    56070,
    56071,
    56072,
    56075,
    56076,
    56078,
    56079,
    56080,
    56081,
    56082,
    56083
  );
  script_osvdb_id(
    86344,
    86345,
    86346,
    86347,
    86348,
    86349,
    86350,
    86351,
    86352,
    86353,
    86354,
    86355,
    86356,
    86357,
    86358,
    86359,
    86360,
    86361,
    86362,
    86363,
    86364,
    86365,
    86366,
    86367,
    86368,
    86369,
    86370,
    86371,
    86372,
    86374
  );

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (October 2012 CPU) (Unix)");
  script_summary(english:"Checks version of the JRE");

  script_set_attribute(attribute:"synopsis", value:
"The remote Unix host contains a programming platform that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is earlier than 7 Update 9 / 6 Update 37
/ 5.0 Update 38 / 1.4.2_40 and is, therefore, potentially affected by
security issues in the following components :

  - 2D
  - Beans
  - Concurrency
  - Deployment
  - Hotspot
  - JAX-WS
  - JMX
  - JSSE
  - Libraries
  - Networking
  - Security
  - Swing");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/524506/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/524507/30/0/threaded");
  # http://www.oracle.com/technetwork/topics/security/javacpuoct2012-1515924.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b0eb44d4");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/javase/7u9-relnotes-1863279.html");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/javase/6u37-relnotes-1863283.html");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/eol-135779.html");
  script_set_attribute(attribute:"solution", value:
"Update to JDK / JRE 7 Update 9 / 6 Update 37, JDK 5.0 Update 38, SDK
1.4.2_40 or later and remove, if necessary, any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK 5 .0 Update 38 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Method Handle Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/16");
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
    ver =~ '^1\\.7\\.0_0[0-8]([^0-9]|$)' ||
    ver =~ '^1\\.6\\.0_([0-9]|[0-2][0-9]|3[0-6])([^0-9]|$)' ||
    ver =~ '^1\\.5\\.0_([0-9]|[0-2][0-9]|3[0-7])([^0-9]|$)' ||
    ver =~ '^1\\.4\\.([01]_|2_([0-9]|[0-3][0-9])([^0-9]|$))'
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.7.0_09 / 1.6.0_37 / 1.5.0_38 / 1.4.2_40\n';
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
