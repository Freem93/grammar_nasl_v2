#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(64840);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/07 22:01:24 $");

  script_cve_id("CVE-2012-3174", "CVE-2013-0422");
  script_bugtraq_id(57246, 57312);
  script_osvdb_id(89059, 89326);
  script_xref(name:"CERT", value:"625617");
  script_xref(name:"EDB-ID", value:"24045");

  script_name(english:"Oracle Java SE 7 < Update 11 Multiple Vulnerabilities (Unix)");
  script_summary(english:"Checks version of the JRE");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a programming platform that is potentially
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is earlier than 7 Update 11 and is,
therefore, potentially affected by the following security issues :

  - An unspecified issue exists in the Libraries
    component. (CVE-2012-3174)

  - An error exists in the 'MBeanInstantiator.findClass'
    method that could allow remote, arbitrary code execution.
    (CVE-2013-0422)

Note that, according the advisory, these issues apply to client
deployments of Java only and can only be exploited through untrusted
'Java Web Start' applications and untrusted Java applets.");
  # http://www.oracle.com/technetwork/topics/security/alert-cve-2013-0422-1896849.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eaf95a3d");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/javase/7u11-relnotes-1896856.html");
  script_set_attribute(attribute:"solution", value:
"Update to JDK / JRE 7 Update 11 or later and, if necessary, remove any
affected versions.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet JMX Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/22");

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

  if (ver =~ '^1\\.7\\.0_(0[0-9]|10)([^0-9]|$)')
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.7.0_11\n';
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
