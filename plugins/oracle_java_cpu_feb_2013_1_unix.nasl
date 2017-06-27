#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(64851);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/07 22:01:24 $");

  script_cve_id(
    "CVE-2013-0169",
    "CVE-2013-1484",
    "CVE-2013-1485",
    "CVE-2013-1486",
    "CVE-2013-1487"
  );
  script_bugtraq_id(57778, 58027, 58028, 58029, 58031);
  script_osvdb_id(89848, 90352, 90353, 90354, 90355);

  script_name(english:"Oracle Java SE Multiple Vulnerabilities (February 2013 CPU Update 1) (Unix)");
  script_summary(english:"Checks version of the JRE");

  script_set_attribute(attribute:"synopsis", value:
"The remote Unix host contains a programming platform that is
potentially affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle (formerly Sun) Java SE or Java for Business
installed on the remote host is earlier than 7 Update 15, 6 Update 41,
5 Update 40 or 1.4.2 Update 42.  It is, therefore, potentially
affected by security issues in the following components :

  - Deployment
  - JMX
  - JSSE
  - Libraries");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-041/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-042/");
  # http://www.oracle.com/technetwork/topics/security/javacpufeb2013update-1905892.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7e310812");
  script_set_attribute(attribute:"see_also", value:"http://www.isg.rhul.ac.uk/tls/");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/eol-135779.html");
  script_set_attribute(attribute:"solution", value:
"Update to JDK / JRE 7 Update 15, 6 Update 41, 5 Update 40, 1.4.2
Update 42 or later and, if necessary, remove any affected versions.

Note that an Extended Support contract with Oracle is needed to obtain
JDK / JRE 5 Update 40 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/19");
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

  if (
    ver =~ '^1\\.4\\.([01]_|2_([0-9]|[0-3][0-9]|4[01]))([^0-9]|$)' ||
    ver =~ '^1\\.5\\.0_([0-9]|[0-2][0-9]|3[0-9])([^0-9]|$)' ||
    ver =~ '^1\\.6\\.0_([0-9]|[0-2][0-9]|3[0-9])([^0-9]|$)' ||
    ver =~ '^1\\.7\\.0_(0[0-9]|1[0-3])([^0-9]|$)'

  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.4.2_42 / 1.5.0_40 / 1.6.0_41 / 1.7.0_15\n';
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
