#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64825);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/03 20:40:06 $");

  script_cve_id("CVE-2008-0628");
  script_bugtraq_id(27553);
  script_osvdb_id(40931);

  script_name(english:"Sun Java JRE External XML Entities Restriction Bypass (231246) (Unix)");
  script_summary(english:"Checks version of Sun JRE");

  script_set_attribute(attribute:"synopsis", value:
"The remote Unix host has an application that is affected by a security
bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the Sun Java Runtime Environment (JRE)
installed on the remote host reportedly allows processing of external
entity references even when the 'external general entities' property is
set to 'FALSE'.  This could allow an application to access certain URL
resources, such as files or web pages, or to launch a denial of service
attack against the system.

Note that successful exploitation requires that specially crafted XML
data be processed by a trusted application rather than by an untrusted
applet or Java Web Start application.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Feb/7");
  script_set_attribute(attribute:"see_also", value:"http://download.oracle.com/sunalerts/1018967.1.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Sun JDK and JRE 6 Update 4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/30");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_set_attribute(attribute:"plugin_type", value:"local");
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
  if (ver =~ "^1\.6\.0_0[0-3][^0-9]?")
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.6.0_04\n';
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
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
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
