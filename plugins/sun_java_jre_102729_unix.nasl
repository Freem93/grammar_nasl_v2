#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64818);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/17 17:13:10 $");

  script_cve_id(
    "CVE-2006-6731",
    "CVE-2006-6736",
    "CVE-2006-6737",
    "CVE-2006-6745"
  );
  script_bugtraq_id(21673, 21674, 21675);
  script_osvdb_id(
    32357,
    32358,
    32393,
    32394,
    32931,
    32932,
    32933,
    32934
  );

  script_name(english:"Sun Java JRE Multiple Vulnerabilities (102729 / 102732) (Unix)");
  script_summary(english:"Checks version of Sun JRE");

  script_set_attribute(attribute:"synopsis", value:
"The remote Unix host has a version of Sun's Java Runtime Environment
that is affected by several vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the Sun JRE installed on the remote
host has two buffer overflow issues that may allow an untrusted applet
to elevate its privileges to, for example, read or write local files or
to execute local applications subject to the privileges of the user
running the applet.

In addition, another set of vulnerabilities may allow an untrusted
applet to access data in other applets.");
  script_set_attribute(attribute:"see_also", value:"http://scary.beasts.org/security/CESA-2005-008.txt");
  # http://web.archive.org/web/20080502110817/http://sunsolve.sun.com/search/document.do?assetkey=1-26-102729-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?58f88e57");
  # http://web.archive.org/web/20080209034954/http://sunsolve.sun.com/search/document.do?assetkey=1-26-102732-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6507bb6f");
  script_set_attribute(attribute:"solution", value:
"Update to Sun Java 2 JDK and JRE 5.0 Update 8 / SDK and JRE 1.4.2_13 /
SDK and JRE 1.3.1_19 or later and remove, if necessary, any affected
versions.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/22");

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
  if (
    ver =~ "^1\.5\.0_0[0-7][^0-9]?" ||
    ver =~ "^1\.4\.([01]_|2_(0[0-9]|1[0-2][^0-9]?))" ||
    ver =~ "^1\.3\.(0_|1_(0[0-9]|1[0-8][^0-9]?))"
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.5.0_08 / 1.4.2_13 / 1.3.1_19\n';
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
