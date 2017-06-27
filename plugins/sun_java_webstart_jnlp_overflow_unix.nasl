#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64834);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_cve_id("CVE-2007-3655");
  script_bugtraq_id(24832);
  script_osvdb_id(37756);
  script_xref(name:"EDB-ID", value:"30284");

  script_name(english:"Sun Java Web Start JNLP File Handling Overflow (102996) (Unix)");
  script_summary(english:"Checks version of Sun JRE");

  script_set_attribute(attribute:"synopsis", value:
"The remote Unix host has an application that may be prone to a buffer
overflow attack.");
  script_set_attribute(attribute:"description", value:
"The Java Web Start utility distributed with the version of Sun Java
Runtime Environment (JRE) installed on the remote host may be affected
by a buffer overflow vulnerability. If an attacker can convince a user
on the affected host to open a specially crafted JNLP file, it may be
possible to execute arbitrary code subject to the user's privileges.");
  # http://www.eeye.com/Resources/Security-Center/Research/Security-Advisories/AD20070705
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cfe5f4a0");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/473224/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/473356/30/0/threaded");
  # http://web.archive.org/web/20080612184027/http://sunsolve.sun.com/search/document.do?assetkey=1-26-102996-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7eec761c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Sun Java JDK and JRE 6 Update 2 / JDK and JRE 5.0 Update 12
or later and remove, if necessary, any affected versions.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/07");
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
    ver =~ "^1\.6\.0_0[01][^0-9]?" ||
    ver =~ "^1\.5\.0_(0[0-9]|1[01])[^0-9]?"
  )
  {
    dirs = make_list(get_kb_list(install));
    vuln += max_index(dirs);

    foreach dir (dirs)
      info += '\n  Path              : ' + dir;

    info += '\n  Installed version : ' + ver;
    info += '\n  Fixed version     : 1.6.0_02 / 1.5.0_12\n';
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
  if (report_verbosity)
  {
    if (vuln > 1) s = "s of Sun's JRE are";
    else s = " of Sun's JRE is";

    report = string(
      "\n",
      "The following vulnerable instance", s, " installed on the\n",
      "remote host :\n",
      info
    );
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
