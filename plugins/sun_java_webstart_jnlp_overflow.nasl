#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25693);
  script_version("$Revision: 1.27 $");
  script_cvs_date("$Date: 2017/05/01 13:40:22 $");

  script_cve_id("CVE-2007-3655");
  script_bugtraq_id(24832);
  script_osvdb_id(37756);
  script_xref(name:"EDB-ID", value:"30284");

  script_name(english:"Sun Java Web Start JNLP File Handling Overflow (102996)");
  script_summary(english:"Checks version of Sun JRE");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that may be prone to a
buffer overflow attack.");
  script_set_attribute(attribute:"description", value:
"There is reportedly a buffer overflow in the Java Web Start utility
distributed with the version of Sun Java Runtime Environment (JRE)
installed on the remote host. If an attacker can convince a user on
the affected host to open a specially crafted JNLP file, arbitrary
code could be executed subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://research.eeye.com/html/advisories/published/AD20070705.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/473224/30/0/threaded" );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/473356/30/0/threaded" );
  # http://web.archive.org/web/20080612184027/http://sunsolve.sun.com/search/document.do?assetkey=1-26-102996-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7eec761c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Sun Java JDK and JRE 6 Update 2 / JDK and JRE 5.0 Update 12
or later and remove, if necessary, any affected versions.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

  script_dependencies("sun_java_jre_installed.nasl");
  script_require_keys("SMB/Java/JRE/Installed");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


# Check each installed JRE.
installs = get_kb_list("SMB/Java/JRE/*");
if (isnull(installs)) exit(0);

info = "";
vuln = 0;
foreach install (list_uniq(keys(installs)))
{
  ver = install - "SMB/Java/JRE/";
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
}


# Report if any were found to be vulnerable.
if (info)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity)
  {
    if (vuln > 1) s = "s of Sun's JRE are";
    else s = " of Sun's JRE is";

    report =
      '\n' +
      'The following vulnerable instance' + s + ' installed on the\n' +
      'remote host :\n' +
      info;
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
