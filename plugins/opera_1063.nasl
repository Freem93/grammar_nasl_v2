#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49964);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/07 13:40:41 $");

  script_cve_id(
    "CVE-2010-4043",
    "CVE-2010-4044",
    "CVE-2010-4045",
    "CVE-2010-4046",
    "CVE-2010-4047",
    "CVE-2010-4048",
    "CVE-2010-4049",
    "CVE-2010-4050"
  );
  script_bugtraq_id(
    43607, 
    43920,
    73570,
    73680
  );
  script_osvdb_id(
    68826,
    68827,
    68828,
    68829,
    68830,
    68831,
    68832,
    68833
  );
  script_xref(name:"MSVR", value:"MSVR11-002");
  script_xref(name:"Secunia", value:"41740");

  script_name(english:"Opera < 10.63 Multiple Vulnerabilities");
  script_summary(english:"Checks the version number of Opera.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote host is prior to 10.63.
It is, therefore, affected by the multiple vulnerabilities :

  - It is possible to bypass cross-domain checks and allow
    partial data theft by using CSS. (971)

  - It is possible to spoof the page address by modifying
    the size of the browser window. (972)

  - Carefully timed reloads and redirects allow spoofing and
    cross-site scripting attacks. Using this XSS vector i
     may be possible to modify Opera's configuration, which
     could allow arbitrary code execution on the remote
     system. (973)

  - It is possible to intercept private video streams.
    (974)

  - An error while displaying invalid URLs allows cross-site
    scripting attacks. (976)

  - It's possible to crash the application and cause a
    denial of service condition when saving a file while the
    page redirects, when viewing a Flash movie with a
    transparent Window Mode (wmode) property, or when SVG
    exists in an '<img>' element.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d1d3543");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/1063/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/971/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/972/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/973/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/974/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/976/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Opera 10.63 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/13");
  
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Opera/Version");

version_ui = get_kb_item("SMB/Opera/Version_UI");
if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

install_path = get_kb_item("SMB/Opera/Path");

if (ver_compare(ver:version, fix:'10.63.3516.0') == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + install_path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : 10.63\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(port:get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, "The host is not affected since Opera "+version_report+" is installed.");
