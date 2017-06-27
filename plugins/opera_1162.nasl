#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58583);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/04/04 10:51:37 $");

  script_cve_id(
    "CVE-2012-1924",
    "CVE-2012-1925",
    "CVE-2012-1926",
    "CVE-2012-1927",
    "CVE-2012-1928"
  );
  script_bugtraq_id(52731);
  script_osvdb_id(80620, 80621, 80622, 80623, 80624);

  script_name(english:"Opera < 11.62 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is potentially affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote Windows host is earlier
than 11.62 and is, therefore, potentially affected by multiple
vulnerabilities :

  - The download dialog box can be displayed in a very
    small window thus, tricking a user into not realizing
    it is open. Certain keyboard entries after this can
    allow a user to take unintended actions. (Issue #1010)

  - The download dialog box can be hidden behind certain
    page content thus, tricking a user into not realizing
    it is open. Certain user actions after this can allow
    a user to take unintended actions. (Issue #1011)

  - Improper restrictions after the use of
    'history.pushState' and 'history.replaceState' can
    allow information disclosure of state data when cross-
    domain frames are in use. (Issue #1012)

  - Dialog boxes can cause the application to display an
    incorrect address in the URL bar. (Issue #1013)

  - Certain webpage reloading timing issues can cause the
    application to display incorrect information in the URL
    bar. (Issue #1014)");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/1010/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/1011/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/1012/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/1013/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/1014/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/1162/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Opera 11.62 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("opera_installed.nasl");
  script_require_keys("SMB/Opera/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

path = get_kb_item_or_exit("SMB/Opera/Path");
version = get_kb_item_or_exit("SMB/Opera/Version");
version_ui = get_kb_item("SMB/Opera/Version_UI");

if (isnull(version_ui)) version_report = version;
else version_report = version_ui; 

fixed_version = "11.62.1347.0";

# Check if we need to display full version info in case of Alpha/Beta/RC
major_minor = eregmatch(string:version, pattern:"^([0-9]+\.[0-9]+)");
if (major_minor[1] == "11.62")
{
  fixed_version_report = fixed_version;
  version_report = version;
}
else
  fixed_version_report = "11.62";

if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  port = get_kb_item("SMB/transport");
  if (report_verbosity > 0)
  {
    report = 
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : ' + fixed_version_report +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The Opera "+version_report+" install under "+path+" is not affected.");
