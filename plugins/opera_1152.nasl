#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56585);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/20 14:21:43 $");

  script_cve_id("CVE-2011-4152");
  script_bugtraq_id(50044, 50320);
  script_osvdb_id(129573);
  script_xref(name:"EDB-ID", value:"17960");
  script_xref(name:"EDB-ID", value:"18006");
  script_xref(name:"EDB-ID", value:"18008");

  script_name(english:"Opera < 11.52 Multiple Vulnerabilities");
  script_summary(english:"Checks the version number of Opera.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote Windows host is prior to
11.52. It is, therefore, affected by multiple vulnerabilities :

  - An unspecified use-after-free error exists due to 
    improper validation of user-supplied input. A remote
    attacker can exploit this, via a specially crafted web
    page, to dereference already freed memory, resulting in
    a crash of the browser. (CVE-2011-4152)

  - An error exists related to the handling of certain font 
    manipulations inside dynamically added or specifically
    embedded SVG images or SVG content in nested frames. A
    remote attacker can exploit this to crash the
    application or execute arbitrary code.
    (BID 50044 / Issue #1002)

  - Multiple unspecified errors exist that allow an attacker
    to cause a stack overflow condition, resulting in a
    browser crash.");
  # https://web.archive.org/web/20130302201601/http://www.opera.com/support/kb/view/1002/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?89f357a0");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/1152/");
  # http://spa-s3c.blogspot.com/2011/10/spas3c-sv-006opera-browser-101112-0-day.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c1a34bd3");
  script_set_attribute(attribute:"see_also", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/50044.rb");
  script_set_attribute(attribute:"solution", value:"Upgrade to Opera 11.52 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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

fixed_version = "11.52.1100.0";

# Check if we need to display full version info in case of Alpha/Beta/RC
major_minor = eregmatch(string:version, pattern:"^([0-9]+\.[0-9]+)");
if (major_minor[1] == "11.52")
{
  fixed_version_report = fixed_version;
  version_report = version;
}
else
  fixed_version_report = "11.52";

if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  if (report_verbosity > 0)
  {
    install_path = get_kb_item("SMB/Opera/Path");

    report = 
      '\n  Path              : ' + install_path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : ' + fixed_version_report +
      '\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(port:get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, "The host is not affected since Opera "+version_report+" is installed.");
