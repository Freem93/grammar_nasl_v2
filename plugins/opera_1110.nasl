#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55506);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/12 14:46:30 $");

  script_cve_id(
    "CVE-2011-2634",
    "CVE-2011-2635",
    "CVE-2011-2636",
    "CVE-2011-2637",
    "CVE-2011-2638",
    "CVE-2011-2639",
    "CVE-2011-2640"
  );
  script_bugtraq_id(48569, 48634);
  script_osvdb_id(73851, 73852, 73853, 73854, 73855, 73856, 73857);

  script_name(english:"Opera < 11.10 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote Windows host is earlier
than 11.10 and thus is potentially affected by the following
vulnerabilities :

  - An unspecified vulnerability allows remote attackers
    to hijack searches and customizations using unspecified
    third-party applications. (CVE-2011-2634)

  - Several errors exist that can cause application
    crashes. Affected items or functionalities are the
    handling of the CSS pseudo-class ':hover' if used
    with transforms on a floated element, unspecified web
    content, and the handling of an embedded Java applet
    with empty parameters. (CVE-2011-2635, CVE-2011-2636,
    CVE-2011-2637, CVE-2011-2638, CVE-2011-2640)

  - An error in the handling of hidden animated GIF 
    images can cause a denial of service through CPU
    consumption as image repaints are triggered. 
    (CVE-2011-2639)");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/1110/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Opera 11.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/05");
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

fixed_version = "11.10.2092.0";

# Check if we need to display full version info in case of Alpha/Beta/RC
major_minor = eregmatch(string:version, pattern:"^([0-9]+\.[0-9]+)");
if (major_minor[1] == "11.10")
{
  fixed_version_report = fixed_version;
  version_report = version;
}
else
  fixed_version_report = "11.10";

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
    security_warning(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_warning(port:get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, "The host is not affected since Opera "+version_report+" is installed.");
