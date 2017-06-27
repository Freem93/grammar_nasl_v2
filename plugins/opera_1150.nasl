#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55470);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/12 14:46:30 $");

  script_cve_id(
    "CVE-2011-1337", 
    "CVE-2011-2609", 
    "CVE-2011-2610",
    "CVE-2011-2611",
    "CVE-2011-2612",
    "CVE-2011-2613",
    "CVE-2011-2614",
    "CVE-2011-2615",
    "CVE-2011-2616",
    "CVE-2011-2617",
    "CVE-2011-2618",
    "CVE-2011-2619",
    "CVE-2011-2620",
    "CVE-2011-2621",
    "CVE-2011-2622",
    "CVE-2011-2623",
    "CVE-2011-2624",
    "CVE-2011-2625",
    "CVE-2011-2626",
    "CVE-2011-2627" 
  );
  script_bugtraq_id(48500, 48501, 48556, 48568);
  script_osvdb_id(
    73484,
    73485,
    73486,
    73804,
    73805,
    73806,
    73807,
    73833,
    73834,
    73835,
    73836,
    73837,
    73838,
    73839,
    73840,
    73841,
    73842,
    73843,
    73844,
    73845
  );
  script_xref(name:"Secunia", value:"45060");

  script_name(english:"Opera < 11.50 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote Windows host is earlier
than 11.50 and thus potentially affected by multiple vulnerabilities:

  - An error exists in the handling of data URIs that
    allows cross-site scripting in some unspecified cases. 
    (Issue #995)

  - An error exists in the browser's handling of error 
    pages. Opera generates error pages in response to an
    invalid URL. If enough invalid URLs are attempted, the
    host's disk space is eventually filled, the browser
    crashes and the error files are left behind. 
    (Issue #996)

  - An additional, moderately severe and unspecified error
    exists. Details regarding this error are to be released
    in the future. (CVE-2011-2610)

  - Several unspecified errors exist that can cause 
    application crashes. Affected items or functionaility
    are: printing, unspecified web content, JavaScript
    Array.prototype.join method, drawing paths with many
    characters, selecting text nodes, iframes, 
    closed or removed pop-up windows, moving audio or
    video elements between windows, canvas elements, SVG
    items, CSS files, form layouts, web workers, SVG BiDi,
    large tables and print preview, select elements with
    many items, and the src attribute of the iframe element.
    (CVE-2011-2611, CVE-2011-2612, CVE-2011-2613, 
    CVE-2011-2614, CVE-2011-2615, CVE-2011-2616,
    CVE-2011-2617, CVE-2011-2618, CVE-2011-2619,
    CVE-2011-2620, CVE-2011-2621, CVE-2011-2622,
    CVE-2011-2623, CVE-2011-2624, CVE-2011-2625,
    CVE-2011-2626, CVE-2011-2627)");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/995/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/996/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/1150/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Opera 11.50 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/30");
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

fixed_version = "11.50.1074.0";

# Check if we need to display full version info in case of Alpha/Beta/RC
major_minor = eregmatch(string:version, pattern:"^([0-9]+\.[0-9]+)");
if (major_minor[1] == "11.50")
{
  fixed_version_report = fixed_version;
  version_report = version;
}
else
  fixed_version_report = "11.50";

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
