#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54587);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/20 14:21:43 $");

  script_cve_id(
    "CVE-2011-2628",
    "CVE-2011-2629",
    "CVE-2011-2630",
    "CVE-2011-2631",
    "CVE-2011-2632",
    "CVE-2011-2633"
  );
  script_bugtraq_id(47906, 48570);
  script_osvdb_id(72406, 73846, 73847, 73848, 73849, 73850);
  script_xref(name:"EDB-ID", value:"17936");
  script_xref(name:"Secunia", value:"44611");

  script_name(english:"Opera < 11.11 Multiple Vulnerabilities");
  script_summary(english:"Checks version number of Opera");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by memory
corruption vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Opera installed on the remote Windows host is earlier
than 11.11. Such versions are potentially affected by:

  - A memory corruption vulnerability exists. The 
    application does not properly handle specific 
    framesets when unloading a page. An attacker could 
    craft a web page that will trigger the vulnerability 
    which may allow arbitrary code execution.
    (CVE-2011-2628)

  - Several errors exist that can cause application 
    crashes. Affected items or functionality include 
    unspecified web content, reloading pages after opening
    a pop-up from the Easy Sticky Note extension, handling
    of the column-count CSS property, destruction of a
    Silverlight instance, the handling of Certificate
    Revocation Lists (CRL). (CVE-2011-2629, CVE-2011-2630, 
    CVE-2011-2631, CVE-2011-2632, CVE-2011-2633)."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/support/kb/view/992/");
  script_set_attribute(attribute:"see_also", value:"http://www.opera.com/docs/changelogs/windows/1111/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Opera 11.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/19");
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

if (ver_compare(ver:version, fix:'11.11.2109.0') == -1)
{
  if (report_verbosity > 0)
  {
    install_path = get_kb_item("SMB/Opera/Path");

    report = 
      '\n  Path              : ' + install_path +
      '\n  Installed version : ' + version_report +
      '\n  Fixed version     : 11.11\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(port:get_kb_item("SMB/transport"));
  exit(0);
}
else exit(0, "The host is not affected since Opera "+version_report+" is installed.");
