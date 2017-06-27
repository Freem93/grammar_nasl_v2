#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59045);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/11/28 21:06:38 $");

  script_cve_id("CVE-2011-3402", "CVE-2012-0159", "CVE-2012-0176");
  script_bugtraq_id(50462, 53335, 53360);
  script_osvdb_id(76843, 81718, 81720);
  script_xref(name:"MSFT", value:"MS12-034");
  script_xref(name:"IAVA", value:"2012-A-0079");

  script_name(english:"MS12-034: Combined Security Update for Microsoft Office, Windows, .NET Framework, and Silverlight (2681578) (Mac OS X)");
  script_summary(english:"Checks version of Microsoft Silverlight");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A multimedia application framework installed on the remote Mac OS X
host is affected by a remote code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Microsoft Silverlight installed on the remote host
is reportedly affected by several vulnerabilities :

  - Incorrect handling of TrueType font (TTF) files could
    lead to arbitrary code execution. (CVE-2011-3402 /
    CVE-2012-0159)

  - A double-free condition leading to arbitrary code
    execution could be triggered when rendering specially
    crafted XAML glyphs. (CVE-2012-0176)"
  );
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-034");
  script_set_attribute(attribute:"solution", value:"Microsoft has released patches for Silverlight 4 and 5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:silverlight");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_silverlight_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Silverlight/Installed");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


kb_base = "MacOSX/Silverlight";
get_kb_item_or_exit(kb_base+"/Installed");
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);
version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);


bulletin = "MS12-034";
fixed_version = "";

# nb: Multiple installs of Silverlight are not possible.
if (version =~ "^4\.")
{
  fixed_version = "4.1.10329.0";
  kb = "2690729";
}
else if (version =~ "^5\.")
{
  fixed_version = "5.1.10411.0";
  kb = "2636927";
}

if (fixed_version && ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  if (defined_func("report_xml_tag")) report_xml_tag(tag:bulletin, value:kb);

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : '+fixed_version +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else exit(0, "The Microsoft Silverlight "+version+" install is not reported to be affected.");
