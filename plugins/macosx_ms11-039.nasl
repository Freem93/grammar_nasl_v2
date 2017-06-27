#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(58093);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/04/15 16:56:27 $");

  script_cve_id("CVE-2011-0664");
  script_bugtraq_id(48212);
  script_osvdb_id(72931);
  script_xref(name:"MSFT", value:"MS11-039");

  script_name(english:"MS11-078: Vulnerability in Microsoft Silverlight Could Allow Remote Code Execution (2514842) (Mac OS X)");
  script_summary(english:"Checks version of Microsoft Silverlight.");

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
reportedly is affected by a code execution vulnerability.  A
specially crafted web application could access memory unsafely,
resulting in arbitrary code execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-039");

  script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/download/en/details.aspx?id=26488");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Silverlight 4.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:silverlight");
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

bulletin = "MS11-039";
kb = "2512827";
fixed_version = "4.0.60531.0";

if (
  version =~ "^4\." &&
  ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0
)
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
else exit(0, "The Microsoft Silverlight "+version+" install is not affected.");
