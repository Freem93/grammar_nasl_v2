#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87250);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/28 21:06:38 $");

  script_cve_id("CVE-2015-6106", "CVE-2015-6107", "CVE-2015-6108");
  script_xref(name:"MSFT", value:"MS15-128");
  script_xref(name:"IAVA", value:"2015-A-0308");

  script_name(english:"Microsoft Silverlight < 5.1.41105.0 Multiple Vulnerabilities (MS15-128) (Mac OS X)");
  script_summary(english:"Checks the version of Microsoft Silverlight.");

  script_set_attribute(attribute:"synopsis", value:
"A multimedia application framework installed on the remote Mac OS X
host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Silverlight installed on the remote host is
affected by multiple remote code execution vulnerabilities due to 
improper handling of embedded fonts by the Windows font library.  A
remote attacker can exploit these by convincing a user to open a file
or visit a website containing a specially crafted embedded font, 
resulting in execution of arbitrary code in the context of the current
user.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms15-128");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Silverlight 5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:silverlight");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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


bulletin = "MS15-128";
kb = "3106614";

fixed_version = "5.1.41105.0";
if (version =~ "^5\." && ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  if (defined_func("report_xml_tag")) report_xml_tag(tag:bulletin, value:kb);

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else exit(0, "The Microsoft Silverlight "+version+" install is not reported to be affected.");
