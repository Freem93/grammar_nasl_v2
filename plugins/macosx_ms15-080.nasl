#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85347);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/20 14:12:05 $");

  script_cve_id(
    "CVE-2015-2435",
    "CVE-2015-2455",
    "CVE-2015-2456",
    "CVE-2015-2463",
    "CVE-2015-2464"
  );
  script_bugtraq_id(
    76216,
    76238,
    76239,
    76240,
    76241
  );
  script_osvdb_id(
    125970,
    125971,
    125972,
    125973,
    125974
  );
  script_xref(name:"MSFT", value:"MS15-080");
  script_xref(name:"IAVA", value:"2015-A-0196");

  script_name(english:"Microsoft Silverlight < 5.1.40728.0 Multiple Vulnerabilities (MS15-080) (Mac OS X)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis",value:
"A multimedia application framework installed on the remote Mac OS X
host is affected by multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The Microsoft Silverlight installed on the remote Mac OS X host is
affected by multiple remote code execution vulnerabilities related to
flaws in handling specially crafted TrueType fonts.");
  script_set_attribute(attribute:"see_also",value:"https://technet.microsoft.com/library/security/MS15-080");
  script_set_attribute(attribute:"solution",value:
"Microsoft has released a set of patches for Mac OS X Silverlight.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/08/11");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/12");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:microsoft:silverlight");
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


bulletin = "MS15-080";
kb = "3080333";

fixed_version = "5.1.40728.0";
if (version =~ "^5\." && ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  if (defined_func("report_xml_tag")) report_xml_tag(tag:bulletin, value:kb);

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' +fixed_version +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else exit(0, "The Microsoft Silverlight "+version+" install is not reported to be affected.");
