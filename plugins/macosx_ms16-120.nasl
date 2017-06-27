#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94010);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/28 21:06:38 $");

  script_cve_id("CVE-2016-3209");
  script_bugtraq_id(93385);
  script_osvdb_id(145510);
  script_xref(name:"MSFT", value:"MS16-120");
  script_xref(name:"IAVA", value:"2016-A-0278");

  script_name(english:"MS16-120: Security Update for Microsoft Graphics Component (3192884) (macOS)");
  script_summary(english:"Checks the version of Microsoft Silverlight.");

  script_set_attribute(attribute:"synopsis", value:
"A multimedia application framework installed on the remote macOS or
Mac OS X host is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Silverlight installed on the remote macOS or
Mac OS X host is affected by an information disclosure vulnerability
in the Graphics Device Interface (GDI) component due to improper
handling of objects in memory. A local attacker can exploit this
vulnerability, via a specially crafted application, to predict memory
offsets in a call stack and bypass the Address Space Layout
Randomization (ASLR) feature, resulting in the disclosure of memory
contents.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-120");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Silverlight 5.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:silverlight");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_silverlight_installed.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Silverlight/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb_base = "MacOSX/Silverlight";
get_kb_item_or_exit(kb_base+"/Installed");
path = get_kb_item_or_exit(kb_base+"/Path", exit_code:1);
version = get_kb_item_or_exit(kb_base+"/Version", exit_code:1);


bulletin = "MS16-120";
kb = "3193713";

fixed_version = "5.1.50901.0";
if (version =~ "^5\." && ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  if (defined_func("report_xml_tag")) report_xml_tag(tag:bulletin, value:kb);

  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_version +
    '\n';
  security_report_v4(port:0, severity:SECURITY_NOTE, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Microsoft Silverlight", version);
