#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70341);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/04/15 16:56:28 $");

  script_cve_id("CVE-2013-3896");
  script_bugtraq_id(62793);
  script_osvdb_id(98223);
  script_xref(name:"MSFT", value:"MS13-087");

  script_name(english:"MS13-087: Vulnerability in Silverlight Could Allow Information Disclosure (2890788) (Mac OS X)");
  script_summary(english:"Checks version of Microsoft Silverlight");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A multimedia application framework installed on the remote Mac OS X
host is affected by an information disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Microsoft Silverlight installed on the remote host is
reportedly affected by an information disclosure vulnerability due to
its failure to properly handle certain objects in memory.

If an attacker could trick a user on the affected system into visiting a
website hosting a malicious Silverlight application, the attacker could
leverage this vulnerability to disclose information from the affected
system, subject to the user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms13-087");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Silverlight 5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS13-022 Microsoft Silverlight ScriptObject Unsafe Memory Access');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:silverlight");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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


bulletin = "MS13-087";
kb = "2890788";

fixed_version = "5.1.20913.0";
if (version =~ "^5\." && ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  if (defined_func("report_xml_tag")) report_xml_tag(tag:bulletin, value:kb);

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : '+fixed_version +
      '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
  exit(0);
}
else exit(0, "The Microsoft Silverlight "+version+" install is not reported to be affected.");
