#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(57042);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/11 19:58:28 $");
  
  script_cve_id("CVE-2011-2462", "CVE-2011-4369");
  script_bugtraq_id(50922, 51092);
  script_osvdb_id(77529, 78026);
  
  script_name(english:"Adobe Acrobat < 9.4.7 Multiple Memory Corruption Vulnerabilities (APSB11-30)");
  script_summary(english:"Checks version of Adobe Acrobat");
 
  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat on the remote Windows host is affected
by multiple memory corruption vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of Adobe Acrobat earlier
than 9.4.7.  Such versions are affected by  multiple memory corruption
vulnerabilities related to the 'Universal 3D' (U3D) file format and
the 'Product Representation Compact' (PRC)  component.

A remote attacker could exploit this by tricking a user into viewing a
maliciously crafted PDF file, causing application crashes and
potentially resulting in arbitrary code execution.

This plugin does not check for Acrobat 10.x releases, which are
vulnerable but were not fixed until APSB12-01. Refer to plugin 57483
for more information.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-30.html");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/advisories/apsa11-04.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Acrobat 9.4.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Reader U3D Memory Corruption Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("adobe_acrobat_installed.nasl");
  script_require_keys("SMB/Acrobat/Version");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

version = get_kb_item_or_exit("SMB/Acrobat/Version");
path = get_kb_item_or_exit("SMB/Acrobat/Path");

version_ui = get_kb_item("SMB/Acrobat/Version_UI");
if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# This affects 9.x <= 9.4.6
# We'll ignore 10.x versions - the vulnerabilities described
# by this bulletin were not fixed in 10.x until APSB12-01
if (
  # 9.x
  (
    (ver[0] == 9 && ver[1] < 4) ||
    (ver[0] == 9 && ver[1] == 4 && ver[2] <= 6)
  )
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : '+path+
      '\n  Installed version : '+version_report+
      '\n  Fixed version     : 9.4.7\n';
    security_hole(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_hole(get_kb_item('SMB/transport'));
  exit(0);
}
else exit(0, 'The Adobe Acrobat '+version_report+' install on the host is not affected.');
