#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(44643);
  script_version('$Revision: 1.15 $');
  script_cvs_date("$Date: 2016/11/11 19:58:28 $");

  script_cve_id("CVE-2010-0186", "CVE-2010-0188");
  script_bugtraq_id(38195, 38198);
  script_osvdb_id(27723, 62300, 62301);
  script_xref(name:"Secunia", value:"38551");

  script_name(english:"Adobe Acrobat < 9.3.1 / 8.2.1  Multiple Vulnerabilities (APSB10-07)");
  script_summary(english:"Checks version of Adobe Acrobat");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote host is earlier
than 9.3.1 / 8.2.1.  Such versions are reportedly affected by multiple
vulnerabilities :

  - An issue that could subvert the domain sandbox and make
    unauthorized cross-domain requests. (CVE-2010-0186)

  - An unspecified vulnerability could cause the application
    to crash or possibly lead to arbitrary code execution.
    (CVE-2010-0188)");
  script_set_attribute(attribute:'see_also', value:'http://www.adobe.com/support/security/bulletins/apsb10-07.html');
  script_set_attribute(attribute:'solution', value:'Upgrade to Adobe Acrobat 9.3.1 / 8.2.1 or later.');
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Acrobat Bundled LibTIFF Integer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:'Windows');

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
  script_dependencies('adobe_acrobat_installed.nasl');
  script_require_keys('SMB/Acrobat/Version');
  exit(0);
}


include('global_settings.inc');

version = get_kb_item('SMB/Acrobat/Version');
if (isnull(version)) exit(1, "The 'SMB/Acrobat/Version' KB item is missing.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if  (
  ver[0] < 8 ||
  (ver[0] == 8 && ver[1] < 2) ||
  (ver[0] == 8 && ver[1] == 2 && ver[2] < 1) ||
  (ver[0] == 9 && ver[1] < 3) ||
  (ver[0] == 9 && ver[1] == 3 && ver[2] < 1)
)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  version_ui = get_kb_item('SMB/Acrobat/Version_UI');

  if (report_verbosity > 0 && version_ui)
  {
    path = get_kb_item('SMB/Acrobat/Path');
    if (isnull(path)) path = 'n/a';

    report =
      '\n'+
      '  Product           : Adobe Acrobat\n'+
      '  Path              : '+path+'\n'+
      '  Installed version : '+version_ui+'\n'+
      '  Fixed version     : 9.3.1 / 8.2.1\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "The host is not affected since Adobe Acrobat "+version+" is installed.");
