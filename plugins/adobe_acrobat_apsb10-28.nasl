#
# (C) Tenable Network Security, Inc.
#


include('compat.inc');

if (description)
{
  script_id(50613);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/11 19:58:28 $");

  script_name(english:"Adobe Acrobat 9.x < 9.4.1 Multiple Vulnerabilities (APSB10-28)");
  script_summary(english:"Checks version of Adobe Acrobat");

  script_cve_id("CVE-2010-3636", "CVE-2010-3637", "CVE-2010-3639", "CVE-2010-3640",
                "CVE-2010-3641", "CVE-2010-3642", "CVE-2010-3643", "CVE-2010-3644", 
                "CVE-2010-3645", "CVE-2010-3646", "CVE-2010-3647", "CVE-2010-3648",
                "CVE-2010-3649", "CVE-2010-3650", "CVE-2010-3652", "CVE-2010-3654", 
                "CVE-2010-3976");
  script_bugtraq_id(44504,44838);
  script_osvdb_id(
    68736,
    68932,
    69121,
    69122,
    69123,
    69124,
    69125,
    69126,
    69127,
    69128,
    69129,
    69130,
    69131,
    69132,
    69133,
    69135,
    69146
  );
  script_xref(name:"Secunia", value:"42030");

  script_set_attribute(attribute:"synopsis",value:
"The version of Adobe Acrobat on the remote Windows host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The version of Adobe Acrobat 9.x installed on the remote host is
earlier than 9.4.1.  Such versions are reportedly affected by multiple
vulnerabilities :

  - A memory corruption vulnerability exists that could lead 
    to code execution.  Note that this issue does not affect
    Adobe Acrobat 8.x.  (CVE-2010-3654)

  - An input validation issue exists that could lead to a
    bypass of cross-domain policy file restrictions with
    certain server encodings. (CVE-2010-3636)

  - A memory corruption vulnerability exists in the ActiveX
    component. (CVE-2010-3637)

  - An unspecified issue exists which could lead to a 
    denial of service or potentially arbitrary code 
    execution. (CVE-2010-3639)

  - Multiple memory corruption issues exist that could lead
    to arbitrary code execution. (CVE-2010-3640, 
    CVE-2010-3641, CVE-2010-3642, CVE-2010-3643, 
    CVE-2010-3644, CVE-2010-3645, CVE-2010-3646,
    CVE-2010-3647, CVE-2010-3648, CVE-2010-3649,
    CVE-2010-3650, CVE-2010-3652)
    
  - A library-loading vulnerability could lead to code 
    execution. (CVE-2010-3976)");

  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb10-28.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Acrobat 9.4.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player "Button" Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/16");
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


include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/Acrobat/Version");
version_ui = get_kb_item('SMB/Acrobat/Version_UI');

if (isnull(version_ui)) version_report = version;
else version_report = version_ui;

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if ( 
  (ver[0] == 9 && ver[1]  < 4) ||
  (ver[0] == 9 && ver[1] == 4 && ver[2] < 1)
)
{
  if (report_verbosity > 0)
  {
    path = get_kb_item('SMB/Acrobat/Path');
    if (isnull(path)) path = 'n/a';

    report =
      '\n  Path              : '+path+
      '\n  Installed version : '+version_report+
      '\n  Fixed version     : 9.4.1\n';
    security_hole(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_hole(get_kb_item('SMB/transport'));
}
else exit(0, "The host is not affected since Adobe Acrobat "+version_report+" is installed.");
