#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(58682);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/11/27 17:20:53 $");

  script_cve_id("CVE-2012-0774", "CVE-2012-0775", "CVE-2012-0776");
  script_bugtraq_id(52949, 52951, 52952);
  script_osvdb_id(81246, 81247, 81248);
  
  script_name(english:"Adobe Acrobat < 10.1.3 / 9.5.1 Multiple Vulnerabilities (APSB12-08)");
  script_summary(english:"Checks version of Adobe Acrobat");

  script_set_attribute(attribute:"synopsis",value:
"The version of Adobe Acrobat on the remote Windows host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The version of Adobe Acrobat installed on the remote host is earlier
than 10.1.3 / 9.5.1 and is, therefore, affected by multiple
vulnerabilities :

  - An integer overflow vulnerability exists in True Type 
    Font (TFF). (CVE-2012-0774)

  - A memory corruption vulnerability exists in the 
    JavaScript handling. (CVE-2012-0775)

  - A security bypass exists in the Adobe Acrobat installer.
    (CVE-2012-0776)");
  script_set_attribute(attribute:"see_also", value:"http://dvlabs.tippingpoint.com/advisory/TPTI-12-03");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb12-08.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Adobe Acrobat 9.5.1 / 10.1.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:'Windows');
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

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
  (ver[0] == 9 && ver[1] < 5) ||
  (ver[0] == 9 && ver[1] == 5 && ver[2] == 0) ||
  (ver[0] == 10 && ver[1] < 1) ||
  (ver[0] == 10 && ver[1] == 1 && ver[2] < 3)
)
{
  if (report_verbosity > 0)
  {
    path = get_kb_item('SMB/Acrobat/Path');
    if (isnull(path)) path = 'n/a';

    report =
      '\n  Path              : '+path+
      '\n  Installed version : '+version_report+
      '\n  Fixed version     : 9.5.1 / 10.1.3\n';
    security_hole(port:get_kb_item('SMB/transport'), extra:report);
  }
  else security_hole(get_kb_item('SMB/transport'));
}
else exit(0, "The Adobe Acrobat "+version_report+" install is not affected.");
