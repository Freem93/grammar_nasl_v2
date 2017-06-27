#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(69834);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/01/28 22:37:18 $");

  script_cve_id("CVE-2013-3155", "CVE-2013-3156", "CVE-2013-3157");
  script_bugtraq_id(62229, 62230, 62231);
  script_osvdb_id(97111, 97112, 97113);
  script_xref(name:"MSFT", value:"MS13-074");
  script_xref(name:"IAVB", value:"2013-B-0099");

  script_name(english:"MS13-074: Vulnerabilities in Microsoft Access Could Allow Remote Code Execution (2848637)");
  script_summary(english:"Checks version of Acecore.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"It is possible to execute arbitrary code on the remote host through
Microsoft Access."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is running a version of Microsoft Access that
is affected by multiple remote code execution vulnerabilities.  These
vulnerabilities are due to the way that Microsoft Access parses content
in Access files.

If an attacker can trick a user on the affected host into opening a
specially crafted Access file, it may be possible to leverage these
issues to read arbitrary files on the target system or execute arbitrary
code, subject to the user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/security/advisory/2848637");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-074");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Microsoft Office 2007,
2010, and 2013."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:access");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS13-074';
kbs = make_list(
  2596825,
  2687423,
  2810009,
  2848637
);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

office_ver = hotfix_check_office_version();
vuln = 0;

# Office 2013
if (office_ver['15.0'])
{
  path = hotfix_get_officecommonfilesdir(officever:"15.0") + "\Microsoft Shared\Office15";

  kb = "2810009";
  if (hotfix_is_vulnerable(file:"Acecore.dll", version:"15.0.4517.1003", min_version:"15.0.0.0", path:path, bulletin:bulletin, kb:kb)) vuln++;
}

# Office 2010 SP1 or SP2
if (office_ver['14.0'])
{
  office_sp = get_kb_item("SMB/Office/2010/SP");
  if (!isnull(office_sp) && (office_sp == 1 || office_sp == 2))
  {
    path = hotfix_get_officecommonfilesdir(officever:"14.0") + "\Microsoft Shared\Office14";

    kb = "2687423";
    if (hotfix_is_vulnerable(file:"Acecore.dll", version:"14.0.7102.1000", min_version:"14.0.0.0", path:path, bulletin:bulletin, kb:kb)) vuln++;
  }
}

# Office 2007 SP3
if (office_ver['12.0'])
{
  office_sp = get_kb_item("SMB/Office/2007/SP");
  if (!isnull(office_sp) && office_sp == 3)
  {
    path = hotfix_get_officecommonfilesdir(officever:"12.0") + "\Microsoft Shared\Office12";

    kb = "2596825";
    if (hotfix_is_vulnerable(file:"Acecore.dll", version:"12.0.6679.5000", min_version:"12.0.0.0", path:path, bulletin:bulletin, kb:kb)) vuln++;
  }
}

if (vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
