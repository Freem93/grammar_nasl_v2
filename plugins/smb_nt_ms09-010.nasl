#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36148);
  script_version("$Revision: 1.29 $");
  script_cvs_date("$Date: 2016/12/09 20:55:00 $");

  script_cve_id(
    "CVE-2008-4841",
    "CVE-2009-0087",
    "CVE-2009-0088",
    "CVE-2009-0235"
  );
  script_bugtraq_id(29769, 32718, 34469, 34470);
  script_osvdb_id(50567, 53662, 53663, 53664);
  script_xref(name:"IAVA", value:"2009-A-0032");
  script_xref(name:"MSFT", value:"MS09-010");
  script_xref(name:"EDB-ID", value:"6560");

  script_name(english:"MS09-010: Vulnerabilities in WordPad and Office Text Converters Could Allow Remote Code Execution (960477)");
  script_summary(english:"Checks for the presence of update 960477");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to execute arbitrary code on the remote Windows host
using a text converter.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Microsoft WordPad and/or
Microsoft Office text converters that could allow remote code execution
if a specially crafted file is opened.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-010");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2000 and XP as well
as the Office 2003 File Converter Pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(20, 119, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_converter_pack");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}


include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS09-010';

kbs = make_list("921606", "923561", "933399", "960476");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'1,2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

path = hotfix_get_programfilesdir() + "\Windows NT\Accessories";

share = hotfix_path2share(path:path);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = 0;

if (
  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", file:"Mswrd8.wpc", version:"10.0.803.10", path:path, bulletin:bulletin, kb:"923561") ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1", file:"Mswrd8.wpc", version:"10.0.803.10", path:path, bulletin:bulletin, kb:"923561") ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0", file:"Mswrd8.wpc", version:"10.0.803.10", path:path, bulletin:bulletin, kb:"923561")
) vuln++;


office_versions = hotfix_check_office_version();
if ( office_versions["10.0"] || office_versions["9.0"] )
{
  path = hotfix_get_commonfilesdir() + "\Microsoft Shared\TextConv";
  share = hotfix_path2share(path:path);
  if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

  if (
     hotfix_is_vulnerable(os:"5.2", file:"Msconv97.dll", version:"2003.1100.8202.0", path:path, bulletin:bulletin, kb:"960476") ||
     hotfix_is_vulnerable(os:"5.1", file:"Msconv97.dll", version:"2003.1100.8202.0", path:path, bulletin:bulletin, kb:"933399") ||
     hotfix_is_vulnerable(os:"5.0", file:"Msconv97.dll", version:"2003.1100.8202.0", path:path, bulletin:bulletin, kb:"921606")
  ) vuln++;
}

if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
