#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59906);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/12/09 21:04:54 $");

  script_cve_id("CVE-2012-1889");
  script_bugtraq_id(53934);
  script_osvdb_id(82873);
  script_xref(name:"MSFT", value:"MS12-043");

  script_name(english:"MS12-043: Vulnerability in Microsoft XML Core Services Could Allow Remote Code Execution (2722479)");
  script_summary(english:"Checks the versions of Msxml3.dll, Msxml4.dll, and Msxml6.dll");
  script_set_attribute(
    attribute:"synopsis",
    value:
"Arbitrary code can be executed on the remote host through Microsoft
XML Core Services."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Microsoft XML Core Services installed on the remote
Windows host is affected by a remote code execution vulnerability
that could allow arbitrary code execution if a user views a specially
crafted web page using Internet Explorer."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-043");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/2719615");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS12-043 Microsoft XML Core Services MSXML Uninitialized Memory Corruption');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:xml_core_services");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS12-043';
kbs = make_list("2719985", "2721691", "2721693", "2687324", "2596856", "2596679", "2687497", "2687627");

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'0,1', win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

if (!is_accessible_share())  audit(AUDIT_SHARE_FAIL, 'is_accessible_share');

commonfiles = hotfix_get_commonfilesdir();
if (commonfiles)
  msxml5_dir = commonfiles + '\\Microsoft Shared\\Office11';

vuln = 0;

# Windows 8 / Server 2012
vuln += hotfix_is_vulnerable(os:"6.2", sp:0, file:"Msxml4.dll", version:"4.30.2114.0", min_version:"4.30.0.0",            dir:"\System32", bulletin:bulletin, kb:"2721691");

# Windows 7 / Server 2008 R2
vuln += hotfix_is_vulnerable(os:"6.1", sp:0, file:"Msxml3.dll", version:"8.110.7600.17036",                                  dir:"\System32", bulletin:bulletin, kb:"2719985");
vuln += hotfix_is_vulnerable(os:"6.1", sp:0, file:"Msxml3.dll", version:"8.110.7600.21227", min_version:"8.110.7600.21000",  dir:"\System32", bulletin:bulletin, kb:"2719985");
vuln += hotfix_is_vulnerable(os:"6.1", sp:1, file:"Msxml3.dll", version:"8.110.7601.17857", min_version:"8.110.7601.17000",  dir:"\System32", bulletin:bulletin, kb:"2719985");
vuln += hotfix_is_vulnerable(os:"6.1", sp:1, file:"Msxml3.dll", version:"8.110.7601.22012", min_version:"8.110.7601.22000",  dir:"\System32", bulletin:bulletin, kb:"2719985");
vuln += hotfix_is_vulnerable(os:"6.1",       file:"Msxml4.dll", version:"4.30.2114.0", min_version:"4.30.0.0",            dir:"\System32", bulletin:bulletin, kb:"2721691");
vuln += hotfix_is_vulnerable(os:"6.1", sp:0, file:"Msxml6.dll", version:"6.30.7600.17036",                                   dir:"\System32", bulletin:bulletin, kb:"2719985");
vuln += hotfix_is_vulnerable(os:"6.1", sp:0, file:"Msxml6.dll", version:"6.30.7600.21227",  min_version:"6.30.7600.21000",   dir:"\System32", bulletin:bulletin, kb:"2719985");
vuln += hotfix_is_vulnerable(os:"6.1", sp:1, file:"Msxml6.dll", version:"6.30.7601.17857",  min_version:"6.30.7601.17000",   dir:"\System32", bulletin:bulletin, kb:"2719985");
vuln += hotfix_is_vulnerable(os:"6.1", sp:1, file:"Msxml6.dll", version:"6.30.7601.22012",  min_version:"6.30.7601.22000",   dir:"\System32", bulletin:bulletin, kb:"2719985");

# Vista / Windows Server 2008
vuln += hotfix_is_vulnerable(os:"6.0", sp:2, file:"Msxml3.dll", version:"8.100.5005.0",                               dir:"\System32", bulletin:bulletin, kb:"2719985");
vuln += hotfix_is_vulnerable(os:"6.0", sp:2, file:"Msxml4.dll", version:"4.30.2114.0", min_version:"4.30.0.0",     dir:"\System32", bulletin:bulletin, kb:"2721691");
vuln += hotfix_is_vulnerable(os:"6.0", sp:2, file:"Msxml6.dll", version:"6.20.5005.0",                                dir:"\System32", bulletin:bulletin, kb:"2719985");

# Windows 2003 and XP x64
vuln += hotfix_is_vulnerable(os:"5.2", sp:2, file:"Msxml3.dll", version:"8.100.1052.0",                               dir:"\System32", bulletin:bulletin, kb:"2719985");
vuln += hotfix_is_vulnerable(os:"5.2", sp:2, file:"Msxml4.dll", version:"4.30.2114.0", min_version:"4.30.0.0",     dir:"\System32", bulletin:bulletin, kb:"2721691");
vuln += hotfix_is_vulnerable(os:"5.2", sp:2, file:"Msxml6.dll", version:"6.20.2012.0",                                dir:"\System32", bulletin:bulletin, kb:"2721693");

# Windows XP
vuln += hotfix_is_vulnerable(os:"5.1", sp:3, file:"Msxml3.dll", version:"8.100.1053.0",                               dir:"\System32", bulletin:bulletin, kb:"2719985");
vuln += hotfix_is_vulnerable(os:"5.1", sp:3, file:"Msxml4.dll", version:"4.30.2114.0", min_version:"4.30.0.0",     dir:"\System32", bulletin:bulletin, kb:"2721691");
vuln += hotfix_is_vulnerable(os:"5.1", sp:3, file:"Msxml6.dll", version:"6.20.2501.0",                                dir:"\System32", bulletin:bulletin, kb:"2719985");

# XML Core Services 5 (this could be one of three KBs - KB2687324, KB2596856, KB2596679)
# Update: KBs KB2687324 and KB2596679 are replaced by KB2687627 and KB2687497 respectively.
if (msxml5_dir)
  vuln += hotfix_is_vulnerable(path:msxml5_dir, file:"Msxml5.dll", version:"5.20.1096.0", min_version:"5.0.0.0", bulletin:bulletin);

if (vuln > 0)
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
