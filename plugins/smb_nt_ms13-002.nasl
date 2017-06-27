#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63420);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/01/28 22:37:17 $");

  script_cve_id("CVE-2013-0006", "CVE-2013-0007");
  script_bugtraq_id(57116, 57122);
  script_osvdb_id(88958, 88959);
  script_xref(name:"MSFT", value:"MS13-002");
  script_xref(name:"IAVA", value:"2013-A-0004");

  script_name(english:"MS13-002: Vulnerabilities in Microsoft XML Core Services Could Allow Remote Code Execution (2756145)");
  script_summary(english:"Checks the versions of Msxml3.dll, Msxml4.dll, and Msxml6.dll");
  script_set_attribute(
    attribute:"synopsis",
    value:
"Arbitrary code can be executed on the remote host through Microsoft XML
Core Services."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Microsoft XML Core Services installed on the remote
Windows host is affected by multiple code execution vulnerabilities when
visiting a specially crafted web page using Internet Explorer."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-002");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2, 8, 2012, Office 2003, 2007, Word Viewer, Office
Compatibility Pack, Expression Web Service, Expression Web 2, SharePoint
Server 2007 and Groove Server 2007."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:xml_core_services");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:expression_web");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:groove_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS13-002';
kbs = make_list(
  "2687497",
  "2687499",
  "2757638",
  "2758694",
  "2758696",
  "2760574"
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (!is_accessible_share())  audit(AUDIT_SHARE_FAIL, 'is_accessible_share');

vuln = 0;

arch = get_kb_item_or_exit("SMB/ARCH");
if (arch == "x86")
  commonfiles = hotfix_get_commonfilesdir();
else commonfiles = hotfix_get_commonfilesdirx86();
if (commonfiles)
  msxml5_dir = commonfiles + '\\Microsoft Shared\\Office11';

# XML Core Services 5 (this could be one of three KBs - KB2760574, KB2687497, KB2687499)
if (msxml5_dir)
  vuln += hotfix_is_vulnerable(path:msxml5_dir, file:"Msxml5.dll", version:"5.20.1099.0", min_version:"5.0.0.0", bulletin:bulletin);

# If a vulnerable version of XML Core Services 5 was detected, we should report on that
# regardless of the OS version.
if ((hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'0,1', win8:'0') <= 0))
{
  if (!vuln) audit(AUDIT_OS_SP_NOT_VULN);
}
else
{
  productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
  # Windows 8 / Server 2012
  vuln += hotfix_is_vulnerable(os:"6.2", arch:"x64", sp:0, file:"Msxml3.dll", version:"8.110.9200.16447",                                  dir:"\SysWOW64", bulletin:bulletin, kb:"2757638");
  vuln += hotfix_is_vulnerable(os:"6.2", arch:"x64", sp:0, file:"Msxml3.dll", version:"8.110.9200.20551", min_version:"8.110.9200.20000",  dir:"\SysWOW64", bulletin:bulletin, kb:"2757638");
  vuln += hotfix_is_vulnerable(os:"6.2", arch:"x64", sp:0, file:"Msxml4.dll", version:"4.30.2117.0", min_version:"4.30.0.0",            dir:"\SysWOW64", bulletin:bulletin, kb:"2758694");
  vuln += hotfix_is_vulnerable(os:"6.2", arch:"x64", sp:0, file:"Msxml6.dll", version:"6.30.9200.16447", min_version:"6.30.9200.16000",     dir:"\SysWOW64", bulletin:bulletin, kb:"2757638");
  vuln += hotfix_is_vulnerable(os:"6.2", arch:"x64", sp:0, file:"Msxml6.dll", version:"6.30.9200.20551", min_version:"6.30.9200.20000",     dir:"\SysWOW64", bulletin:bulletin, kb:"2757638");
  vuln += hotfix_is_vulnerable(os:"6.2", arch:"x64", sp:0, file:"Msxml3.dll", version:"8.110.9200.16447",                                  dir:"\System32", bulletin:bulletin, kb:"2757638");
  vuln += hotfix_is_vulnerable(os:"6.2", arch:"x64", sp:0, file:"Msxml3.dll", version:"8.110.9200.20551", min_version:"8.110.9200.20000",  dir:"\System32", bulletin:bulletin, kb:"2757638");
  vuln += hotfix_is_vulnerable(os:"6.2",             sp:0, file:"Msxml4.dll", version:"4.30.2117.0", min_version:"4.30.0.0",            dir:"\System32", bulletin:bulletin, kb:"2758694");
  vuln += hotfix_is_vulnerable(os:"6.2",             sp:0, file:"Msxml6.dll", version:"6.30.9200.16447", min_version:"6.30.9200.16000",     dir:"\System32", bulletin:bulletin, kb:"2757638");
  vuln += hotfix_is_vulnerable(os:"6.2",             sp:0, file:"Msxml6.dll", version:"6.30.9200.20551", min_version:"6.30.9200.20000",     dir:"\System32", bulletin:bulletin, kb:"2757638");

  # Windows 7 / Server 2008 R2
  vuln += hotfix_is_vulnerable(os:"6.1", arch:"x64", sp:0, file:"Msxml3.dll", version:"8.110.7600.17157",                                  dir:"\SysWOW64", bulletin:bulletin, kb:"2757638");
  vuln += hotfix_is_vulnerable(os:"6.1", arch:"x64", sp:0, file:"Msxml3.dll", version:"8.110.7600.21360", min_version:"8.110.7600.21000",  dir:"\SysWOW64", bulletin:bulletin, kb:"2757638");
  vuln += hotfix_is_vulnerable(os:"6.1", arch:"x64", sp:1, file:"Msxml3.dll", version:"8.110.7601.17988", min_version:"8.110.7601.17000",  dir:"\SysWOW64", bulletin:bulletin, kb:"2757638");
  vuln += hotfix_is_vulnerable(os:"6.1", arch:"x64", sp:1, file:"Msxml3.dll", version:"8.110.7601.22149", min_version:"8.110.7601.22000",  dir:"\SysWOW64", bulletin:bulletin, kb:"2757638");
  vuln += hotfix_is_vulnerable(os:"6.1", arch:"x64",       file:"Msxml4.dll", version:"4.30.2117.0", min_version:"4.30.0.0",            dir:"\SysWOW64", bulletin:bulletin, kb:"2758694");
  vuln += hotfix_is_vulnerable(os:"6.1", arch:"x64", sp:0, file:"Msxml6.dll", version:"6.30.7600.17157",                                   dir:"\SysWOW64", bulletin:bulletin, kb:"2757638");
  vuln += hotfix_is_vulnerable(os:"6.1", arch:"x64", sp:0, file:"Msxml6.dll", version:"6.30.7600.21360",  min_version:"6.30.7600.21000",   dir:"\SysWOW64", bulletin:bulletin, kb:"2757638");
  vuln += hotfix_is_vulnerable(os:"6.1", arch:"x64", sp:1, file:"Msxml6.dll", version:"6.30.7601.17988",  min_version:"6.30.7601.17000",   dir:"\SysWOW64", bulletin:bulletin, kb:"2757638");
  vuln += hotfix_is_vulnerable(os:"6.1", arch:"x64", sp:1, file:"Msxml6.dll", version:"6.30.7601.22149",  min_version:"6.30.7601.22000",   dir:"\SysWOW64", bulletin:bulletin, kb:"2757638");
  vuln += hotfix_is_vulnerable(os:"6.1", arch:"x64", sp:0, file:"Msxml3.dll", version:"8.110.7600.17157",                                  dir:"\System32", bulletin:bulletin, kb:"2757638");
  vuln += hotfix_is_vulnerable(os:"6.1", arch:"x64", sp:0, file:"Msxml3.dll", version:"8.110.7600.21360", min_version:"8.110.7600.21000",  dir:"\System32", bulletin:bulletin, kb:"2757638");
  vuln += hotfix_is_vulnerable(os:"6.1", arch:"x64", sp:1, file:"Msxml3.dll", version:"8.110.7601.17988", min_version:"8.110.7601.17000",  dir:"\System32", bulletin:bulletin, kb:"2757638");
  vuln += hotfix_is_vulnerable(os:"6.1", arch:"x64", sp:1, file:"Msxml3.dll", version:"8.110.7601.22149", min_version:"8.110.7601.22000",  dir:"\System32", bulletin:bulletin, kb:"2757638");
  vuln += hotfix_is_vulnerable(os:"6.1",                   file:"Msxml4.dll", version:"4.30.2117.0", min_version:"4.30.0.0",            dir:"\System32", bulletin:bulletin, kb:"2758694");
  vuln += hotfix_is_vulnerable(os:"6.1",             sp:0, file:"Msxml6.dll", version:"6.30.7600.17157",                                   dir:"\System32", bulletin:bulletin, kb:"2757638");
  vuln += hotfix_is_vulnerable(os:"6.1",             sp:0, file:"Msxml6.dll", version:"6.30.7600.21360",  min_version:"6.30.7600.21000",   dir:"\System32", bulletin:bulletin, kb:"2757638");
  vuln += hotfix_is_vulnerable(os:"6.1",             sp:1, file:"Msxml6.dll", version:"6.30.7601.17988",  min_version:"6.30.7601.17000",   dir:"\System32", bulletin:bulletin, kb:"2757638");
  vuln += hotfix_is_vulnerable(os:"6.1",             sp:1, file:"Msxml6.dll", version:"6.30.7601.22149",  min_version:"6.30.7601.22000",   dir:"\System32", bulletin:bulletin, kb:"2757638");

  # Vista / Windows Server 2008
  vuln += hotfix_is_vulnerable(os:"6.0", arch:"x64",  sp:2, file:"Msxml3.dll", version:"8.100.5006.0",                               dir:"\SysWOW64", bulletin:bulletin, kb:"2757638");
  vuln += hotfix_is_vulnerable(os:"6.0", arch:"x64",  sp:2, file:"Msxml4.dll", version:"4.30.2117.0", min_version:"4.30.0.0",     dir:"\SysWOW64", bulletin:bulletin, kb:"2758694");
  vuln += hotfix_is_vulnerable(os:"6.0", arch:"x64",  sp:2, file:"Msxml6.dll", version:"6.20.5006.0",                                dir:"\SysWOW64", bulletin:bulletin, kb:"2757638");
  vuln += hotfix_is_vulnerable(os:"6.0", arch:"x64",  sp:2, file:"Msxml3.dll", version:"8.100.5006.0",                               dir:"\System32", bulletin:bulletin, kb:"2757638");
  vuln += hotfix_is_vulnerable(os:"6.0",              sp:2, file:"Msxml4.dll", version:"4.30.2117.0", min_version:"4.30.0.0",     dir:"\System32", bulletin:bulletin, kb:"2758694");
  vuln += hotfix_is_vulnerable(os:"6.0",              sp:2, file:"Msxml6.dll", version:"6.20.5006.0",                                dir:"\System32", bulletin:bulletin, kb:"2757638");

  # Windows 2003 and XP x64
  vuln += hotfix_is_vulnerable(os:"5.2", arch:"x64", sp:2, file:"Msxml3.dll", version:"8.100.1053.0",                               dir:"\SysWOW64", bulletin:bulletin, kb:"2757638");
  vuln += hotfix_is_vulnerable(os:"5.2", arch:"x64", sp:2, file:"Msxml4.dll", version:"4.30.2117.0", min_version:"4.30.0.0",     dir:"\SysWOW64", bulletin:bulletin, kb:"2758694");
  vuln += hotfix_is_vulnerable(os:"5.2", arch:"x64", sp:2, file:"Msxml6.dll", version:"6.20.2016.0",                                dir:"\SysWOW64", bulletin:bulletin, kb:"2758696");
  vuln += hotfix_is_vulnerable(os:"5.2", arch:"x64", sp:2, file:"Msxml3.dll", version:"8.100.1053.0",                               dir:"\System32", bulletin:bulletin, kb:"2757638");
  vuln += hotfix_is_vulnerable(os:"5.2",             sp:2, file:"Msxml4.dll", version:"4.30.2117.0", min_version:"4.30.0.0",     dir:"\System32", bulletin:bulletin, kb:"2758694");
  vuln += hotfix_is_vulnerable(os:"5.2",             sp:2, file:"Msxml6.dll", version:"6.20.2016.0",                                dir:"\System32", bulletin:bulletin, kb:"2758696");

  # Windows XP
  vuln += hotfix_is_vulnerable(os:"5.1", arch:"x64", sp:3, file:"Msxml4.dll", version:"4.30.2117.0", min_version:"4.30.0.0",     dir:"\SysWOW64", bulletin:bulletin, kb:"2758694");
  vuln += hotfix_is_vulnerable(os:"5.1", arch:"x64", sp:3, file:"Msxml6.dll", version:"6.20.2502.0",                                dir:"\SysWOW64", bulletin:bulletin, kb:"2757638");
  vuln += hotfix_is_vulnerable(os:"5.1",             sp:3, file:"Msxml4.dll", version:"4.30.2117.0", min_version:"4.30.0.0",     dir:"\System32", bulletin:bulletin, kb:"2758694");
  vuln += hotfix_is_vulnerable(os:"5.1",             sp:3, file:"Msxml6.dll", version:"6.20.2502.0",                                dir:"\System32", bulletin:bulletin, kb:"2757638");
}

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
