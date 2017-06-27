#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(53381);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id("CVE-2010-3974", "CVE-2010-4701");
  script_bugtraq_id(45942, 45583);
  script_osvdb_id(70126, 71775);
  script_xref(name:"EDB-ID", value:"15839");
  script_xref(name:"IAVB", value:"2011-B-0045");
  script_xref(name:"MSFT", value:"MS11-024");

  script_name(english:"MS11-024: Vulnerability in Windows Fax Cover Page Editor Could Allow Remote Code Execution (2527308)");
  script_summary(english:"Checks version of fax cover page editor");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A fax cover page editor on the remote host has a memory corruption
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Windows Fax Cover Page Editor on the remote host has a
heap-based buffer overflow vulnerability.  A remote attacker could
exploit this by tricking a user into opening a specially crafted fax
cover page file, resulting in arbitrary code execution."
  );
  script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/9sg_cov_bof.html");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-024");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS11-024';
kbs = make_list("2491683", "2506212");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 7 and Windows Server 2008 R2
  (hotfix_check_server_core() != 1 &&
   (hotfix_is_vulnerable(os:"6.1", sp:1, file:"Fxscover.exe", version:"6.1.7601.21659", min_version:"6.1.7601.21000", dir:"\system32", bulletin:bulletin, kb:"2491683") ||
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"Fxscover.exe", version:"6.1.7601.17559", min_version:"6.1.7600.17000", dir:"\system32", bulletin:bulletin, kb:"2491683") ||
    hotfix_is_vulnerable(os:"6.1", sp:0, file:"Fxscover.exe", version:"6.1.7600.20900", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:"2491683") ||
    hotfix_is_vulnerable(os:"6.1", sp:0, file:"Fxscover.exe", version:"6.1.7600.16759", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:"2491683"))
  ) ||
  hotfix_is_vulnerable(os:"6.1", file:"Mfc42.dll", version:"6.6.8064.0", dir:"\system32", bulletin:bulletin, kb:"2506212") ||

  # Vista / Windows 2008
  (hotfix_check_server_core() != 1 &&
   (hotfix_is_vulnerable(os:"6.0", sp:2, file:"Fxscover.exe", version:"6.0.6002.22586", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:"2491683") ||
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"Fxscover.exe", version:"6.0.6002.18403", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"2491683") ||
    hotfix_is_vulnerable(os:"6.0", sp:1, file:"Fxscover.exe", version:"6.0.6001.22852", min_version:"6.0.6001.22000", dir:"\system32", bulletin:bulletin, kb:"2491683") ||
    hotfix_is_vulnerable(os:"6.0", sp:1, file:"Fxscover.exe", version:"6.0.6001.18597", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:"2491683"))
  ) ||
  hotfix_is_vulnerable(os:"6.0", file:"Mfc42.dll", version:"6.6.8064.0", dir:"\system32", bulletin:bulletin, kb:"2506212") ||

  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Fxscover.exe", version:"5.2.3790.4829", dir:"\system32", bulletin:bulletin, kb:"2491683") ||
  hotfix_is_vulnerable(os:"5.2", arch:"x64", sp:2, file:"Mfc42.dll", version:"6.5.9151.0", dir:"\system32", bulletin:bulletin, kb:"2506212") ||
  hotfix_is_vulnerable(os:"5.2", arch:"x86", sp:2, file:"Mfc42.dll", version:"6.6.8064.0", dir:"\system32", bulletin:bulletin, kb:"2506212") ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Fxscover.exe", version:"5.2.2600.6078", dir:"\system32", bulletin:bulletin, kb:"2491683") ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Mfc42.dll", version:"6.2.8081.0", dir:"\system32", bulletin:bulletin, kb:"2506212")
)
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
