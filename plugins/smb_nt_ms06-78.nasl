#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(23838);
 script_version("$Revision: 1.33 $");
 script_cvs_date("$Date: 2015/04/23 21:04:51 $");

 script_cve_id("CVE-2006-4702", "CVE-2006-6134");
 script_bugtraq_id(21247, 21505);
 script_osvdb_id(30818, 30819);
 script_xref(name:"CERT", value:"208769");
 script_xref(name:"MSFT", value:"MS06-078");

 script_name(english:"MS06-078: Vulnerability in Windows Media Format Could Allow Remote Code Execution (923689/925398)");
 script_summary(english:"Checks the version of Media Format");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the Media
Format Series.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Windows Media Player/Series.

There is a vulnerability in the remote version of this software which
may allow an attacker to execute arbitrary code on the remote host.

To exploit this flaw, one attacker would need to set up a rogue ASF/ASX
file and send it to a victim on the remote host.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms06-078");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and
2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/22");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/12/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/12");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

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

bulletin = 'MS06-078';
kb = '923689';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if ( hotfix_is_vulnerable(os:"5.2", sp:0, file:"Wmvcore.dll", version:"9.0.0.3265", min_version:"9.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.2", arch:"x86", file:"Wmvcore.dll", version:"10.0.0.3708", min_version:"10.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.2", file:"Dxmasf.dll", version:"6.4.9.1133", min_version:"6.4.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.1", file:"Wmvcore.dll", version:"9.0.0.3265", min_version:"9.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.1", file:"Wmvcore.dll", version:"10.0.0.3702", min_version:"10.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.1", file:"Dxmasf.dll", version:"6.4.9.1133", min_version:"6.4.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.0", file:"Wmvcore.dll", version:"7.10.0.3079", min_version:"7.10.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.0", file:"Wmvcore.dll", version:"9.0.0.3265", min_version:"9.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.0", file:"Dxmasf.dll", version:"6.4.9.1133", min_version:"6.4.0.0", dir:"\system32", bulletin:bulletin, kb:kb) )
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
