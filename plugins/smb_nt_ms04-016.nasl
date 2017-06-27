#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(12267);
 script_version("$Revision: 1.35 $");
 script_cvs_date("$Date: 2015/04/23 21:04:49 $");

 script_cve_id("CVE-2004-0202");
 script_bugtraq_id(10487);
 script_osvdb_id(6742);
 script_xref(name:"MSFT", value:"MS04-016");

 script_name(english:"MS04-016: Vulnerability in DirectPlay Could Allow Denial of Service (839643)");
 script_summary(english:"Checks for ms04-016 over the registry");

 script_set_attribute(attribute:"synopsis", value:"It is possible to crash the remote DirectPlay service.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of DirectPlay that is vulnerable to
a denial of service attack.  DirectPlay is a component of DirectX and is
frequently used by game developpers to create networked multi-player
games.

An attacker could exploit this flaw by sending a malformed IDirectPlay
packet to a remote application using this service and cause it to
crash.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms04-016");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/06/08");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/06/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/06/10");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
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

bulletin = 'MS04-016';
kb = '839643';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'2,4', xp:'0,1', win2003:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (!get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/DirectX/Version")) audit(AUDIT_NOT_INST, "DirectX");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.2", sp:0, file:"Dplayx.dll", version:"5.2.3790.163", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:1, file:"Dplayx.dll", version:"5.1.2600.1517", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:0, file:"Dplayx.dll", version:"5.1.2600.148", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", file:"Dplayx.dll", version:"5.0.2195.6922", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", file:"Dplayx.dll", version:"5.1.2258.410", min_version:"5.1.0.0", dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
