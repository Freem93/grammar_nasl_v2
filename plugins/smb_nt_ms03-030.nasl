#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11803);
 script_version("$Revision: 1.49 $");
 script_cvs_date("$Date: 2017/05/25 13:29:27 $");

 script_cve_id("CVE-2003-0346");
 script_bugtraq_id(8262);
 script_osvdb_id(13389);
 script_xref(name:"MSFT", value:"MS03-030");
 script_xref(name:"CERT", value:"265232");
 script_xref(name:"CERT", value:"561284");
 script_xref(name:"MSKB", value:"819696");

 script_name(english:"MS03-030: DirectX MIDI Overflow (819696)");
 script_summary(english:"Checks hotfix 819696");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code can be executed on the remote host through DirectX.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows with a version of
DirectX that is vulnerable to a buffer overflow attack involving the
module that handles MIDI files.

To exploit this flaw, an attacker needs to craft a rogue MIDI file and
send it to a user of this computer.  When the user attempts to read the
file, it will trigger the buffer overflow condition and the attacker may
gain a shell on this host.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms03-030");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for DirectX.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/07/23");
 script_set_attribute(attribute:"patch_publication_date", value:"2003/07/23");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/07/23");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:directx");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");
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

bulletin = 'MS03-030';
kb = "819696";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(nt:'6', win2k:'2,3', xp:'0,1', win2003:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (!get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/DirectX/Version")) audit(AUDIT_NOT_INST, "DirectX");

if (
  hotfix_is_vulnerable(os:"5.2", sp:0, file:"Quartz.dll", version:"6.4.3790.9",    min_version:"6.4.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:0, file:"Quartz.dll", version:"6.5.1.902",     min_version:"6.5.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:1, file:"Quartz.dll", version:"6.4.2600.1221", min_version:"6.4.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:0, file:"Quartz.dll", version:"6.4.2600.113",  min_version:"6.4.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1",       file:"Quartz.dll", version:"6.5.1.902",     min_version:"6.5.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", sp:3, file:"Quartz.dll", version:"6.1.9.729",     min_version:"6.1.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0",       file:"Quartz.dll", version:"6.5.1.902",     min_version:"6.5.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0",       file:"Quartz.dll", version:"6.3.1.886",     min_version:"6.3.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"4.0",       file:"Quartz.dll", version:"6.1.5.132",     min_version:"6.1.0.0", dir:"\system32", bulletin:bulletin, kb:kb)
)
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
