#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(34121);
 script_version("$Revision: 1.24 $");
 script_cvs_date("$Date: 2015/04/23 21:11:57 $");

 script_cve_id("CVE-2008-3008");
 script_bugtraq_id(31065);
 script_osvdb_id(47962);
 script_xref(name:"CERT", value:"996227");
 script_xref(name:"MSFT", value:"MS08-053");
 script_xref(name:"IAVB", value:"2008-B-0057");

 script_name(english:"MS08-053: Vulnerability in Windows Media Encoder 9 Could Allow Remote Code Execution (954156)");
 script_summary(english:"Checks the version of Media Player");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Media
Player.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Windows Media Player 9.

There is a vulnerability in the remote version of this software that
could allow an attacker to execute arbitrary code on the remote host.

To exploit this flaw, the attacker would need to set up a rogue web
page and entice a victim to visit it.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms08-053");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista and 2008.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Windows Media Encoder 9 wmex.dll ActiveX Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_cwe_id(119);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/09/09");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/09/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/10");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"stig_severity", value:"II");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

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

bulletin = 'MS08-053';
kb = '954156';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'1,2', vista:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);


login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) audit(AUDIT_SHARE_FAIL, "IPC$");

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
 NetUseDel();
 audit(AUDIT_REG_FAIL);
}


path = NULL;

key = "Software\Microsoft\Windows Media\Encoder";
item = "InstallDir";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:item);
 if (!isnull (value)) path = value[1];

 RegCloseKey (handle:key_h);
}
RegCloseKey (handle:hklm);
NetUseDel();


if (path)
{
  share = hotfix_path2share(path:path);
  if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

  if (
    hotfix_is_vulnerable(os:"6.0", arch:"x86", file:"Wmex.dll", version:"9.0.0.3359", min_version:"9.0.0.0", path:path, bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"6.0", arch:"x64", file:"Wmex.dll", version:"10.0.0.3817", min_version:"10.0.0.0", path:path, bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"5.2", arch:"x86", file:"Wmex.dll", version:"9.0.0.3359", min_version:"9.0.0.0", path:path, bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"5.2", arch:"x64", file:"Wmex.dll", version:"10.0.0.3817", min_version:"10.0.0.0", path:path, bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"5.1", arch:"x86", file:"Wmex.dll", version:"9.0.0.3359", min_version:"9.0.0.0", path:path, bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(os:"5.0", arch:"x86", file:"Wmex.dll", version:"9.0.0.3359", min_version:"9.0.0.0", path:path, bulletin:bulletin, kb:kb)
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
}
else audit(AUDIT_HOST_NOT, 'affected');
