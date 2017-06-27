#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11309);
 script_version("$Revision: 1.38 $");
 script_cvs_date("$Date: 2017/05/26 15:15:34 $");

 script_cve_id("CVE-2002-0049");
 script_bugtraq_id(4053);
 script_osvdb_id(2042);
 script_xref(name:"CERT", value:"978131");
 script_xref(name:"MSFT", value:"MS02-003");
 script_xref(name:"MSKB", value:"316056");

 script_name(english:"MS02-003: WinReg Remote Registry Key Manipulation (316056)");
 script_summary(english:"Determines the permissions for the winreg key");

 script_set_attribute(attribute:"synopsis", value:"Local users can elevate their privileges.");
 script_set_attribute(attribute:"description", value:
"The key HKLM\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg
is writeable by non-administrators.

The installation software of Microsoft Exchange sets this key to a
world-writeable mode.

Local users could use this misconfiguration to escalate their
privileges on this host.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms02-003");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for the Windows NT, 2000 and
XP.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/02/07");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/02/07");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/02");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_full_access.nasl",
 		     "smb_reg_service_pack.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS02-003';
kb = '316056';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

access = get_kb_item("SMB/registry_full_access");
if(!access)exit(0, "Registry not fully accessible.");

login	= kb_smb_login();
pass	= kb_smb_password();
domain  = kb_smb_domain();
port	= kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 )
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,"IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

key = "SYSTEM\CurrentControlSet\Control\SecurePipeServers\WinReg";


key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED | ACCESS_SYSTEM_SECURITY);
if(!isnull(key_h))
{
 rep = RegGetKeySecurity (handle:key_h, type: DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION);
 if(!isnull(rep) && registry_key_writeable_by_non_admin(security_descriptor:rep))
 {
 {
 set_kb_item(name:"SMB/Missing/MS02-003", value:TRUE);
 hotfix_add_report(bulletin:bulletin, kb:kb);
 hotfix_security_hole();
 }
 }
 RegCloseKey (handle:key_h);
}

RegCloseKey (handle:hklm);
NetUseDel();


