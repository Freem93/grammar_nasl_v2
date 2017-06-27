#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(12091);
 script_version("$Revision: 1.34 $");
 script_cvs_date("$Date: 2016/06/30 19:55:37 $");

 script_cve_id("CVE-2004-0122");
 script_bugtraq_id(9828);
 script_osvdb_id(4169);
 script_xref(name:"MSFT", value:"MS04-010");

 script_name(english:"MS04-010: MSN Messenger Information Disclosure (838512)");
 script_summary(english:"Checks for MS04-010");

 script_set_attribute(attribute:"synopsis", value:"It is possible to read files on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host is running MSN Messenger.

The remote host appears to be vulnerable to a remote attack wherein an
attacker can read any local file that the victim has 'read' access to.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms04-010");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Messenger 6.0 and 6.1.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/03/09");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/03/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/03/09");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:msn_messenger");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_nt_ms05-009.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");

 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}


if ( get_kb_item("SMB/890261") ) exit(0);


include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS04-010';
kbs = make_list("838512");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_NOTE);

if ( hotfix_check_sp(nt:7, win2k:5,xp:2, win2003:1) <= 0 ) exit(0);
if ( hotfix_missing(name:"KB823353") <= 0 ) exit(0);
if ( hotfix_missing(name:"911565") <= 0 ) exit(0);


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


kb       = '838512';

key = "SOFTWARE\Microsoft\MSNMessenger";
item = "InstallationDirectory";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 value = RegQueryValue(handle:key_h, item:item);
 if (!isnull (value))
 {
  key = "SOFTWARE\Classes\Installer\Products\C838BEBA7A1AD5C47B1EB83441062011";
  item = "Version";

  key_h2 = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if ( ! isnull(key_h) )
  {
   value = RegQueryValue(handle:key_h2, item:item);
   if (!isnull (value))
   {
    set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Classes/Installer/Products/C838BEBA7A1AD5C47B1EB83441062011/Version", value:value[1]);
    a = ((value[1]) & 0xFF000000) >> 24;
    b = ((value[1] & 0xFF0000)) >> 16;
    c = value[1] & 0xFFFF;

    if ( ( a == 6 ) &&
	 ( (b == 0) || ( (b == 1) && (c < 211) ) ) )
 {
 set_kb_item(name:"SMB/Missing/MS04-010", value:TRUE);
 hotfix_add_report(bulletin:bulletin, kb:kb);
 hotfix_security_note();
 }
   }

   RegCloseKey(handle:key_h2);
  }
 }

 RegCloseKey (handle:key_h);
}

RegCloseKey (handle:hklm);
NetUseDel();
