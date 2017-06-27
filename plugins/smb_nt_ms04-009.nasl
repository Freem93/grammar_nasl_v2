#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(12092);
 script_version("$Revision: 1.34 $");
 script_cvs_date("$Date: 2016/06/30 19:55:37 $");

 script_cve_id("CVE-2004-0121");
 script_bugtraq_id(9827);
 script_osvdb_id(4168);
 script_xref(name:"CERT", value:"305206");
 script_xref(name:"MSFT", value:"MS04-009");

 script_name(english:"MS04-009: Vulnerability in Outlook could allow code execution (828040)");
 script_summary(english:"Determines the version of OutLook.exe");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the email
client.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of outlook that could allow
Internet Explorer to execute script code in the Local Machine zone and
therefore let an attacker execute arbitrary programs on this host.

To exploit this bug, an attacker would need to send an special HTML
message to a user of this host.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms04-009");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office 2002 and XP.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/03/09");
 script_set_attribute(attribute:"patch_publication_date", value:"2004/03/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/03/10");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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

bulletin = 'MS04-009';
kb       = '828040';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

CommonFilesDir = hotfix_get_commonfilesdir();
if ( ! CommonFilesDir ) exit(1, "Failed to get the Common Files directory.");

login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();

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

key_h = RegOpenKey(handle:hklm, key:"SOFTWARE\Microsoft\Office\10.0\Outlook\InstallRoot", mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(1);
}

value = RegQueryValue(handle:key_h, item:"Path");
RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

if ( isnull(value) )
{
 NetUseDel();
 exit(1);
}


share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:value[1]);
outlook =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\outlook.exe", string:value[1]);

r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 )
{
   NetUseDel();
   audit(AUDIT_SHARE_FAIL,share);
}

handle =  CreateFile (file:outlook, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

if ( ! isnull(handle) )
{
 v = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( ! isnull(v) )
 {
  if ( v[0] == 10 && v[1] == 0 && v[2] < 5709 ) {
 set_kb_item(name:"SMB/Missing/MS04-009", value:TRUE);
 report = '\nInstalled version : '+join(v, sep:'.')+'\nFixed version : 10.0.5709.0\n';
 hotfix_add_report(report, bulletin:bulletin, kb:kb);
 hotfix_security_hole();
 }
 }
}

NetUseDel();
