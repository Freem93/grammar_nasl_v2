#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11867);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2015/01/12 17:12:48 $");
 script_cve_id("CVE-2001-0047");
 script_bugtraq_id(2065);

 script_name(english:"Microsoft Windows SMB Registry : NT MTS Package Administration Registry Key Permission Weakness");
 script_summary(english:"Determines the access rights of a remote key");

 script_set_attribute(attribute:"synopsis", value:"A local user can gain additional privileges.");
 script_set_attribute(attribute:"description", value:
"The registry key HKLM\SOFTWARE\Microsoft\Transaction Server\Packages
can be modified by users not in the admin group.

Write access to this key allows an unprivileged user to gain
additional privileges.");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms00-095");
 script_set_attribute(attribute:"solution", value:
"Use regedt32 and set the permissions of this key to :

- admin group  : Full Control
    - system	   : Full Control
    - everyone	   : Read");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/12/06");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/10/08");

 script_osvdb_id(13480);
script_xref(name:"MSFT", value:"MS00-095");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_access.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}

#

include("audit.inc");
include("smb_func.inc");

access = get_kb_item("SMB/registry_access");
if(!access)exit(0, "Registry not accessible.");

login	= kb_smb_login();
pass	= kb_smb_password();
domain  = kb_smb_domain();
port	= kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 )
{
 NetUseDel();
 audit(AUDIT_SHARE_FAIL, "IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
 NetUseDel();
 audit(AUDIT_REG_FAIL);
}

key = "SOFTWARE\Microsoft\Transaction Server\Packages";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED | ACCESS_SYSTEM_SECURITY);
if(!isnull(key_h))
{
 rep = RegGetKeySecurity (handle:key_h, type: DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION);
 if(!isnull(rep) && registry_key_writeable_by_non_admin(security_descriptor:rep))
 {
   security_warning(port);
 }
 RegCloseKey (handle:key_h);
}

RegCloseKey (handle:hklm);
NetUseDel();
