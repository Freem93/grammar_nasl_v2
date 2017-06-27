#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(10432);
 script_version("$Revision: 1.35 $");
 script_cvs_date("$Date: 2015/12/15 17:46:20 $");
 script_cve_id("CVE-1999-0589");
 script_osvdb_id(334);

 script_name(english:"Microsoft Windows SMB Registry : Key Permissions Path Subversion Local Privilege Escalation");
 script_summary(english:"Determines the access rights of remote keys");

 script_set_attribute(attribute:"synopsis", value:"Local users can gain SYSTEM privileges.");
 script_set_attribute(attribute:"description", value:
"Some SYSTEM registry keys can be written by non administrator.

These keys contain paths to common programs and DLLs. If a user can
change a path, then he may put a trojan program into another location
(say C:/temp) and point to it.");
 script_set_attribute(attribute:"solution", value:
"Use regedt32 and set the permissions of this key to :

- admin group  : Full Control
    - system	   : Full Control
    - everyone	   : Read");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value:"2000/05/30");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2015 Tenable Network Security, Inc.");
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

keys[0] = "Software\Microsoft\Windows\CurrentVersion\App Paths";
keys[1] = "Software\Microsoft\Windows\CurrentVersion\Controls Folder";
keys[2] = "Software\Microsoft\Windows\CurrentVersion\DeleteFiles";
keys[3] = "Software\Microsoft\Windows\CurrentVersion\Explorer";
keys[4] = "Software\Microsoft\Windows\CurrentVersion\Extensions";
keys[5] = "Software\Microsoft\Windows\CurrentVersion\ExtShellViews";
keys[6] = "Software\Microsoft\Windows\CurrentVersion\Internet Settings";
keys[7] = "Software\Microsoft\Windows\CurrentVersion\ModuleUsage";
keys[8] = "Software\Microsoft\Windows\CurrentVersion\RenameFiles";
keys[9] = "Software\Microsoft\Windows\CurrentVersion\Setup";
keys[10] = "Software\Microsoft\Windows\CurrentVersion\SharedDLLs";
keys[11] = "Software\Microsoft\Windows\CurrentVersion\Shell Extensions";
keys[12] = "Software\Microsoft\Windows\CurrentVersion\Uninstall";
keys[13] = "Software\Microsoft\Windows NT\CurrentVersion\Compatibility";
keys[14] = "Software\Microsoft\Windows NT\CurrentVersion\Drivers";
keys[15] = "Software\Microsoft\Windows NT\CurrentVersion\drivers.desc";
keys[16] = "Software\Microsoft\Windows NT\CurrentVersion\Drivers32\0";
keys[17] = "Software\Microsoft\Windows NT\CurrentVersion\Embedding";
keys[18] = "Software\Microsoft\Windows NT\CurrentVersion\MCI";
keys[19] = "Software\Microsoft\Windows NT\CurrentVersion\MCI Extensions";
keys[20] = "Software\Microsoft\Windows NT\CurrentVersion\Ports";
keys[21] = "Software\Microsoft\Windows NT\CurrentVersion\ProfileList";
keys[22] = "Software\Microsoft\Windows NT\CurrentVersion\WOW";

vuln = 0;
vuln_keys = "";

for(my_counter=0;keys[my_counter];my_counter=my_counter+1)
{
 key_h = RegOpenKey(handle:hklm, key:keys[my_counter], mode:MAXIMUM_ALLOWED | ACCESS_SYSTEM_SECURITY);

 if(!isnull(key_h))
 {
  rep = RegGetKeySecurity (handle:key_h, type: DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION);
  if(!isnull(rep) && registry_key_writeable_by_non_admin(security_descriptor:rep))
  {
   vuln_keys += '\nHKLM\\' + keys[my_counter];
   vuln = vuln + 1;
  }
  RegCloseKey (handle:key_h);
 }
}

RegCloseKey (handle:hklm);
NetUseDel();


if(vuln)
{
 report =
"The following registry keys are writeable by users who are not in
the admin group : "
+
 vuln_keys;

 security_hole(port:port, extra:report);
}

