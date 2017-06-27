#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(34097);
 script_version("$Revision: 1.8 $");
 script_cvs_date("$Date: 2015/01/12 17:12:43 $");
 script_name(english:"BIOS Version Information (via SMB)");
 script_summary(english:"Determines the access rights of a remote key, Reads HKLM\Hardware\Descript\System\SystemBiosVersion");

 script_set_attribute(attribute:"synopsis", value:"The BIOS version could be read.");
 script_set_attribute(attribute:"description", value:
"By reading HKLM\Hardware\Descript\System\SystemBiosVersion, it was
possible to get the BIOS vendor and version.");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"solution", value:"n/a");

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/08");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
 script_family(english:"General");
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl", "smb_registry_access.nasl");
 if ( NASL_LEVEL >= 3000 ) script_dependencies("bios_get_info_wmi.nbin");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
 script_exclude_keys("BIOS/Vendor", "BIOS/Version", "BIOS/ReleaseDate");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("audit.inc");
if (get_kb_item("BIOS/Vendor") && get_kb_item("BIOS/Version") && get_kb_item("BIOS/ReleaseDate")) exit(0);
#
access = get_kb_item("SMB/registry_access");
if(!access)exit(0);
#
# port = get_kb_item("SMB/transport");
# if(!port)port = 139;

login	= kb_smb_login();
pass	= kb_smb_password();
domain  = kb_smb_domain();
port	= kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(0);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
 NetUseDel();
 exit(0);
}

key = "Hardware\Description\System";
item = "SystemBiosVersion";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if(!isnull(key_h))
{
 rep = '\n';
 foreach item (make_list("SystemBiosVersion", "SystemBiosDate"))
 {
  value = RegQueryValue(handle:key_h, item: item);
  if (!isnull (value))
  {
    rep = strcat(rep, item, crap(data: ' ', length: 18 - strlen(item)),
    	  	 ': ', value[1], '\n');
    set_kb_item(name: strcat("BIOS/", item), value: value[1]);
  }
 }
 if (strlen(rep) > 1) security_note(port: port, extra: rep);
 RegCloseKey (handle:key_h);
}

RegCloseKey (handle:hklm);
NetUseDel();
