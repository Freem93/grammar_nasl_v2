#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10400);
 script_version("$Revision: 1.49 $");
 script_cvs_date("$Date: 2015/01/12 17:12:49 $");

 script_name(english:"Microsoft Windows SMB Registry Remotely Accessible");
 script_summary(english:"Determines whether the remote registry is accessible");

 script_set_attribute(attribute:"synopsis", value:"Access the remote Windows Registry.");
 script_set_attribute(attribute:"description", value:
"It was possible to access the remote Windows Registry using the login
/ password combination used for the Windows local checks (SMB tests).");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2000/05/09");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "start_registry_svc.nasl");
 if ( NASL_LEVEL >= 4000 )script_dependencies("wmi_enable_shares.nbin");
 script_exclude_keys("SMB/not_windows");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
 script_require_ports(139, 445);
 exit(0);
}


include("audit.inc");
include("smb_func.inc");

if (get_kb_item("SMB/not_windows")) audit(AUDIT_OS_NOT, "Windows");

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

port  = kb_smb_transport();
login	= kb_smb_login();
pass	= kb_smb_password();
domain  = kb_smb_domain();

logged = 0;

r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r == 1 )
{
 hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
 if (! isnull(hklm) )
 {
  key_h = RegOpenKey(handle:hklm, key:"SYSTEM\CurrentControlSet\Control\Session Manager\Environment", mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
   item = RegQueryValue(handle:key_h, item:"PROCESSOR_ARCHITECTURE");
   if (!isnull(item))
   {
    arch = item[1];
    if ("x86" >!< arch)
      set_kb_item(name:"SMB/WoW", value:TRUE);
   }

   RegCloseKey(handle:key_h);
  }

  RegCloseKey (handle:hklm);
  logged = 1;
 }
 else reason = "Could not connect to \winreg";
 NetUseDel();
}
else reason = "Could not connect to IPC$";

if (logged == 0)
{
 set_kb_item(name:"SMB/registry_not_accessible", value:TRUE);
 if ( !isnull(reason) ) set_kb_item(name:"SMB/registry_not_accessible/reason", value:reason);
}
else
{
 security_note (port);

 set_kb_item(name:"SMB/registry_access", value:TRUE);
}
