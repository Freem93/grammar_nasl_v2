#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50346);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/12 17:12:45 $");

  # it's called "Microsoft Update" not "Microsoft Windows Update"
  # Microsoft Update and Microsoft Windows Update are two different things
  script_name(english:"Microsoft Update Installed");
  script_summary(english:"Checks for muweb.dll");

  script_set_attribute(attribute:"synopsis", value:"A software updating service is installed.");
  script_set_attribute(attribute:"description", value:
"Microsoft Update, an expanded version of Windows Update, is installed
on the remote Windows host. This service provides updates for the
operating system and Internet Explorer as well as other Windows
software such as Microsoft Office, Exchange, and SQL Server.");
  script_set_attribute(attribute:"see_also", value:"http://update.microsoft.com/microsoftupdate/v6/default.aspx");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
  script_require_ports(139, 445);

  exit(0);
}


include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");


login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();
port    =  kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

ret = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (ret != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,"IPC$");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

service = NULL;
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"DefaultService");
  if (item) service = item[1];
  RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);
NetUseDel();

if (service == '7971f918-a847-4430-9279-4a52d1efe18d')
  security_note(port);
else if (isnull(service))
  exit(0, 'The registry entry '+key+'\\DefaultService not found');
else
  exit(0, 'Unknown service GUID : '+service);

