#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38689);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/01/26 18:40:46 $");

  script_name(english:"Microsoft Windows SMB Last Logged On User Disclosure");
  script_summary(english:"Checks the last logged on user.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to identify the last logged on user on the remote
host.");
  script_set_attribute(attribute:"description", value:
"By connecting to the remote host with the supplied credentials, Nessus
was able to identify the username associated with the last successful
logon.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/kb/260324");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "KB 'SMB/Registry/Enumerated' not set to TRUE.");

# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) {
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

username = NULL;

key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"DefaultUserName");
  if (!isnull(value)) username = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel();

if(!empty_or_null(username))
{
  report = NULL;
  report = string("\n",
            "Last Successful logon : ", username, "\n");
  set_kb_item(name:'SMB/last_user_login', value:username);
  security_note(port:port,extra:report);
}
