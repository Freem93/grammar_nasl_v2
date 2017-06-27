#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if (description)
{
  script_id(10428);
  script_version("$Revision: 1.45 $");
 script_cvs_date("$Date: 2015/01/12 17:12:49 $");

  script_name(english:"Microsoft Windows SMB Registry Not Fully Accessible Detection");
  script_summary(english:"Determines whether the remote registry is fully accessible");

  script_set_attribute(attribute:'synopsis', value:"Nessus had insufficient access to the remote registry.");

  script_set_attribute(attribute:'description', value:
"Nessus did not access the remote registry completely, because full
administrative rights are required.

If you want the permissions / values of all the sensitive registry
keys to be checked, we recommend that you complete the 'SMB Login'
options in the 'Windows credentials' section of the policy with the
administrator login name and password.");

  script_set_attribute(attribute:'solution', value:"Use an administrator level account for scanning.");

  script_set_attribute(attribute:'risk_factor', value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2000/05/29");

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

include("smb_func.inc");
include("misc_func.inc");
include("audit.inc");

access = get_kb_item_or_exit("SMB/registry_access");


#---------------------------------------------------------------------#
# Here is our main()                                                  #
#---------------------------------------------------------------------#

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

login	= kb_smb_login();
pass	= kb_smb_password();
domain  = kb_smb_domain();
port	= kb_smb_transport();

r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) audit(AUDIT_SHARE_FAIL, 'IPC$');

sid = NULL;
handle = LsaOpenPolicy (desired_access:0x20801);
if (!isnull(handle))
{
  ret = LsaQueryInformationPolicy (handle:handle, level:PolicyAccountDomainInformation);
  LsaClose (handle:handle);
  sid = ret[1];
}


hku = RegConnectRegistry(hkey:HKEY_USERS);
if ( isnull(hku) )
{
 NetUseDel();
 audit(AUDIT_REG_FAIL);
}


full = FALSE;

keys = make_list(
  "S-1-5-20\Software\Microsoft\Command Processor",
  "S-1-5-20\Environment",
  "S-1-5-20\Console"
	);


items = make_list(
  "Identity Login",
  "TEMP",
  "WindowSize"
	);


if ( ! isnull(sid) )
{
 keys[max_index(keys)] =  strcat("S-", sid2string(sid:sid), "-500\Console");
 items[max_index(items)] = "WindowSize";
}

# NetworkService test -> enough rights
for (i=0; i<max_index(keys); i++)
{
 key_h = RegOpenKey(handle:hku, key:keys[i], mode:MAXIMUM_ALLOWED);

 if ( ! isnull(key_h) )
 {
  value = RegQueryValue(handle:key_h, item:items[i]);

  if (!isnull (value))
  {
   full = TRUE;
   set_kb_item(name:"SMB/registry_full_access", value:TRUE);
   break;
  }

  RegCloseKey (handle:key_h);
 }
}

RegCloseKey(handle:hku);
NetUseDel();

if (full == FALSE)
  security_note (port);
