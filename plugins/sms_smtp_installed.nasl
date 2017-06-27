#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40870);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/01/12 17:12:49 $");

  script_name(english:"Symantec Mail Security for SMTP Detection");
  script_summary(english:"Looks for SMS for SMTP");

  script_set_attribute(attribute:"synopsis", value:"An email security application is running on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Symantec Mail Security for SMTP. This
application is used to protect mail servers against against spam,
viruses, and other unwanted content.");
  script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/business/mail-security-for-smtp");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:mail_security");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");
include("install_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated"))
  exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");

name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}

key = "SOFTWARE\Symantec\SMSSMTP";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

dir = NULL;
config = NULL;

if (!isnull(key_h))
{
  dir = RegQueryValue(handle:key_h, item:"LoadPoint");
  if (!isnull(dir)) dir = dir[1];
  config = RegQueryValue(handle:key_h, item:"ConfigFile");
  if (!isnull(config)) config = config[1];

  RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);

if (isnull(dir) && isnull(config))
{
  NetUseDel();
  exit(0, "No evidence of Mail Security was found in the registry.");
}
NetUseDel(close:FALSE);

# Try to access each config file in order to make sure it's actually installed
# where the registry thinks it is (and to get the version number)
share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:config);
path = ereg_replace(
  pattern:'^[A-Za-z]:(.*)',
  replace:"\1",
  string:config
);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);

if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to "+share+" share.");
}

fh = CreateFile(
  file:path,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

# Grab the version number if the file was opened successfully.  Otherwise,
# bail out.
if (fh)
{
  # The config of the trial install of SMSSMTP is ~50k.  The version is on
  # the third line.  If there are false negatives, we should probably read
  # in more of the file
  len = 1024;
  data = ReadFile(handle:fh, length:len, offset:0);

  if (strlen(data) == len)
  {
    pattern = '<productVersion>([0-9.]+)</productVersion>';
    match = eregmatch(string:data, pattern:pattern);
    if (match)
    {
      ver = match[1];
      set_kb_item(name:'Symantec/SMSSMTP/Version', value:ver);
      set_kb_item(name:'SMB/Symantec/SMSSMTP/' + ver, value:dir);

      register_install(
        app_name:"Symantec Mail Security for SMTP",
        path:dir,
        version:ver,
        cpe:"cpe:/a:symantec:mail_security");
    }
  }
  else debug_print('Unable to read ' + len + ' bytes from ' + path);

  CloseFile(handle:fh);
}
else debug_print("Unable to access Mail Security file: " + path);

NetUseDel();

if (isnull(ver)) exit(0, "SMS for SMTP wasn't detected");

if (report_verbosity > 0)
{
  report += string(
    "\n",
    "  Install Path : ", dir, "\n",
    "  Version      : ", ver, "\n"
  );
  security_note(port:port, extra:report);
}
else security_note(port);
