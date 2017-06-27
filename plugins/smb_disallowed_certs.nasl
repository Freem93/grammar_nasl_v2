#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(56954);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/12 17:12:47 $");

  script_name(english:"Microsoft Revoked Digital Certificates Enumeration");
  script_summary(english:"Enumerates the Revoked Certificates");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host a list of revoked digital certificates.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a list of digital certificates that
have been revoked by Microsoft.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/library/cc700805.aspx");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('audit.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_hotfixes.inc');
include('smb_func.inc');
include('misc_func.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
winver = get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (winver != '6.0' && winver != '6.1') exit(0, 'The check does not run against this host based on its version.');

# Check the registry
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();
port   = kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:'IPC$');
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,"IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

disallowedcerts = make_list();
key = 'SOFTWARE\\Microsoft\\SystemCertificates\\Disallowed\\Certificates';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (!isnull(subkey))
    {
      disallowedcerts = make_list(disallowedcerts, subkey);
      set_kb_item(name:'SMB/DisallowedCerts', value:subkey);
    }
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel();

if (max_index(disallowedcerts) > 0)
{
  if (report_verbosity > 0)
  {
    if (max_index(disallowedcerts) > 1) s = 's are listed';
    else s = ' is listed';

    report = '\n  The following certificate'+s+' in the disallowed certificate registry :\n';
    for (i=0; i < max_index(disallowedcerts); i++)
    {
      report += '\n' + disallowedcerts[i];
    }
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
exit(0, 'There are no revoked certificates in the disallowed certificate registry.');
