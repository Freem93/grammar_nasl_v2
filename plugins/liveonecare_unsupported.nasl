#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55701);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/09/24 21:17:11 $");

  script_name(english:"Windows Live OneCare Unsupported Application Detection");
  script_summary(english:"Checks for Windows Live OneCare");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an unsupported antivirus application
installed.");
  script_set_attribute(attribute:"description", value:
"Windows Live OneCare, an antivirus application, is installed on the
remote Windows host. Official support for Windows Live OneCare ended
on April 11, 2011. As a result, the application may contain critical
vulnerabilities and will not detect the latest malware.");
  script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/en-us/security_essentials/onecare.aspx");
  script_set_attribute(attribute:"solution", value:
"Remove Windows Live OneCare and install a supported antivirus
application.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:windows_live_onecare");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");
include("smb_func.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');

# Connect to the appropriate share.
name   = kb_smb_name();
port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();





if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:'IPC$');
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

# Connect to the remote registry
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

path = NULL;
key = 'SOFTWARE\\Microsoft\\OneCare Protection';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:'InstallLocation');

  if (!isnull(item))
  {
    path = item[1];
    path = path - '\\Antivirus';
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  audit(AUDIT_NOT_INST, 'Windows Live OneCare');
}

share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:path);
exe = ereg_replace(pattern:'[A-Za-z]:(.*)', replace:'\\1\\WinSSUI.exe', string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

if (isnull(fh))
{
  NetUseDel();
  exit(0, "Failed to open '"+(share-'$')+":"+exe+"'.");
}

ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();
if (isnull(ver))
{
  exit(1, "Couldn't get the version of "+(share-'$')+":"+exe+"'.");
}

version = join(ver, sep:'.');

register_unsupported_product(product_name:'Microsoft Windows Live OneCare',
                             version:version, cpe_base:"microsoft:windows_live_onecare");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
