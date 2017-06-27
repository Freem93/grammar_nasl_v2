#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(56282);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/10/07 13:30:47 $");

  script_bugtraq_id(48898);
  script_osvdb_id(74157, 74158);
  script_xref(name:"EDB-ID", value:"17582");
  script_xref(name:"IAVB", value:"2011-B-0087");
  script_xref(name:"EDB-ID", value:"17583");

  script_name(english:"Citrix XenApp/XenDesktop Multiple Code Execution Vulnerabilities (credentialed check)");
  script_summary(english:"Checks version of ctxxmlss.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is running an XML service that is affected by
multiple code execution vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The remote Windows host has the Citrix XML Service, a component of
Citrix XenApp and XenDesktop, installed. According to its version
number, the Citrix XML service installed on the remote host is
affected by multiple code execution vulnerabilities when handling
specially crafted HTTP POST requests.");

  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/Jul/224");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/Jul/225");
  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX129430");
  script_set_attribute(attribute:"solution", value:"Apply the relevant vendor-supplied patch.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:presentation_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:desktop_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('smb_func.inc');
include("audit.inc");

if (report_paranoia < 2)
{
  status = get_kb_item_or_exit('SMB/svc/CtxHttp');
  if (status != SERVICE_ACTIVE)  exit(0, 'The Citrix XML Service is installed but not active.');
}

name   = kb_smb_name();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();
port   = kb_smb_transport();





if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:'IPC$');
if (rc != 1)
{
  NetUseDel();
  exit(1, 'Can\'t connect to IPC$ share.');
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, 'Can\'t connect to the remote registry.');
}

# Check if its XenDesktop
xendesktop = FALSE;
key = 'SOFTWARE\\Citrix\\DesktopServer';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  xendesktop = TRUE;
  RegCloseKey(handle:key_h);
}

# Make sure Citrix XML service is installed
# and make sure it is one of the affected versions
ctxver = NULL;
ctxpath = NULL;
key = 'SOFTWARE\\Citrix\\Install';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:'Location');
  if (!isnull(item))
  {
    ctxpath = item[1] + '\\system32';
    RegCloseKey(handle:key_h);
  }
}

if (isnull(ctxpath))
{
  key = 'SOFTWARE\\Wow6432Node\\Citrix\\Install';
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:'Location');
    if (!isnull(item))
    {
      ctxpath = item[1] + '\\system32';
      RegCloseKey(handle:key_h);
    }
  }
}
RegCloseKey(handle:hklm);
if (isnull(ctxpath))
{
  NetUseDel();
  exit(0, 'Citrix XenDesktop or XenApp wasn\'t detected on the remote host.');
}

share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:ctxpath);
exe = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\ctxxmlss.exe', string:ctxpath);

NetUseDel(close:FALSE);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, 'Can\'t connect to '+share+' share.');
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
  exit(1, 'Couldn\'t open file \''+ctxpath+'\\ctxxmlss.exe\'.');
}

ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();

if (isnull(ver)) exit(1, 'Couldn\'t get the version number from \''+ctxpath+'\\ctxxmlss.exe.\'.');

if (
  (!xendesktop &&
    (
#      (ver[0] == 6 && ver[1] == 0 && ver[2] < 63) ||
      (ver[0] == 6 && ver[1] == 0 && ver[2] == 63 && ver[3] < 6410) ||
      (ver[0] == 5 && ver[1] == 0 && ver[2] < 6426) ||
      (ver[0] == 5 && ver[1] == 0 && ver[2] == 6426 && ver[3] < 5357) ||
      (ver[0] == 4 && ver[1] < 5) ||
      (ver[0] == 4 && ver[1] == 5 && ver[2] < 4466) ||
      (ver[0] == 4 && ver[1] == 5 && ver[2] == 4466 && ver[3] == 0) ||
      ver[0] < 4
    )
  ) ||
  (xendesktop &&
    (ver[0] == 4 && ver[1] == 5 && ver[2] < 4220) ||
    (ver[0] == 4 && ver[1] == 5 && ver[2] == 4220 && ver[3] == 0)
  )
)
{
  if (ver[0] == 6) fix = '6.0.63.6410';
  else if (ver[0] == 5) fix = '5.0.6426.5357';
  else
  {
    if (!xendesktop) fix = '4.5.4466.1 / 4.5.4600.1';
    else fix = '4.5.4220.1';
  }
  version = join(ver, sep:'.');
  if (report_verbosity > 0)
  {
    report =
      '\n  Component         : Citrix XML Service' +
      '\n  File              : ' + ctxpath + '\\ctxxmlss.exe' +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, 'No vulnerable versions of the Citrix XML service were found on the remote host.');
