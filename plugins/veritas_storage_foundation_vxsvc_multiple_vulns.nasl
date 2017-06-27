#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(55983);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/08/16 14:42:21 $");

  script_cve_id("CVE-2011-0547");
  script_bugtraq_id(49014);
  script_osvdb_id(74919, 74920, 97853);
  script_xref(name:"IAVB", value:"2011-B-0108");

  script_name(english:"Symantec Veritas Enterprise Administrator Service (vxsvc) Multiple Integer Overflows (SYM11-010)");
  script_summary(english:"Checks version of vxsvc");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an administrator service that is affected by
multiple integer overflow vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Symantec Veritas Enterprise Administrator Service (vxsvc), a component
of Veritas Storage Foundation, is installed on the remote Windows
host. According to its version number, the installed version of
Symantec Veritas Enterprise Administrator service is affected by
multiple integer overflow vulnerabilities in the following functions :

  - vxveautil.value_binary_unpack

  - vxveautil.value_binary_unpack

  - vxveautil.kv_binary_unpack

A remote, unauthenticated attacker, exploiting these flaws, could
execute arbitrary code on the remote host subject to the privileges of
the user running the affected application.");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ab713d2");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-262/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-263/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-264/");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch from the Symantec advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:veritas:enterprise_administrator");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:veritas_storage_foundation");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "smb_enum_services.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("audit.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");

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

# Make sure Veritas Storage Foundation is installed
# and make sure it is one of the affected versions
vsfver = NULL;
key = 'SOFTWARE\\Veritas\\VPI';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ '^{[A-Za-z0-9\\-]+}')
    {
      key2 = key + '\\' + subkey + '\\Config';
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        item = RegQueryValue(handle:key2_h, item:'VersionName');
        if (!isnull(item)) vsfver = item[1];
        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey(handle:key_h);
}

if (isnull(vsfver))
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0, 'Symantec Veritas Storage Foundation wasn\'t detected on the remote host.');
}

affectedver = 0;
affectedvsfvers = make_list('5.0', '5.0 RP1', '5.0 RP2', '5.1', '5.1 SP1', '5.1 SP2');
for (i=0; i<max_index(affectedvsfvers); i++)
{
  if (vsfver == affectedvsfvers[i])
  {
    affectedver = 1;
    break;
  }
}

if (!affectedver)
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0, 'No affected versions of Symantec Veritas Storage Foundation were detected on the remote host.');
}

# Get the paths to the DLLs from the registry
vxsvcpath = NULL;
vrtsobcpath = NULL;
key = 'SOFTWARE\\Veritas\\VxSvc\\CurrentVersion';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryValue(handle:key_h, item:'InstallDir');
  if (!isnull(info)) vxsvcpath = info[1] + '\\bin';
  RegCloseKey(handle:key_h);
}

key = 'SOFTWARE\\Veritas\\VRTSobc\\pal33';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryValue(handle:key_h, item:'InstallDir');
  if (!isnull(info)) vrtsobcpath = info[1] + '\\pal33\\bin';
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

dlls = make_list();
if (isnull(vxsvcpath) && isnull(vrtsobcpath))
{
  NetUseDel();
  exit(1, 'Couldn\'t determine the path for the affected DLLs.');
}

# Unless we're paranoid, make sure the service is running.
if (report_paranoia < 2)
{
  status = get_kb_item_or_exit('SMB/svc/vxob');
  if (status != SERVICE_ACTIVE)
    exit(0, 'The Veritas Storage Foundation Enterprise Administrator Service is installed but not active.');
}

# Build a list of affected DLLs
if (!isnull(vxsvcpath))
{
  dlls = make_list(
    ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\vxveautil.dll', string:vxsvcpath),
    ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\vxvea3.dll', string:vxsvcpath)
  );
}
if (!isnull(vrtsobcpath))
{
  dlls = make_list(
    dlls,
    ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\vxveautil.dll', string:vrtsobcpath),
    ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\vxpal3.dll', string:vrtsobcpath)
  );
}

vulns = 0;
share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:vxsvcpath);
foreach dll (dlls)
{
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, 'Can\'t connect to '+share+' share.');
  }

  fh = CreateFile(
    file:dll,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (isnull(fh))
  {
    debug_print('Couldn\'t open file '+dll+'.');
    continue;
  }

  ver = GetFileVersion(handle:fh);
  if (isnull(ver))
  {
    debug_print('Couldn\'t get the version of '+dll+'.');
    continue;
  }
  else
  {
    vulndll = '';
    version = join(ver, sep:'.');
    if (ver_compare(ver:version, fix:'3.3.1068.0') == -1)
    {
      vulns++;
      vulndll = ereg_replace(pattern:'^([A-Za-z])\\$', replace:'\\1:\\', string:share);
      vulndll = vulndll + dll;
    }

    report +=
      '\n  Vulnerable dll : ' + vulndll +
      '\n  Version        : ' + version + '\n';
  }
  CloseFile(handle:fh);
}
NetUseDel();

if (vulns)
{
  if (report_verbosity > 0)
  {
    if (vulns > 1) s = 's were found ';
    else s = ' was found ';
    report =
      '\n  The following vulnerable dll' + s + 'on the remote host :' +
      '\n' +
      report;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, 'No vulnerable vxsvc dlls were detected on the remote host.');
