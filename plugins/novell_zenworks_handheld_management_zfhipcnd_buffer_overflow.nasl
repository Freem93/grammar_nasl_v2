#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50679);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/01/12 17:12:46 $");

  script_cve_id("CVE-2010-4299");
  script_bugtraq_id(44700);
  script_osvdb_id(69157);

  script_name(english:"Novell ZENworks Handheld Management ZfHIPCND.exe Unspecified Buffer Overflow");
  script_summary(english:"Checks the BuildDate");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a server that is affected by a remote heap
overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"A vulnerability exists in the server ZfHIPCND.exe, which handles the
data received on TCP port 2400. An attacker can overflow a buffer on a
heap belonging to the server and possibly execute arbitrary code with
SYSTEM privileges. Authentication is not required to exploit this
vulnerability.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-230/");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1a78ca9d");
  script_set_attribute(attribute:"solution", value:"Apply patch ZHM_635573_29102010 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:TF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "smb_enum_services.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");


function display_dword (dword, nox)
{
 local_var tmp;

 if (isnull(nox) || (nox == FALSE))
   tmp = "0x";
 else
   tmp = "";

 return string (tmp,
               toupper(
                  hexstr(
                    raw_string(
                               (dword >>> 24) & 0xFF,
                               (dword >>> 16) & 0xFF,
                               (dword >>> 8) & 0xFF,
                               dword & 0xFF
                              )
                        )
                      )
               );
}

# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
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


# Check whether it's installed.
path = NULL;

key = "SOFTWARE\Novell\ZENworks\Handheld Management\AccessPoint";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"InstallPath");
  if (!isnull(value))
  {
    path = value[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }

  RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0, "Novell ZENworks Handheld Management is not installed.");
}


# Check the version of the main exe.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\ZfHIPCND.exe", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
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
  exit(0, "Failed to open '"+path+"\ZfHIPCND.exe'.");
}

set_kb_item(name:"SMB/ZENworks/ZfHIPCND/Installed", value:TRUE);
set_kb_item(name:"SMB/ZENworks/ZfHIPCND/Path", value:path);

bd = NULL;

ver = GetFileVersion(handle:fh);
if (isnull(ver)) version = '';
else
{
  version = join(ver, sep:'.');
  set_kb_item(name:"SMB/ZENworks/ZfHIPCND/Version", value:version);
}

ret = GetFileVersionEx(handle:fh);
if (!isnull(ret)) children = ret['Children'];
if (!isnull(children))
{
  varfileinfo = children['VarFileInfo'];
  if (!isnull(varfileinfo))
  {
    translation =
      (get_word(blob:varfileinfo['Translation'], pos:0) << 16) +
      get_word(blob:varfileinfo['Translation'], pos:2);
    translation = tolower(display_dword(dword:translation, nox:TRUE));
  }
  stringfileinfo = children['StringFileInfo'];
  if (!isnull(stringfileinfo) && !isnull(translation))
  {
    data = stringfileinfo[translation];
    if (!isnull(data)) bd = data['BuildDate'];
  }
}
CloseFile(handle:fh);
NetUseDel();

if (isnull(bd)) exit(1, "Failed to get the build date of '"+(share-'$')+":"+exe+"'.");

set_kb_item(name:"SMB/ZENworks/ZfHIPCND/BuildDate", value:bd);


# Check the build date.
pat = "Build ([0-9][0-9])/([0-9][0-9])/([0-9][0-9])";

match = eregmatch(pattern:pat, string:bd);
if (!match) exit(1, "Failed to parse the build date ("+bd+").");

month = int(match[1]);
day = int(match[2]);
year = int(match[3]);

if (version) installed_version = version + ' ' + bd;
else installed_version = bd;

fixed_version = '7.0.2.01029 Build 10/29/10 16:23';
fixed_builddate = strstr(fixed_version, 'Build ');

match = eregmatch(pattern:pat, string:fixed_builddate);
if (!match) exit(1, "Failed to parse the build date ("+fixed_builddate+").");
fixed_month = int(match[1]);
fixed_day = int(match[2]);
fixed_year = int(match[3]);

if (
  year < fixed_year ||
  (
    year == fixed_year &&
    (
      month < fixed_month ||
      (month == fixed_month && day < fixed_day)
    )
  )
)
{
  if (report_paranoia < 2)
  {
    status = get_kb_item_or_exit("SMB/svc/ZENworks for Handhelds IP Conduit");
    if (status != SERVICE_ACTIVE)
      exit(0, "The host is not affected since the Access Point service is not active even though its version is "+installed_version+".");
  }

  if (report_verbosity > 0)
  {
    report =
      '\n  File              : ' + path + "\ZfHIPCND.exe" +
      '\n  Installed version : ' + installed_version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The host is not affected since the version of the Access Point process is "+installed_version+".");
