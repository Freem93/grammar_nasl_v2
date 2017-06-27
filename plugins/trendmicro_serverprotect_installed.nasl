#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58580);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/04/05 00:04:30 $");

  script_name(english:"Trend Micro ServerProtect Detection and Status (credentialed check)");
  script_summary(english:"Checks for ServerProtect version.");

  script_set_attribute(attribute:"synopsis", value:
"An antivirus application is installed on the remote host, but it is
not working properly.");
  script_set_attribute(attribute:"description", value:
"Trend Micro ServerProtect for Windows, a commercial antivirus and
antimalware software package for Windows, is installed on the remote
host. However, there is a problem with the installation; either its
services are not running or its engine and/or virus definitions are
out of date.");
  # https://www.trendmicro.com/us/enterprise/cloud-solutions/server-protection/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?54d5a650");
  script_set_attribute(attribute:"solution", value:
"Make sure that updates are working and the associated services are
running.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trend_micro:serverprotect");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "trendmicro_serverprotect_detect.nasl", "smb_enum_services.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/Services/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("antivirus.inc");

#==============================================================#
# Section 1. Utilities                                         #
#==============================================================#

#-------------------------------------------------------#
# Checks the engine version                             #
#-------------------------------------------------------#
function check_pattern_version(data)
{
  local_var idx_start, idx_end, section, pattern;

  pattern = NULL;
  idx_start = stridx(data, 'P.4=pattern');
  if (idx_start >= 0)
    idx_end = stridx(data, 'P.', idx_start+1);

  if (idx_start >= 0 && idx_end > idx_start)
  {
    section = substr(data, idx_start, idx_end);
    section = chomp(section);

    pattern = ereg_replace(string:section, pattern:'P.4=pattern[^,]+,([\\s]+)?([0-9]+).*', replace:"\2");
  }
  return pattern;
}

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit("SMB/Services/Enumerated");

# Connect to the appropriate share.
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
  audit(AUDIT_SHARE_FAIL, 'IPC$');
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

# Find where it's installed
path = NULL;

key = 'SOFTWARE\\TrendMicro\\ServerProtect\\CurrentVersion';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:'HomeDirectory');
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  audit(AUDIT_NOT_INST, 'TrendMicro ServerProtect');
}
NetUseDel(close:FALSE);

# Grab the file version of file SpntSvc.exe

share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:path);
exe = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\SpntSvc.exe", string:path);

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
  exit(0, 'Couldn\'t open \''+(share-'$')+':'+exe+'\'.');
}

ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);

if (isnull(ver))
{
  NetUseDel();
  audit(AUDIT_VER_FAIL, (share - '$')+':'+exe+'\'.');
}
version = join(ver, sep:'.');

# Get the engine version
engine = NULL;
sys = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\VsapiNT.sys", string:path);
fh = CreateFile(
  file:sys,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (!isnull(fh))
{
  engine = GetFileVersion(handle:fh);
  if (!isnull(engine)) engine = engine[0] + '.' + engine[1] + '.' + engine[3]; # There seems to be an extra 0 in the engine version
  CloseFile(handle:fh);
}

# Try to get various useful information
viruspattern = NULL;
inifile = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\SpntShare\server.ini", string:path);
fh = CreateFile(
  file:inifile,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (isnull(fh))
{
  if ('x64' >< path)
  {
    inipath = path - 'x64';
    inifile = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\SpntShare\server.ini", string:inipath);
    fh = CreateFile(
      file:inifile,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
  }
}

if (!isnull(fh))
{
  fsize = GetFileSize(handle:fh);
  if (fsize > 10240) fsize = 10240;
  if (fsize)
  {
    data = ReadFile(handle:fh, length:fsize, offset:0);
    CloseFile(handle:fh);
    if (!isnull(data))
      viruspattern = check_pattern_version(data:data);
  }
}
NetUseDel();

# Save the info in the KB
kb_base = "Antivirus/TrendMicro ServerProtect/";
set_kb_item(name:kb_base+"installed", value:TRUE);
if (!isnull(engine))
  set_kb_item(name:kb_base+"trendmicro_engine_version", value:engine);
if (!isnull(viruspattern))
  set_kb_item(name:kb_base+"trendmicro_internal_pattern_version", value:viruspattern);
if (!isnull(version))
  set_kb_item(name:kb_base+"trendmicro_program_version", value:version);

# Determine the info reference key
if (version =~ '^5\\.58\\.')
  refkey = 'spnt558';
else if (version =~ '^5\\.80\\.')
  refkey = 'spnt58';
else if (version =~ '^6\\.')
  exit(0, "TrendMicro Server Protect 6.x is not currently supported.");

# Generate the report.
last_engine_version = '';
info = get_av_info("trendmicro");
if (isnull(info)) exit(1, "Failed to get Trend Micro Antivirus info from antivirus.inc.");
if (refkey)
  last_engine_version = info[refkey]["last_engine_version"];

problems = make_list();
if (isnull(engine)) engine = 'n/a';
if (isnull(viruspattern)) viruspattern = 'n/a';
if (isnull(version)) version = 'n/a';

report =
  '\n' + 'Nessus has gathered the following information about the Trend Micro' +
  '\n' + 'ServerProtect install on the remote host : ' +
  '\n' +
  '\n  Product name      : Trend Micro ServerProtect' +
  '\n  Version           : ' + version +
  '\n  Path              : ' + path +
  '\n  Engine version    : ' + engine +
  '\n  Virus def version : ' + viruspattern +
  '\n';

if (engine == 'n/a')
  problems = make_list(problems, 'The engine version could not be determined.');
else
{
  if (last_engine_version)
  {
    if (engine =~ '^[0-9\\.]+$' && last_engine_version =~ '^[0-9\\.]+$')
    {
      if (ver_compare(ver:engine, fix:last_engine_version, strict:FALSE) < 0)
        problems = make_list(problems, "The virus engine is out-of-date - " + last_engine_version + " is current.");
    }
    else
      problems = make_list(problems, "The engine version is not numeric.");
  }
  else
  {
    item  = 'Nessus does not have information currently about Trend Micro' +
            '\n    ServerProtect ' + version + ' - it may no longer be supported.' +
            '\n';
    problems = make_list(problems, item);
  }
}

services = get_kb_item("SMB/svcs");
if (services)
{
  if ("SpntSvc" >!< services)
    problems = make_list(problems, "The Trend Micro ServerProtect service is not running.");
}
else
{
  problems = make_list(problems, "Nessus was unable to retrieve a list of running services from the host.");
}

if (max_index(problems) > 0)
{
  report += '\n';
  if (max_index(problems) == 1) report += 'One problem was uncovered :\n';
  else report += 'Multiple problems were uncovered :\n';

  foreach problem (problems)
    report += '\n  - ' + problem;

  report += '\n\n' + 'As a result, the host might be infected by viruses.' + '\n';
  security_hole(port:port, extra:report);
}
else
{
  set_kb_item(name:kb_base+"description", value:report);
  exit(0, "Detected Trend Micro ServerProtect with no known issues to report.");
}
