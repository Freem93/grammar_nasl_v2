#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47039);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/01/12 17:12:46 $");

  script_cve_id("CVE-2009-0849");
  script_bugtraq_id(33954, 39693);
  script_osvdb_id(52301, 52302, 65486, 65487, 65488);
  script_xref(name:"Secunia", value:"34024");

  script_name(english:"NovaStor NovaNET < 13 Multiple Vulnerabilities");
  script_summary(english:"Checks version of nnwinsdr.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a program that is affected by several
remote vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The installed version of NovaStor NovaNET is affected by several
remote vulnerabilities, including code execution and information
disclosure. The issues have been reportedly silently fixed in version
13.");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e72d328b");

  script_set_attribute(attribute:"solution", value:"Upgrade to version 13 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");

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

# Find where it's installed.
ver = NULL;
path = NULL;

key = "SOFTWARE\NovaStor Corporation\NovaNet";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"RootPath");
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, "NovaStor NovaNet is not installed.");
}

# Grab the file version of file nnwinsdr.exe.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\nnwinsdr.exe", string:path);

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
  exit(1, "Can't open the file "+exe+".");
}

ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();

# Check the version number.
if (!isnull(ver))
{
  version = join(sep:".", ver);
  fixed_version = "13.0";

  fix = split(fixed_version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if (ver[i] < fix[i])
    {
      if (report_verbosity > 0)
      {
        report =
          '\n  Path              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : ' + fixed_version + '\n';
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      exit(0);
    }
    else if (ver[i] > fix[i])
      break;

 exit(0, "nnwinsdr.exe version "+version+" is installed at "+path+" but not vulnerable.");
}
else exit(1, "Can't get file version of 'nnwinsdr.exe' in "+path+".");
