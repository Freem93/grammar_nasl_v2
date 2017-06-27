#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50831);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/12 17:12:49 $");

  script_bugtraq_id(45034);
  script_osvdb_id(69458);
  script_xref(name:"Secunia", value:"42370");

  script_name(english:"Trend Micro OfficeScan TMTDI Module Local Privilege Escalation");
  script_summary(english:"Checks for vulnerable versions of Trend Micro products");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by a local
privilege escalation issue.");
  script_set_attribute(attribute:"description", value:
"The remote host is either running Trend Micro OfficeScan or Trend
Micro OfficeScan Client. The TMTDI module included with the installed
version is affected by an unspecified vulnerability, which could allow
a local attacker to execute arbitrary code on the remote system.");
  script_set_attribute(attribute:"see_also", value:"http://www.trendmicro.com/ftp/documentation/readme/Readme_2820.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.trendmicro.com/ftp/documentation/readme/Readme_1161.txt");
  script_set_attribute(attribute:"solution", value:
"  - v10.0 - Upgrade to Service Pack 1 Patch 2, and apply
    critical patch 2820.

   - v10.5 - Apply critical patch 1161.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trend_micro:officescan");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_ports(139, 445);
  script_require_keys("SMB/Registry/Enumerated");
  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

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
  exit(1, "Can't connect to IPC$ share.");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}

# Figure out the Software version

# 1.First check if its OfficeScan server.

path = NULL;
server_version = NULL;
SP_version = NULL;

key = "SOFTWARE\TrendMicro\OfficeScan\service\Information";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  # TrendMicro OfficeScan Server install...

  value =  RegQueryValue(handle:key_h, item:"Local_Path");
  if (!isnull(value)) path = value[1];

  value =  RegQueryValue(handle:key_h, item:"Server_Version");
  if (!isnull(value)) server_version = value[1];

  RegCloseKey(handle:key_h);
}

# 2. If path is null, then either OfficeScan server is
#    not installed or its a OfficeScan Client install.

if (isnull(path))
{
  key = "SOFTWARE\TrendMicro\PC-cillinNTCorp\CurrentVersion";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

  if (!isnull(key_h))
  {
    value =  RegQueryValue(handle:key_h, item:"Application Path");
    if (!isnull(value)) path = value[1];
  }
}

RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, "Trend Micro OfficeScan is not installed.");
}

NetUseDel(close:FALSE);

# Grab the file version of Tmtdi.sys
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
if ("PCCSRV" >< path)
  sys = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1Pccnt\drv\Tmtdi.sys", string:path);
else
{
  sys = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1Tmtdi.sys", string:path);

  # nb : Reporting client only installs based on
  #      file version of Tmtdi.sys could result in FP's.
  #      Therefore we try to get the server version
  #      from a dll file known to indicate correct server
  #      version in use.
  dll   = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1NTSvcRes.dll", string:path);
}

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to "+share+" share.");
}

fh = CreateFile(
  file:sys,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

ver = NULL;
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}

if (isnull(ver)) exit(1, "Couldn't get file version of '"+(share-'$')+":"+sys+"'.");
version = join(ver, sep:".");

# 3. Check if its a OfficeScan client only install,
# if so then get the server version
# from the NTSvcRes.dll.

ver_dll = NULL;
if ("PCCSRV" >!< path)
{
  fh = CreateFile(
    file:dll,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  if (!isnull(fh))
  {
    ver_dll = GetFileVersion(handle:fh);
    CloseFile(handle:fh);
  }
}

NetUseDel();

# Check the server version number.
if (!isnull(ver_dll))
{
   if(isnull(server_version))
   server_version = ver_dll[0] + "." + ver_dll[1];
}

if((server_version == "10.0" || server_version == "10.5") && ver_compare(ver:version, fix:'5.82.0.1024') == -1) # OfficeScan 10 2820/10.5 1161
{
  if (report_verbosity > 0)
  {
    if ("PCCSRV" >< path) path += "Pccnt\drv";

    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.82.0.1024\n';
      security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else
 exit (0,"Trend Micro OfficeScan version "+ server_version + " has file Tmtdi.sys version "+ version + " installed, and hence not vulnerable.");
