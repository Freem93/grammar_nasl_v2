#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52044);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/03 20:40:06 $");

  script_bugtraq_id(45843);
  script_osvdb_id(72114);

  script_name(english:"Trend Micro Control Manager mrf.exe Stack Overflow");
  script_summary(english:"Checks file version of mrf.exe");

  script_set_attribute(attribute:"synopsis", value:
"An application affected by a stack overflow vulnerability is installed
on the remote host.");
  script_set_attribute(attribute:"description", value:
"The Trend Micro Control Manager installed on the remote Windows host
includes a version of the Message Routing Framework module (mrf.exe)
that fails to perform sufficient boundary checks on attacker-
controlled data before using to construct an error message. An
attacker may be able to leverage this issue to execute arbitrary code
on the remote system.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-301/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2011/Jan/314");
   # http://www.trendmicro.com/ftp/documentation/readme/readme_critical_patch_TMCM50_2017.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c969cad7");
   # http://www.trendmicro.com/ftp/documentation/readme/readme_critical_patch_TMCM55_1318.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b358a190");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Trend Micro Control Manager 5.0 Build 2017 / 5.5 Build 1318
and ensure that the file version of the associated mrf.exe is
1.12.0.1156.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trend_micro:control_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "smb_enum_services.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

if (report_paranoia < 2)
{
  status = get_kb_item_or_exit("SMB/svc/TMCM");
  if (status != SERVICE_ACTIVE)
    exit(0, "The Trend Micro Control Manager service is installed but not active.");
}

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

# Figure out where it is installed.
path = NULL;

key = "SOFTWARE\TrendMicro\TMI";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"HomeDirectory");
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, "Trend Micro Control Manager is not installed.");
}
NetUseDel(close:FALSE);

# Grab the file version of mrf.exe
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe   = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\mrf.exe", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to "+share+" share.");
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

if (isnull(ver)) exit(1, "Couldn't get file version of '"+(share-'$')+":"+exe+"'.");

version = join(ver, sep:".");
fixed_version = "1.12.0.1156";
if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : '+ fixed_version + '\n';
      security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0);
}
else exit(0, "mrf.exe version " + version + " is installed and thus not affected.");
