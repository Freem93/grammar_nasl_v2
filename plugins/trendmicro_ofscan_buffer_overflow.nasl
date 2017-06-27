#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24683);
  script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2016/06/13 20:14:28 $");
  script_cve_id("CVE-2007-0325");
  script_bugtraq_id(22585);
  script_osvdb_id(33040);

  script_name(english:"Trend Micro OfficeScan OfficeScanSetupINI.dll Remote Buffer Overflow");
  script_summary(english:"Checks if vulnerable version Trend Micro OfficeScan is installed");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a remote buffer overflow
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Trend Micro Antivirus, a commercial anti-
virus software package for Windows.

The remote version of the installed antivirus is vulnerable to a
remote buffer overflow attack.

The issue exists due a vulnerability in the ActiveX control installed
by the OfficeScan server during a web install of the OfficeScan
clients. The clients cache this ActiveX control, which can be
exploited by a malicious website. The attacker can trigger this issue
by enticing a user to click on a malicious link or sending the link in
an email and urging the user to click on it. Successful exploitation
of this issue might result in arbitrary code execution.");
  # http://www.trendmicro.com/ftp/documentation/readme/osce_73_win_en_securitypatch_1241_readme.txt
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?62e87258");
  # http://www.trendmicro.com/ftp/documentation/readme/osce_70_win_en_securitypatch_1344_readme.txt
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14064dc2" );
  # File Download
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2b2f278b" );
  # File Download
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ad4ca3ae" );
 script_set_attribute(attribute:"solution", value:"Apply the security patch released by the vendor.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Trend Micro OfficeScan Client ActiveX Control Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_cwe_id(119);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/02/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/21");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:trend_micro:officescan_corporate_edition");
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl","trendmicro_installed.nasl");
  script_require_keys("Antivirus/TrendMicro/installed","Antivirus/TrendMicro/trendmicro_program_version");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("audit.inc");

if (!get_kb_item("Antivirus/TrendMicro/installed"))
  exit(0);

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
  exit(0);
}

# Connect to remote hkcr registry.
hkcr = RegConnectRegistry(hkey:HKEY_CLASS_ROOT);
if (isnull(hkcr))
{
  NetUseDel();
  exit(0);
}

# Determine if the control is installed.
clid = "08D75BC1-D2B5-11D1-88FC-0080C859833B";
key = "CLSID\{" + clid +  "}\InprocServer32";
key_h = RegOpenKey(handle:hkcr, key:key, mode:MAXIMUM_ALLOWED);
path = NULL;
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hkcr);

if(isnull(path) || "OfficeScanSetup.dll" >!< path )
{
  NetUseDel();
  exit(0);
}

# Connect to remote hklm registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}

exe = NULL;
path = NULL;

# Determine where it's installed.

key = "SOFTWARE\TrendMicro\PC-cillinNTCorp\CurrentVersion";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
 value = RegQueryValue(handle:key_h, item:"Application Path");
 if (!isnull(value))
   path = value[1];

 RegCloseKey(handle:key_h);
}


RegCloseKey(handle:hklm);

if (isnull(path))
{
 NetUseDel();
 exit(0);
}

NetUseDel(close:FALSE);

path1  = path;
share  = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
path   = ereg_replace(pattern:"^[A-Za-z]:(.*)$", replace:"\1", string:path);
exe    = path + "\tmlisten.exe";

# Connect to the appropriate share.

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
 NetUseDel();
 exit(0);
}

fh = CreateFile(file:exe, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);

v = NULL;
trouble = 0;

if (!isnull(fh))
{
  v = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
NetUseDel();

if (
  !isnull(v) &&
  (
    v[0] < 7 ||
    (
      (v[0] == 7 && v[1] == 3 && v[2] == 0 && v[3] < 1241) ||
      (v[0] == 7 && v[1] == 0 && v[2] == 0 && v[3] < 1344)
    )
  )
)
{
 info = string (
		'Version ', v[0], ".", v[1], ".", v[2], ".", v[3],  ' of tmlisten.exe is installed on the remote\n',
		'host under the following path :\n',
		'\n',
		'  ', path1
		);

 report = string(
		"\n",
		info,"\n"
  		);

 security_hole(port:port, extra:report);
}
