#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(46733);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/19 18:02:20 $");

  script_cve_id("CVE-2010-1688");
  script_bugtraq_id(40311);
  script_osvdb_id(64752);
  script_xref(name:"EDB-ID", value:"12662");
  script_xref(name:"Secunia", value:"39865");

  script_name(english:"SyncBack Profile File Remote Buffer Overflow");
  script_summary(english:"Checks version of SyncBack.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a program that is prone to a remote
buffer overflow attack.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of SyncBack that is earlier
than 3.2.21. Such versions are prone to a remote buffer overflow
attack.

An attacker may exploit this issue to execute arbitrary code in the
context of the vulnerable application by tricking the user into
importing a malicious profile file.");
  # http://www.corelan.be:8800/index.php/forum/security-advisories/corelan-10-041-syncback-freeware-v3-2-20-0/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db9db69b");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.2brightsparks.com/freeware/changes.html"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to SyncBack version 3.2.21 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (isnull(list)) exit(1,"The 'SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName' KB items are missing.");

key = NULL;
foreach name (keys(list))
{
  prod = list[name];
  if (prod &&  "SyncBack" >< prod)
  {
   key = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
   key = str_replace(find:"/", replace:"\", string:key);
   break;
  }
}
if(isnull(key)) exit(0, "No evidence of SyncBack is found in the Uninstaller's registry hive.");


# Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");
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


# Check whether it's installed.
path = NULL;

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"InstallLocation");
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
  exit(0, "Can't find SyncBack's installation directory.");
}


# Check the version of the main exe.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\SyncBack.exe", string:path);
NetUseDel(close:FALSE);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to '"+share+"' share.");
}

fh = CreateFile(
  file:exe,
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
else
{
  NetUseDel();
  exit(0, "Failed to open '"+path+"\SyncBack.exe'.");
}
NetUseDel();


# Check the version number.
if (!isnull(ver))
{
  version = string(ver[0], ".", ver[1], ".", ver[2]);
  fixed_version = "3.2.21";

  if (ver[0] < 3 || (ver[0] == 3 && ver[1] < 2) || (ver[0] == 3 && ver[1] == 2 && ver[2] < 21))
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
  exit(0, "SyncBack version "+version+" is installed and not vulnerable.");
}
else exit(1, "Can't get file version of '"+(share-'$')+':'+exe+"'.");
