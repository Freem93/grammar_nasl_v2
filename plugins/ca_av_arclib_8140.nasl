#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42105);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/10/07 13:30:47 $");

  script_cve_id("CVE-2009-3587", "CVE-2009-3588");
  script_bugtraq_id(36653);
  script_osvdb_id(58691);
  script_xref(name:"Secunia", value:"36976");

  script_name(english:"Computer Associates Anti-Virus Engine arclib.dll < 8.1.4.0 Multiple Flaws");
  script_summary(english:"Checks version of arclib.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple flaws.");

  script_set_attribute(attribute:"description", value:
"The antivirus engine from Computer Associates installed on the remote
host is affected by multiple vulnerabilities :

  - Due to improper handling of certain specially crafted
    RAR
    files it may be possible for a remote attacker to
    trigger
    a heap overflow or denial of service condition.
    (CVE-2009-3587)

  - Due to improper handling of certain specially crafted
    RAR
    files it may be possible for a remote attacker to
    trigger
    a stack overflow or denial of service condition.
    (CVE-2009-3588)");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cccd446a");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/507101/30/0/threaded" );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aeda8c7c" );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2009/Oct/79" );

  script_set_attribute(attribute:"solution", value:
"Either manually apply the patch listed in the vendor advisory or
ensure that the product's automatic updates feature is enabled and
working properly.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("audit.inc");
include("misc_func.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1,"The 'SMB/Registry/Enumerated' KB item is missing.");

# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) {
  NetUseDel();
  exit(1,"Can't connect to IPC$ share.");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1,"Can't connect to remote registry.");
}

# Find where it's installed.
reg_path = NULL;

key = "SOFTWARE\ComputerAssociates\ScanEngine\Path";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Engine");
  if (!isnull(value)) reg_path = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);


pfd = hotfix_get_programfilesdir();

if(reg_path && pfd)
{
  paths = list_uniq(make_list(reg_path,
                      string(pfd,'\\CA\\SharedComponents\\ScanEngine'),
                      string(pfd,'\\eTrust\\Intrusion Detection\\Common'),
                      string(pfd,'\\CA\\Intrusion Detection\\Common')));
}
else if(reg_path && isnull(pfd))
  paths = make_list(reg_path);
else if(!isnull(pfd) && isnull(reg_path))
{
 paths = make_list(string(pfd,'\\CA\\SharedComponents\\ScanEngine'),
                   string(pfd,'\\eTrust\\Intrusion Detection\\Common'),
                   string(pfd,'\\CA\\Intrusion Detection\\Common'));
}

if(max_index(paths) == 0)
{
  NetUseDel();
  exit(0, "Can't determine path for Computer Associates Anti-Virus engine.");
}

ver = NULL;

found = 0;

foreach path (paths)
{
  # Grab the file version of file Arclib.dll.

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Arclib.dll", string:path);

  NetUseDel(close:FALSE);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, "Can't connect to '"+share+"' share.");
  }

  fh = CreateFile(
    file:dll,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    found = 1;
    ver = GetFileVersion(handle:fh);
    CloseFile(handle:fh);
    break;
  }
}

NetUseDel();

if(!found) exit(0, "File Arclib.dll was not found on the remote system.");

# Check the version number.
if (!isnull(ver))
{
  fixed_version = "8.1.4.0";
  fix = split(fixed_version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity > 0)
      {
	version = string(ver[0],".",ver[1],".",ver[2],".",ver[3]);
        report = string(
          "\n",
          "File              : ", path, "\\Arclib.dll\n",
          "Installed version : ", version, "\n",
          "Fixed version     : ", fixed_version, "\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      exit(0);
    }
    else if (ver[i] > fix[i])
      break;

 exit(0, "Arclib.dll version "+version+" is installed and not vulnerable.");
}
else exit(1, "Can't get file version of 'Arclib.dll'.");
