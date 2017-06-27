#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42292);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/08/16 14:42:22 $");

  script_cve_id("CVE-2009-3748", "CVE-2009-3749");
  script_bugtraq_id(36740, 36741);
  script_osvdb_id(59072, 59073, 59074, 59075, 59076);
  script_xref(name:"Secunia", value:"37091");
  script_xref(name:"IAVB", value:"2009-B-0055");

  script_name(english:"Websense Email Security < 7.1 Hotfix 4");
  script_summary(english:"Checks version of STEMRCV.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"Websense Email Security is installed on the remote host. The installed
version is affected by multiple issues :

  - Websense Email Security Web Administrator service is
    affected by a denial of service issue.

  - Websense Email Security Web Administrator is affected
    by multiple cross-site scripting issues.");

  script_set_attribute(attribute:"see_also", value:"http://sotiriu.de/adv/NSOADV-2009-002.txt");
  script_set_attribute(attribute:"see_also", value:"http://sotiriu.de/adv/NSOADV-2009-003.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/507329/30/0/threaded" );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/507330/30/0/threaded" );

  script_set_attribute(attribute:"solution", value:"Apply Hotfix 4 for version 7.1.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

#

include("smb_func.inc");
include("audit.inc");
include("smb_hotfixes.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1,"The 'SMB/Registry/Enumerated' KB item is missing.");

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
path = NULL;

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Websense Email Security";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"path");
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(1, "Could not get path.");
}
NetUseDel(close:FALSE);


# Grab the file version of file STEMRCV.exe
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\STEMRCV.exe", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to '"+share+"' share.");
}

ver = NULL;

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
NetUseDel();

# Check the version number.
if (!isnull(ver))
{
  fixed_version = "7.1.0.130";
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
          " File              : STEMRCV.exe\n",
          " Path              : ", path, "\n",
          " Installed version : ", version, "\n",
          " Fixed version     : ", fixed_version, "\n"
        );
        security_warning(port:port, extra:report);
      }
      else security_warning(port);
      exit(0);
    }
    else if (ver[i] > fix[i])
      break;
 exit(0, "STEMRCV.exe version "+version+" is installed and not vulnerable.");
}
else exit(1, "Can't get file version of 'STEMRCV.exe'.");
