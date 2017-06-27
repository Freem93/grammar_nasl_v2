#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40333);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2014/02/02 01:31:04 $");

  script_cve_id("CVE-2009-0693", "CVE-2009-0695");  
  script_bugtraq_id(35649, 54028);
  script_osvdb_id(55839, 83202);
  script_xref(name:"CERT", value:"654545");
  script_xref(name:"Secunia", value:"35794");

  script_name(english:"Wyse Device Manager Buffer Overflow");
  script_summary(english:"Checks if hotpatch is installed");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by a
buffer overflow vulnerability.");

  script_set_attribute(attribute:"description", value:
"Wyse Device Manager is installed on the remote system.  The installed
version is affected by a buffer overflow vulnerability.  By sending a
specially crafted request to the server, it may be possible for an
unauthorized attacker to crash the server or execute arbitrary
commands on the remote system with system level privileges.");

  script_set_attribute(attribute:"see_also", value:"http://www.theregister.co.uk/2009/07/10/wyse_remote_exploit_bugs/");
  # http://web.archive.org/web/20110726030311/http://www.wyse.com/serviceandsupport/Wyse%20Security%20Bulletin%20WSB09-01.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?27941b3b");
  script_set_attribute(attribute:"solution", value:"Apply vendor-supplied patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Wyse Rapport Hagent Fake Hserver Command Execution');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",  value:"2009/07/10");
  script_set_attribute(attribute:"patch_publication_date",  value:"2009/07/10");
  script_set_attribute(attribute:"plugin_publication_date",  value:"2009/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:dell:wyse_device_manager");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl","http_version.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445,80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("smb_func.inc");


if (report_paranoia < 2)
{
 port = get_http_port(default:80);
 banner = get_http_banner(port:port); 
 if(!banner || "Microsoft-IIS" >!< banner) exit(0, "The web server does not appear to be Microsoft IIS.");

 res = http_send_recv3(method:"GET", item:"/hserver.dll?&V94",port:port, exit_on_fail: 1 );
 
 # If we don't see a response, then we are not looking at WDM.
 # For e.g. 
 # Please append |Tsk=0 to the V94 command for more options 

 if(!ereg(pattern:"Please append |Tsk=0 to the V94 command for more options",string:res[2]))
 exit(0, "Wyse WDM Service was not detected.");
}

if (!get_kb_item("SMB/Registry/Enumerated")) exit(0, "SMB/Registry/Enumerated does not exist in KB.");

# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();
if (!get_port_state(port)) exit(1, "Port "+port+" is closed.");
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

soc = open_sock_tcp(port);
if (!soc) exit(1, "Connection refused on port "+port+".");

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) {
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

# Find where it's installed.
path = NULL;
release_ver = NULL;
patch = NULL;

key = "SOFTWARE\Rapport";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"ReleaseVersion");
  if (!isnull(value)) release_ver = value[1];

  RegCloseKey(handle:key_h);
}

key = "SOFTWARE\Rapport\Install";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"BaseDir");
  if (!isnull(value)) path = value[1];
 
  value = RegQueryValue(handle:key_h, item:"RptInstalled");
  if (!isnull(value)) patch = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, "Wyse WDM is not installed.");
}

if (isnull(release_ver))
{
  NetUseDel();
  exit(0, "Wyse WDM release_ver is NULL.");
}
NetUseDel(close:FALSE);


known_format = 0;
if(ereg(pattern:"^0*HF0*40720[0-9]+",string:patch))
{
  # Get rid of starting 0's and HF
  # For e.g. 00HF040720324   (unpatched default v4.7.2 install)
  #            HF04072019009 (patched)

  patch = ereg_replace(pattern:"^0*HF0*40720([0-9]+)$",string:patch,replace:"\1");
  patch = int(patch);
  known_format = 1;
}

# Grab the file version of file HServerInit.exe, just to make sure the 
# file exists. But rely on the version found in the registry since it
# is accurate.

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\HServerInit.exe", string:path);

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
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
NetUseDel();

if (!isnull(ver))
{
  v = split(release_ver,sep:'.',keep:FALSE);
  for (i=0; i<max_index(v); i++)
    v[i] = int(v[i]);

  if (
    (v[0]  < 4 ) ||
    (v[0] == 4 && v[1]  < 7) || 
    (v[0] == 4 && v[1] == 7 && v[2]  < 2) ||
    (v[0] == 4 && v[1] == 7 && v[2] == 2 && isnull(patch)) ||
    (v[0] == 4 && v[1] == 7 && v[2] == 2 && !isnull(patch) && known_format && patch < 19009)
  ) 
  {
    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "  Version : ", release_ver, "\n",
        "  Path    : ", path, "\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
  else exit(0, "Wyse WDM version "+release_ver+" is installed and not vulnerable.");
}
else exit(1, "Couldn't get file version of '"+exe+"'.");
