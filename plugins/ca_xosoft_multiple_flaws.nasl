#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(45503);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/10/07 13:30:47 $");

  script_cve_id("CVE-2010-1221", "CVE-2010-1222", "CVE-2010-1223");
  script_bugtraq_id(39238, 39244, 39249);
  script_xref(name:"OSVDB", value:"63610");
  script_xref(name:"OSVDB", value:"63611");
  script_xref(name:"OSVDB", value:"63612");
  script_xref(name:"OSVDB", value:"63613");
  script_xref(name:"Secunia", value:"39337");

  script_name(english:"Computer Associates XOsoft Multiple Flaws (CA20100406) (credentialed check)");
  script_summary(english:"Checks version of mng_core_com.dl");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by
multiple vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"XOsoft, a product from Computer Associates for combined business
continuity and disaster recovery, is installed on the remote Windows
host. 

According to its version, it is affected by several vulnerabilities. 

  - By sending a specially crafted SOAP request, it may be 
    possible for an unauthenticated attacker to enumerate 
    users on the remote system. (CVE-2010-1221)

  - By sending a specially crafted SOAP request, it may be 
    possible for an unauthenticated attacker to gain 
    sensitive information from the remote system. 
    (CVE-2010-1222)

  - By sending a specially crafted request, it may be 
    possible for an attacker to execute arbitrary code on
    the remote system within the context of the service or 
    trigger a denial of service condition. (CVE-2010-1223)");

  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-065" );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-10-066" );
  script_set_attribute(attribute:"see_also", value:"https://support.ca.com/irj/portal/anonymous/phpsupcontent?contentID=232869");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/Apr/82");

  script_set_attribute(attribute:"solution", value: "Apply vendor-supplied patches." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/06");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2)
{
  port = get_http_port(default:8088);

  banner = get_http_banner(port:port);
  if (!banner) exit(1, "Unable to get banner from web server on port "+port+".");
  if(!egrep(pattern:"^Server:.*Microsoft-HTTPAPI/",string:banner))
    exit(0,"The banner from the web server on port "+ port + " does not appear to be from XOsoft.");

  url = "/entry_point.aspx?width=1440";

  res = http_send_recv3(method:"GET", item:url, port:port,exit_on_fail:1);

  if ("Login to CA XOsoft" >!< res[2])
    exit (0, "The web application running on port "+ port + " does not appear to be XOsoft.");
}

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1,"The 'SMB/Registry/Enumerated' KB item is missing.");

# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();
if (!get_port_state(port)) exit(1, "Port "+port+" is not open.");
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

soc = open_sock_tcp(port);
if (!soc) exit(1,"Can't open socket on port "+port+".");

session_init(socket:soc, hostname:name);
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

# Find where it's installed.
path = NULL;

key = "SOFTWARE\CA\XOsoft\Manager";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Install_Dir");
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, "XOsoft product is not installed..");
}

# Grab the file version of file mng_core_com.dll.

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\mng_core_com.dll", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to "+share+" share.");
}

fh = CreateFile(
  file:dll,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

ver  = NULL;

if (!isnull(fh))
{
 ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}

NetUseDel();

# Check the version number.
if (!isnull(ver))
{
  if(ver[0] == 5) 
    fixed_version = "5.0.5.128"; # 12.0
  else if (ver[0] == 12 && ver[1] == 5)
    fixed_version = "12.5.2.563"; # 12.5
  # Do not flag versions other than 12.0 and 12.5
  # as they might not be affected.
  else 
   exit(0, "XOsoft version "+ join(ver,sep:".") + " is not known to be affected.");
  
  version = join(ver, sep:".");
  fix = split(fixed_version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity > 0)
      {
        report = 
          "\n  Path              : " + path + 
          "\n  Installed version : " + version + 
          "\n  Fixed version     : " + fixed_version + '\n';
        security_hole(port:port, extra:report);
      }
      else security_hole(port);

      exit(0);
    }
    else if (ver[i] > fix[i])
      break;

  exit(0, "XOsoft version "+version+" is installed and not vulnerable.");
}
else exit(1, "Couldn't get file version of '"+(share-'$')+":"+dll+"'.");
