#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34216);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/04/25 21:51:07 $");

  script_cve_id("CVE-2008-2437");
  script_bugtraq_id(31139);
  script_osvdb_id(48024);
  script_xref(name:"Secunia", value:"31342"); 

  script_name(english:"Trend Micro OfficeScan 'cgiRecvFile.exe' ComputerName Parameter Buffer Overflow");
  script_summary(english:"Checks cgiRecvFile.exe version");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by a buffer
overflow vulnerability." );
  script_set_attribute(attribute:"description", value:
"Trend Micro OfficeScan or Client Server Messaging Security is
installed on the remote host.  The installed version is affected by a
buffer overflow vulnerability.  By setting the parameter
'ComputerName' to a very long string in a specially crafted HTTP
request, a malicious user within the local network may be able to
trigger a stack-based overflow in 'cgiRecvFile.exe'. 

Exploitation of this issue requires manipulation of the parameters
'TempFileName', 'NewFileSize', and 'Verify' and, if successful, would
result in arbitrary code execution on the remote system." );
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2008-35/" );
   # http://www.trendmicro.com/ftp/documentation/readme/OSCE_7.3_Win_EN_CriticalPatch_B1367_readme.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f0629899");
   # http://www.trendmicro.com/ftp/documentation/readme/CSM_3.6_OSCE_7.6_Win_EN_CriticalPatch_B1195_readme.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4cf6e9b8");
   # http://www.trendmicro.com/ftp/documentation/readme/OSCE_8.0_Win_EN_CriticalPatch_B1361_readme.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?181dece3");
   # http://www.trendmicro.com/ftp/documentation/readme/OSCE_8.0_SP1_Win_EN_CriticalPatch_B2424_readme.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e96b6aa1");
   # http://www.trendmicro.com/ftp/documentation/readme/OSCE_8.0_SP1_Patch1_Win_EN_CriticalPatch_B3060_readme.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?46ebb3f9");
  script_set_attribute(attribute:"solution", value:
"Upgrade to : 

 - Trend Micro OfficeScan 8.0 Build 1361/2424 or 3060
   depending on the current OfficeScan patch level.
 - Trend Micro Client Server Messaging Security 3.6
   Build 1195.
 - Trend Micro OfficeScan 7.3 Build 3167." );
 script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);

  script_set_attribute(attribute:"plugin_publication_date", value: "2008/09/16");
  script_set_attribute(attribute:"patch_publication_date", value: "2008/09/12");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:trend_micro:officescan");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl","http_version.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports("Services/www", 4343, 8080,139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");
include("http.inc");

# Check if we can find an instance of OfficeScan Server or CSM 

if (report_paranoia < 2)
{
  found = 0;
  ports = add_port_in_list(list:get_kb_list("Services/www"), port:8080);
  ports = add_port_in_list(list:ports, port:4343);

  foreach port (ports)
  {
    w = http_send_recv3(method:"GET", item:"/officescan/default.htm", port:port);
    if (isnull(w))
    {
      debug_print("the web server on port ", port, " did not answer");
      continue;
    }
    buf = strcat(w[0], w[1], '\r\n', w[2]);
    if ("console/html/cgi/cgiChkMasterPwd.exe" >!< buf)
     {
      # Check if CSM is installed. 	
      w = http_send_recv3(method:"GET", item:"/officescan/default_SMB.htm", port:port);
      if (isnull(w))
      {
        debug_print("the web server on port ", port, " did not answer");
        continue;
      }
      buf = strcat(w[0], w[1], '\r\n', w[2]);
     }
   
    if ("console/html/cgi/cgiChkMasterPwd.exe" >< buf) 
     {
      found = 1;
      break;		
    }
  } 

  if(!found) exit(0);
}

if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);

# Connect to the appropriate share.

name    =  kb_smb_name();
port    =  kb_smb_transport();
if (!get_port_state(port)) exit(0);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

soc = open_sock_tcp(port);
if (!soc) exit(0);

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}

# Figure out where it is installed.

path = NULL;
server_version = NULL;
SP_version = NULL;

key = "SOFTWARE\TrendMicro\OfficeScan\service\Information";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Local_Path");
  if (!isnull(value)) path = value[1];

  value =  RegQueryValue(handle:key_h, item:"Server_Version");
  if (!isnull(value)) server_version = value[1];

  value =  RegQueryValue(handle:key_h, item:"ServicePack_Build");
  if (!isnull(value)) SP_version = value[1];
 
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0);
}
NetUseDel(close:FALSE);


# Grab the file version of cgiRecvFile.exe
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);

if("8.0" >< server_version)
exe   = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Web_OSCE\Web\CGI\cgiRecvFile.exe", string:path);
else
exe   = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Web\CGI\cgiRecvFile.exe", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
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
NetUseDel();


# Check the version number.
if (!isnull(ver))
{
  for (i=0; i<4; i++)
    ver[i] = int(ver[i]);

  if ( ( ver[0] ==  7 && ver[1] == 3 && ver[2] == 0 && ver[3] < 1367) || # OfficeScan 7.3 without patch 1367
       ( ver[0] ==  7 && ver[1] == 6 && ver[2] == 0 && ver[3] < 1195) || # OfficeScan 7.6/CSM 3.6 without patch 1195
       ( ver[0] ==  8 && ver[1] == 0 && ver[2] == 0 && ver[3] < 1361) || # OfficeScan 8.0 without patch 1361
       ( ver[0] ==  8 && ver[1] == 0 && ver[2] == 0 && SP_version >= 2302 && ver[3] < 2424) || # OfficeScan 8.0 Service Pack 1 without patch 2424 
       ( ver[0] ==  8 && ver[1] == 0 && ver[2] == 0 && SP_version >= 3031 && ver[3] < 3060)    # OfficeScan 8.0 Service Pack 1 Patch 1 without patch 3060
     ) 
     if (report_verbosity )
      {
        report = string(
          "\n",
          "Version ", string(ver[0],".",ver[1]," build ",ver[3]), " of Trend Micro OfficeScan\n", 
	  " is installed under :\n", 
          "\n",
          "  ", path, "\n"
        ); 	
      	security_hole(port:port,extra:report);
      }
      else
      	security_hole(port);
}
