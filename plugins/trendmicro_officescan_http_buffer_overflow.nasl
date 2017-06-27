#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34490);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/04/25 21:52:36 $");

  script_cve_id("CVE-2008-3862");
  script_bugtraq_id(31859);
  script_osvdb_id(49275);
  script_xref(name:"Secunia", value:"32005"); 

  script_name(english:"Trend Micro OfficeScan HTTP Request Remote Buffer Overflow");
  script_summary(english:"Checks cgiLog.exe version");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by a buffer
overflow vulnerability." );
  script_set_attribute(attribute:"description", value:
"Trend Micro OfficeScan is installed on the remote host.  The installed
version is affected by a buffer overflow vulnerability.  By sending a
specially crafted HTTP request to Trend Micro OfficeScan server CGI
modules, it may be possible to trigger a stack-based buffer overflow. 

Successful exploitation of this issue may result in arbitrary code
execution on the remote system." );
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2008-40/" );
   # http://www.trendmicro.com/ftp/documentation/readme/Readme_WFBS5.0_EN_CriticalPatch1418.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9805a21c");
   # http://www.trendmicro.com/ftp/documentation/readme/OSCE_7.3_CriticalPatch_B1374_readme.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2b7bfd4c");
   # http://www.trendmicro.com/ftp/documentation/readme/OSCE_8.0_sp1p1_CriticalPatch_B3110_readme.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01759f7a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to : 

 - Trend Micro Worry-Free Business Security 5.0 Build 1418
 - Trend Micro OfficeScan 7.3 Build 1374
 - Trend Micro OfficeScan 8.0 Build 3110" );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
 script_cwe_id(119);

  script_set_attribute(attribute:"plugin_publication_date", value: "2008/10/24");
  script_set_attribute(attribute:"patch_publication_date", value: "2008/10/22");
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

# Check if we can find an instance of OfficeScan Server or WFBS

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

    if ("cgiChkMasterPwd.exe" >!< buf)
     {
      # Check if WFBS  is installed. 	
      w = http_send_recv3(method: "GET", item:"/officescan/default_SMB.htm", port:port);
      if (isnull(w))
      {
        debug_print("the web server on port ", port, " did not answer");
        continue;
      }
      buf = strcat(w[0], w[1], '\r\n', w[2]);
     }
   
    if ("cgiChkMasterPwd.exe" >< buf) 
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

# Check if Worry-Free Business Server is installed.

wfbs = 0;
key = "SOFTWARE\TrendMicro\WFBS";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  wfbs = 1;
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
exe   = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Web_OSCE\Web\CGI\cgiLog.exe", string:path);
else
exe   = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Web\CGI\cgiLog.exe", string:path);

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
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  if ( ( ver[0] ==  7 && ver[1] == 3 && ver[2] == 0 && ver[3] < 1374) || # OfficeScan 7.3 without patch 1374
       ( ver[0] ==  8 && ver[1] == 0 && ver[2] == 0 && SP_version >= 3031 && ver[3] < 3110) ||    # OfficeScan 8.0 Service Pack 1 Patch 1 without patch 3110
       ( wfbs && ver[0] == 15 && ver[1] == 0 && ver[2] == 0 && ver[3] < 1418) 	# WFBS without patch 1418
     ) 
     if (report_verbosity && !wfbs)
      {
        report = string(
          "\n",
          "Version ", ver[0],".",ver[1]," build ",ver[3], " of Trend Micro OfficeScan is installed under :\n", 
          "\n",
          "  ", path, "\n"
        ); 	
     	security_hole(port:port,extra:report);
      }
      else
      	security_hole(port);
}
